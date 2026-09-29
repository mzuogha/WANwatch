"""Web dashboard and REST API."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import os
import secrets
import time
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from .detector import Event
from .service import MonitorService

STATIC = Path(__file__).parent / "static"
_ORDER = {"unknown": -1, "healthy": 0, "degraded": 1, "down": 2}


# --- password hashing (pbkdf2, stdlib only) -----------------------------------
def hash_password(password: str, iterations: int = 310_000) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, it, salt, dk = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        calc = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt), int(it))
        return hmac.compare_digest(calc, base64.b64decode(dk))
    except Exception:
        return False


def create_app(svc: MonitorService) -> FastAPI:
    cfg = svc.cfg
    security = HTTPBasic(auto_error=False)
    fails: dict[str, list[float]] = {}

    def auth(request: Request, creds: HTTPBasicCredentials | None = Depends(security)) -> None:
        if not cfg.web.password_hash:
            return  # auth disabled (warned at startup)
        ip = request.client.host if request.client else "?"
        recent = [t for t in fails.get(ip, []) if time.time() - t < 300]
        if len(recent) >= 10:
            raise HTTPException(429, "Too many failed sign-ins. Try again in 5 minutes.")
        ok = creds is not None and secrets.compare_digest(creds.username, cfg.web.username) \
            and verify_password(creds.password, cfg.web.password_hash)
        if not ok:
            fails[ip] = recent + [time.time()]
            raise HTTPException(401, "Sign-in required", headers={"WWW-Authenticate": 'Basic realm="WANWatch"'})

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await svc.start()
        yield
        await svc.stop()

    app = FastAPI(title=cfg.title, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Content-Security-Policy",
                                "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:")
        return resp

    # --- unauthenticated -------------------------------------------------------
    @app.get("/healthz")
    async def healthz():
        age = time.time() - svc.last_poll if svc.last_poll else None
        alive = age is not None and age < max(60, 3 * cfg.detection.poll_interval_s)
        return JSONResponse({"service": "ok" if alive else "stalled", "last_poll_age_s": age,
                             "firewall_reachable": svc.detector.fw_reachable}, status_code=200 if alive else 503)

    # --- dashboard ---------------------------------------------------------------
    @app.get("/", response_class=HTMLResponse, dependencies=[Depends(auth)])
    async def index():
        html = (STATIC / "index.html").read_text(encoding="utf-8")
        return html.replace("{{TITLE}}", cfg.title)

    @app.get("/api/status", dependencies=[Depends(auth)])
    async def status():
        return svc.status()

    @app.get("/api/stream", dependencies=[Depends(auth)])
    async def stream(request: Request):
        q = svc.hub.subscribe()

        async def gen():
            try:
                yield f"event: status\ndata: {__import__('json').dumps(svc.status(), default=str)}\n\n"
                while not await request.is_disconnected():
                    try:
                        yield await asyncio.wait_for(q.get(), timeout=15)
                    except asyncio.TimeoutError:
                        yield ": keep-alive\n\n"
            finally:
                svc.hub.unsubscribe(q)
        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.get("/api/history", dependencies=[Depends(auth)])
    async def history(hours: float = Query(24, gt=0, le=24 * 31), points: int = Query(288, ge=10, le=2000)):
        end = time.time()
        start = end - hours * 3600
        rows = await asyncio.to_thread(svc.store.samples, start, end)
        polls = await asyncio.to_thread(svc.store.polls, start, end)
        bucket = (end - start) / points
        out = {}
        for l in cfg.links:
            out[l.interface] = [{"t": start + i * bucket, "lat": [], "jit": [], "loss": [], "state": None} for i in range(points)]
        for r in rows:
            b = out.get(r["link"])
            if b is None:
                continue
            i = min(points - 1, int((r["ts"] - start) / bucket))
            cell = b[i]
            for k, col in (("lat", "latency"), ("jit", "jitter"), ("loss", "loss")):
                if r[col] is not None and r["raw_state"] != "down":
                    cell[k].append(r[col])
            st = r["raw_state"]
            if cell["state"] is None or _ORDER[st] > _ORDER[cell["state"]]:
                cell["state"] = st
        failed = [0] * points
        for p in polls:
            if not p["ok"]:
                failed[min(points - 1, int((p["ts"] - start) / bucket))] = 1
        avg = lambda v: round(sum(v) / len(v), 2) if v else None
        series = {k: [{"t": c["t"], "latency": avg(c["lat"]), "jitter": avg(c["jit"]), "loss": avg(c["loss"]),
                       "state": c["state"] or ("unknown" if failed[i] else None)} for i, c in enumerate(v)]
                  for k, v in out.items()}
        # rolling availability for the window, per link
        avail = {}
        for l in cfg.links:
            mine = [r for r in rows if r["link"] == l.interface]
            avail[l.interface] = round(100 * sum(r["raw_state"] != "down" for r in mine) / len(mine), 3) if mine else None
        return {"start": start, "end": end, "bucket_s": bucket, "series": series, "availability": avail}

    @app.get("/api/events", dependencies=[Depends(auth)])
    async def events(limit: int = Query(100, ge=1, le=1000), hours: float = Query(24 * 7, gt=0)):
        rows = await asyncio.to_thread(svc.store.events, time.time() - hours * 3600, None, limit)
        return [dict(r) for r in rows]

    @app.get("/api/reports", dependencies=[Depends(auth)])
    async def list_reports():
        return [dict(r) | {"html_path": None, "csv_path": None} for r in await asyncio.to_thread(svc.store.reports)]

    def _day(day: str) -> date:
        try:
            return date.fromisoformat(day)
        except ValueError:
            raise HTTPException(400, "Date must be YYYY-MM-DD") from None

    @app.post("/api/reports/generate", dependencies=[Depends(auth)])
    async def gen_report(day: str | None = None, email: bool = False):
        d = _day(day) if day else (datetime.now(ZoneInfo(cfg.reports.timezone)) - timedelta(days=1)).date()
        return await svc.build_report(d, email=email)

    @app.get("/reports/{day}.{ext}", dependencies=[Depends(auth)])
    async def get_report(day: str, ext: str):
        _day(day)
        row = await asyncio.to_thread(svc.store.report, day)
        if not row or ext not in ("html", "csv"):
            raise HTTPException(404, f"No report for {day}. Generate it from the dashboard first.")
        p = Path(row["html_path"] if ext == "html" else row["csv_path"])
        if not p.exists():
            raise HTTPException(404, "Report file was removed from disk.")
        return FileResponse(p, media_type="text/html" if ext == "html" else "text/csv",
                            filename=None if ext == "html" else p.name)

    @app.post("/api/alerts/test", dependencies=[Depends(auth)])
    async def test_alert():
        ev = Event(time.time(), "test", "info", f"Test alert from {cfg.title}. If you can read this, alert delivery works.")
        ok = await svc.alerts.deliver(ev)
        if not ok:
            raise HTTPException(502, "No alert channel accepted the test. Check the service log for the error from each channel.")
        return {"delivered": True}

    async def metrics():
        s = svc.status()
        lines = ["# TYPE wanwatch_link_state gauge", "# HELP wanwatch_link_state 0 healthy, 1 degraded, 2 down, -1 unknown"]
        for l in s["links"]:
            lab = f'link="{l["interface"]}",name="{l["name"]}",role="{l["role"]}"'
            lines.append(f"wanwatch_link_state{{{lab}}} {_ORDER.get(l['state'], -1)}")
            if l["state"] != "unknown":
                lines.append(f"wanwatch_link_up{{{lab}}} {0 if l['state'] == 'down' else 1}")
            for key, metric in (("latency_ms", "latency_ms"), ("jitter_ms", "jitter_ms"), ("loss_pct", "packet_loss_pct"),
                                ("rx_bps", "rx_bps"), ("tx_bps", "tx_bps")):
                if l[key] is not None:
                    lines.append(f"wanwatch_link_{metric}{{{lab}}} {l[key]}")
        lines.append(f"wanwatch_firewall_reachable {1 if s['firewall']['reachable'] else 0}")
        lines.append(f"wanwatch_polls_total {s['poll']['count']}")
        lines.append(f"wanwatch_poll_failures_total {s['poll']['failures']}")
        return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")

    app.add_api_route("/metrics", metrics, methods=["GET"],
                      dependencies=[] if cfg.web.public_metrics else [Depends(auth)])
    return app
