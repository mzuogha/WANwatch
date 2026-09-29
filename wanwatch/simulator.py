"""A fake FortiGate REST API for demos and testing (no firewall needed).

Runs an automatic scenario (wan1 periodically degrades then fails, wan2 has
occasional jitter). Force a state with:
    curl -X POST "http://127.0.0.1:8443/sim/set?iface=wan1&mode=down"   # healthy|degraded|down|auto
    curl -X POST "http://127.0.0.1:8443/sim/api?mode=offline"            # offline|online
"""
from __future__ import annotations

import math
import random
import time

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse

START = time.time()
MODES = {"wan1": "auto", "wan2": "auto"}
API = {"online": True}
COUNTERS = {"wan1": [0, 0], "wan2": [0, 0]}
LAST = {"t": time.time()}


def _auto(iface: str, t: float) -> str:
    cycle = (t - START) % 480  # 8-minute scenario
    if iface == "wan1":
        if 240 <= cycle < 300:
            return "degraded"
        if 300 <= cycle < 390:
            return "down"
    elif 60 <= cycle < 100:
        return "degraded"
    return "healthy"


def _member(iface: str) -> dict:
    t = time.time()
    mode = MODES[iface] if MODES[iface] != "auto" else _auto(iface, t)
    base = 18 if iface == "wan1" else 42
    wobble = 3 * math.sin(t / 30)
    if mode == "down":
        return {"status": "down", "latency": 0, "jitter": 0, "packet_loss": 100, "sla_targets_met": [],
                "packet_sent": 100, "packet_received": 0, "session": 0}
    if mode == "degraded":
        lat, jit, loss = base + 180 + random.uniform(0, 60), 35 + random.uniform(0, 20), random.choice([0, 3, 5, 8])
    else:
        lat, jit, loss = base + wobble + random.uniform(0, 4), random.uniform(0.3, 3), random.choice([0] * 30 + [1])
    return {"status": "up", "latency": round(lat, 3), "jitter": round(jit, 3), "packet_loss": loss,
            "sla_targets_met": [1] if mode == "healthy" else [], "packet_sent": 100,
            "packet_received": 100 - loss, "session": random.randint(50, 400)}


def create_app() -> FastAPI:
    app = FastAPI(title="FortiGate simulator", docs_url=None, redoc_url=None)

    def guard(authorization: str | None):
        if not API["online"]:
            raise HTTPException(503, "simulated outage")
        if not authorization or not authorization.startswith("Bearer ") or len(authorization) < 12:
            raise HTTPException(401, "missing token")

    def ok(results, **extra):
        return JSONResponse({"http_method": "GET", "results": results, "status": "success",
                             "vdom": "root", "serial": "FGT60FSIMULATOR", "version": "v7.4.4", **extra})

    @app.get("/api/v2/monitor/system/status")
    def status(authorization: str | None = Header(None)):
        guard(authorization)
        return ok({"hostname": "FGT-SIM", "model_name": "FortiGate", "model_number": "60F"})

    @app.get("/api/v2/monitor/virtual-wan/health-check")
    def hc(authorization: str | None = Header(None)):
        guard(authorization)
        return ok({"Default_DNS": {"wan1": _member("wan1"), "wan2": _member("wan2")}})

    @app.get("/api/v2/monitor/system/link-monitor")
    def lm(authorization: str | None = Header(None)):
        guard(authorization)
        res = {}
        for i in ("wan1", "wan2"):
            m = _member(i)
            res[f"{i}_mon"] = {"status": "alive" if m["status"] == "up" else "dead", "srcintf": i,
                               "latency": m["latency"], "jitter": m["jitter"], "packet_loss": m["packet_loss"]}
        return ok(res)

    @app.get("/api/v2/monitor/system/interface")
    def ifaces(authorization: str | None = Header(None)):
        guard(authorization)
        now = time.time()
        dt, LAST["t"] = now - LAST["t"], now
        res = {}
        for i, mbps in (("wan1", 60), ("wan2", 12)):
            up = _member(i)["status"] == "up"
            if up:
                COUNTERS[i][0] += int(mbps * 1e6 / 8 * dt * random.uniform(.5, 1.2))
                COUNTERS[i][1] += int(mbps * 1e6 / 8 * dt * random.uniform(.1, .3))
            res[i] = {"id": i, "name": i, "link": True, "speed": 1000,
                      "rx_bytes": COUNTERS[i][0], "tx_bytes": COUNTERS[i][1]}
        return ok(res)

    @app.get("/api/v2/monitor/router/ipv4")
    def routes(authorization: str | None = Header(None)):
        guard(authorization)
        res = [{"ip_version": 4, "type": "static", "ip_mask": "0.0.0.0/0", "distance": 10, "interface": i,
                "gateway": "10.0.%d.1" % n} for n, i in ((1, "wan1"), (2, "wan2")) if _member(i)["status"] == "up"]
        return ok(res)

    @app.post("/sim/set")
    def set_mode(iface: str, mode: str):
        if iface not in MODES or mode not in ("auto", "healthy", "degraded", "down"):
            raise HTTPException(400, "iface wan1|wan2, mode auto|healthy|degraded|down")
        MODES[iface] = mode
        return MODES

    @app.post("/sim/api")
    def set_api(mode: str):
        API["online"] = mode != "offline"
        return API

    return app


def run(host: str = "127.0.0.1", port: int = 8443) -> None:
    import uvicorn
    print(f"FortiGate simulator on http://{host}:{port}  (any bearer token accepted)")
    uvicorn.run(create_app(), host=host, port=port, log_level="warning")
