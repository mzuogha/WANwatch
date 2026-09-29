"""The monitoring service: polling loop, report scheduler and live-status hub."""
from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

from . import reports
from .alerts import AlertManager, send_email
from .config import AppConfig
from .detector import Detector, Event
from .fortigate import FortiGateClient, FortiGateError, Snapshot
from .storage import Store

log = logging.getLogger(__name__)


class Hub:
    """Fan-out of live status to Server-Sent-Event subscribers."""

    def __init__(self):
        self._subs: set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=20)
        self._subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subs.discard(q)

    def publish(self, kind: str, data: dict) -> None:
        msg = f"event: {kind}\ndata: {json.dumps(data, default=str)}\n\n"
        for q in list(self._subs):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:  # slow client: drop it rather than grow memory
                self._subs.discard(q)


class MonitorService:
    def __init__(self, cfg: AppConfig):
        self.cfg = cfg
        self.store = Store(cfg.resolve(cfg.storage.path))
        self.client = FortiGateClient(cfg.fortigate, [l.interface for l in cfg.links])
        self.detector = Detector(cfg)
        self.alerts = AlertManager(cfg, self.store)
        self.hub = Hub()
        self.started = time.time()
        self.last_poll: float | None = None
        self.last_ok: float | None = None
        self.last_error: str = ""
        self.last_snapshot: Snapshot | None = None
        self.last_raw: dict = {}
        self.poll_count = 0
        self.poll_failures = 0
        self._tasks: list[asyncio.Task] = []

    # --- lifecycle -------------------------------------------------------------
    async def start(self) -> None:
        await self.client.identify()
        self._tasks = [
            asyncio.create_task(self._poll_loop(), name="poll"),
            asyncio.create_task(self.alerts.run(), name="alerts"),
            asyncio.create_task(self._report_loop(), name="reports"),
            asyncio.create_task(self._housekeeping_loop(), name="housekeeping"),
        ]
        await self._record(Event(time.time(), "service", "info", f"{self.cfg.title} monitoring started."), notify=False)

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await self.client.close()
        await self.alerts.close()
        self.store.add_event(time.time(), "service", "info", "", "", "", f"{self.cfg.title} monitoring stopped.")
        self.store.close()

    # --- polling ---------------------------------------------------------------
    async def _poll_loop(self) -> None:
        interval = self.cfg.detection.poll_interval_s
        next_at = time.monotonic()
        while True:
            try:
                await self.poll_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("Unexpected error in poll cycle")
            next_at += interval
            delay = next_at - time.monotonic()
            if delay < 0:  # overran (slow firewall): resync instead of bursting
                next_at, delay = time.monotonic(), 0
            await asyncio.sleep(delay)

    async def poll_once(self) -> None:
        ts = time.time()
        self.last_poll = ts
        self.poll_count += 1
        try:
            snap = await self.client.snapshot()
        except FortiGateError as e:
            self.poll_failures += 1
            self.last_error = str(e)
            log.warning("Poll failed: %s", e)
            await asyncio.to_thread(self.store.add_poll, ts, [], False, str(e)[:500])
            for ev in self.detector.on_poll_failure(ts, str(e)):
                await self._record(ev)
            self.hub.publish("status", self.status())
            return

        snap.ts = ts
        for err in snap.errors:
            log.debug("Secondary source error: %s", err)
        events, raw = self.detector.on_snapshot(ts, snap.links, snap.default_route_ifaces)
        rows = []
        for iface, tr in self.detector.trackers.items():
            r = snap.links[iface]
            rows.append((ts, iface, tr.state, raw[iface][0], r.latency_ms, r.jitter_ms, r.loss_pct,
                         None if r.sla_met is None else int(r.sla_met), r.rx_bps, r.tx_bps))
        await asyncio.to_thread(self.store.add_poll, ts, rows, True, None)
        self.last_ok, self.last_error = ts, ""
        self.last_snapshot, self.last_raw = snap, raw
        for ev in events:
            await self._record(ev)
        self.hub.publish("status", self.status())

    async def _record(self, ev: Event, notify: bool = True) -> None:
        log.log(logging.WARNING if ev.severity != "info" else logging.INFO, "EVENT %s: %s", ev.kind, ev.message)
        eid = await asyncio.to_thread(self.store.add_event, ev.ts, ev.kind, ev.severity, ev.link,
                                      ev.from_state, ev.to_state, ev.message)
        self.hub.publish("event", {"id": eid, "ts": ev.ts, "kind": ev.kind, "severity": ev.severity,
                                   "link": ev.link, "message": ev.message})
        if notify:
            self.alerts.submit(ev, eid)

    # --- reporting -------------------------------------------------------------
    def _tz(self) -> ZoneInfo:
        return ZoneInfo(self.cfg.reports.timezone)

    async def build_report(self, day: date, email: bool | None = None) -> dict:
        rep, html_p, csv_p = await asyncio.to_thread(reports.generate, self.cfg, self.store, day)
        log.info("Report for %s written: %s", day, reports.summary_line(rep))
        sent = False
        if (self.cfg.reports.email if email is None else email) and self.cfg.alerts.email.enabled:
            try:
                await asyncio.to_thread(
                    send_email, self.cfg, f"{self.cfg.title}: WAN SLA report {day} - {reports.summary_line(rep)}",
                    f"Daily WAN availability report for {day}.\n{reports.summary_line(rep)}\n",
                    html_p.read_text(encoding="utf-8"),
                    [(csv_p.name, csv_p.read_bytes(), "text/csv")])
                sent = True
            except Exception as e:
                log.error("Could not email report for %s: %s", day, e)
        return {"day": day.isoformat(), "summary": reports.summary_line(rep), "emailed": sent}

    async def _report_loop(self) -> None:
        if not self.cfg.reports.enabled:
            return
        hh, mm = map(int, self.cfg.reports.time.split(":"))
        # catch up: if yesterday's report is missing (service was down at report time), build it now
        now = datetime.now(self._tz())
        yesterday = (now - timedelta(days=1)).date()
        if now.time() >= datetime.strptime(self.cfg.reports.time, "%H:%M").time() and \
                not await asyncio.to_thread(self.store.report, yesterday.isoformat()):
            await asyncio.sleep(5)
            try:
                await self.build_report(yesterday)
            except Exception:
                log.exception("Catch-up report failed")
        while True:
            now = datetime.now(self._tz())
            run_at = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
            if run_at <= now:
                run_at += timedelta(days=1)
            log.info("Next SLA report at %s", run_at.isoformat(timespec="minutes"))
            # sleep in chunks so clock changes / host sleep don't make us miss it
            while (remaining := (run_at - datetime.now(self._tz())).total_seconds()) > 0:
                await asyncio.sleep(min(remaining, 300))
            try:
                await self.build_report((run_at - timedelta(days=1)).date())
            except Exception:
                log.exception("Scheduled report failed")

    async def _housekeeping_loop(self) -> None:
        while True:
            await asyncio.sleep(3600)
            try:
                n = await asyncio.to_thread(self.store.purge, self.cfg.storage.retention_days)
                pruned = await asyncio.to_thread(reports.prune, self.cfg)
                await asyncio.to_thread(self.store.vacuum)
                if n or pruned:
                    log.info("Housekeeping: purged %d samples, %d old report files", n, pruned)
            except Exception:
                log.exception("Housekeeping failed")

    # --- status for UI/API -----------------------------------------------------
    def status(self) -> dict:
        snap = self.last_snapshot
        links = []
        for iface, tr in self.detector.trackers.items():
            r = snap.links.get(iface) if snap else None
            links.append({
                "interface": iface, "name": tr.link.name, "role": tr.link.role,
                "state": tr.state if self.detector.fw_reachable is not False else "unknown",
                "since": tr.since or None, "reasons": tr.reasons,
                "pending": {"state": tr.candidate, "count": tr.count} if tr.candidate else None,
                "raw_state": (self.last_raw.get(iface) or ("unknown",))[0],
                "latency_ms": r.latency_ms if r else None, "jitter_ms": r.jitter_ms if r else None,
                "loss_pct": r.loss_pct if r else None, "sla_met": r.sla_met if r else None,
                "link_up": r.link_up if r else None, "rx_bps": r.rx_bps if r else None,
                "tx_bps": r.tx_bps if r else None,
                "thresholds": vars(tr.link.thresholds),
                "carries_default_route": (iface in (self.detector.default_route or [])) if self.detector.default_route is not None else None,
            })
        states = [l["state"] for l in links]
        overall = ("unknown" if self.detector.fw_reachable is False or "unknown" in states and len(set(states)) == 1
                   else "outage" if all(s == "down" for s in states)
                   else "failover" if self.detector.failed_over
                   else "impaired" if any(s in ("down", "degraded") for s in states)
                   else "healthy")
        return {
            "title": self.cfg.title, "overall": overall, "links": links,
            "firewall": {"reachable": self.detector.fw_reachable, "hostname": snap.hostname if snap else "",
                         "firmware": snap.firmware if snap else "", "health_check": snap.health_check if snap else "",
                         "source": self.cfg.fortigate.source, "last_error": self.last_error},
            "default_route": self.detector.default_route,
            "poll": {"interval_s": self.cfg.detection.poll_interval_s, "last": self.last_poll, "last_ok": self.last_ok,
                     "count": self.poll_count, "failures": self.poll_failures},
            "service": {"started": self.started, "now": time.time()},
            "sla_target_pct": self.cfg.reports.sla_target_pct,
        }
