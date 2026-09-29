"""Alert delivery: SMTP email and webhooks (generic JSON, Slack, Microsoft Teams).

Notifications go through an async queue so a slow mail server never delays
polling. Repeated alerts of the same kind for the same link are suppressed for
``cooldown_s``; recoveries are always delivered when the matching problem alert
was delivered, so nobody is left with an open incident.
"""
from __future__ import annotations

import asyncio
import logging
import smtplib
import ssl
import time
from datetime import datetime
from email.message import EmailMessage
from html import escape

import httpx

from .config import AppConfig
from .detector import Event

log = logging.getLogger(__name__)
_SEV = {"info": 0, "warning": 1, "critical": 2}
_COLOR = {"info": "#1f8a5b", "warning": "#b7791f", "critical": "#c0392b"}
_RECOVERY = {"fw_reachable": "fw_unreachable", "outage_cleared": "total_outage", "failback": "failover"}


def send_email(cfg: AppConfig, subject: str, text: str, html: str | None = None,
               attachments: list[tuple[str, bytes, str]] | None = None) -> None:
    """Blocking SMTP send; call via asyncio.to_thread."""
    e = cfg.alerts.email
    if not (e.enabled and e.host and e.recipients):
        raise RuntimeError("email is not configured")
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, e.sender or e.username, ", ".join(e.recipients)
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    for name, data, mime in attachments or []:
        maintype, subtype = mime.split("/", 1)
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    ctx = ssl.create_default_context()
    if e.ssl:
        server = smtplib.SMTP_SSL(e.host, e.port, context=ctx, timeout=20)
    else:
        server = smtplib.SMTP(e.host, e.port, timeout=20)
    with server:
        if e.starttls and not e.ssl:
            server.starttls(context=ctx)
        if e.username:
            server.login(e.username, e.password)
        server.send_message(msg)


class AlertManager:
    def __init__(self, cfg: AppConfig, store=None):
        self.cfg = cfg
        self.store = store
        self.queue: asyncio.Queue[tuple[Event, int | None]] = asyncio.Queue(maxsize=1000)
        self._last_sent: dict[tuple[str, str], float] = {}
        self._open_problem: set[tuple[str, str]] = set()  # (link, kind-family) with a delivered problem alert
        self._http = httpx.AsyncClient(timeout=15)

    async def close(self) -> None:
        await self._http.aclose()

    def submit(self, event: Event, event_id: int | None = None) -> None:
        try:
            self.queue.put_nowait((event, event_id))
        except asyncio.QueueFull:
            log.error("Alert queue full; dropping: %s", event.message)

    def _should_send(self, ev: Event) -> bool:
        family = ev.kind if ev.kind != "link_state" else "link_state"
        key = (ev.link, _RECOVERY.get(ev.kind, family))
        is_recovery = ev.kind in _RECOVERY or (ev.kind == "link_state" and ev.to_state == "healthy")
        if is_recovery:
            if key in self._open_problem:
                self._open_problem.discard(key)
                return True
            return _SEV["info"] >= _SEV[self.cfg.alerts.min_severity]
        if _SEV[ev.severity] < _SEV[self.cfg.alerts.min_severity]:
            return False
        # escalations (e.g. degraded -> down) bypass cooldown; repeats of the same state don't
        ck = (ev.link, f"{ev.kind}:{ev.to_state}")
        now = time.time()
        if now - self._last_sent.get(ck, 0) < self.cfg.alerts.cooldown_s:
            log.info("Alert suppressed by cooldown: %s", ev.message)
            return False
        self._last_sent[ck] = now
        self._open_problem.add(key)
        return True

    async def run(self) -> None:
        # decisions are made in order (cooldown/recovery pairing), delivery runs
        # concurrently so one slow or failing channel never delays the next alert
        sem = asyncio.Semaphore(4)
        pending: set[asyncio.Task] = set()

        async def send(ev: Event, eid: int | None) -> None:
            async with sem:
                try:
                    ok = await self.deliver(ev)
                    if self.store and eid:
                        await asyncio.to_thread(self.store.mark_notified, eid, 1 if ok else -1)
                except Exception:
                    log.exception("Alert delivery failed")

        try:
            while True:
                ev, eid = await self.queue.get()
                try:
                    if self._should_send(ev):
                        t = asyncio.create_task(send(ev, eid))
                        pending.add(t)
                        t.add_done_callback(pending.discard)
                finally:
                    self.queue.task_done()
        finally:
            if pending:  # give in-flight alerts a moment on shutdown
                await asyncio.wait(pending, timeout=10)

    async def deliver(self, ev: Event) -> bool:
        """Send to every channel. Returns True if at least one channel succeeded."""
        title = f"[{ev.severity.upper()}] {self.cfg.title}: {ev.message}"
        when = datetime.fromtimestamp(ev.ts).strftime("%Y-%m-%d %H:%M:%S")
        results = list(await asyncio.gather(*(self._webhook(w.url, w.kind, ev, title, when)
                                               for w in self.cfg.alerts.webhooks)))
        if self.cfg.alerts.email.enabled:
            html = (f"<div style='font-family:Segoe UI,Arial,sans-serif'>"
                    f"<p style='border-left:4px solid {_COLOR[ev.severity]};padding:8px 12px;font-size:15px'>"
                    f"{escape(ev.message)}</p><p style='color:#555;font-size:12px'>{when} &middot; "
                    f"{escape(self.cfg.title)} &middot; event: {ev.kind}</p></div>")
            try:
                await asyncio.to_thread(send_email, self.cfg, title[:180], f"{ev.message}\n\nTime: {when}\nEvent: {ev.kind}", html)
                results.append(True)
            except Exception as e:
                log.error("Email alert failed: %s", e)
                results.append(False)
        if not results:
            log.warning("No alert channels configured; event logged only: %s", ev.message)
            return False
        return any(results)

    async def _webhook(self, url: str, kind: str, ev: Event, title: str, when: str) -> bool:
        if kind == "slack":
            payload = {"text": title, "attachments": [{"color": _COLOR[ev.severity], "text": f"{ev.message}\n{when}"}]}
        elif kind == "teams":  # Teams "Workflows" webhook expects an Adaptive Card
            payload = {"type": "message", "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                            "type": "AdaptiveCard", "version": "1.4", "body": [
                                {"type": "TextBlock", "size": "Medium", "weight": "Bolder", "wrap": True,
                                 "color": {"critical": "Attention", "warning": "Warning", "info": "Good"}[ev.severity],
                                 "text": f"{self.cfg.title}: {ev.severity.upper()}"},
                                {"type": "TextBlock", "wrap": True, "text": ev.message},
                                {"type": "TextBlock", "isSubtle": True, "size": "Small", "text": f"{when} | {ev.kind}"}]}}]}
        else:
            payload = {"source": self.cfg.title, "time": ev.ts, "time_iso": when, "kind": ev.kind,
                       "severity": ev.severity, "link": ev.link, "from": ev.from_state,
                       "to": ev.to_state, "message": ev.message}
        for attempt in range(3):
            try:
                r = await self._http.post(url, json=payload)
                if r.status_code < 300:
                    return True
                log.warning("Webhook %s returned HTTP %s", kind, r.status_code)
            except httpx.HTTPError as e:
                log.warning("Webhook %s failed (attempt %d): %s", kind, attempt + 1, e)
            if attempt < 2:
                await asyncio.sleep(2 ** attempt)
        return False
