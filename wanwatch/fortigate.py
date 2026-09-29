"""FortiGate REST API client.

Reads WAN health from one of two sources and normalises it:

* ``sdwan``        GET /api/v2/monitor/virtual-wan/health-check   (SD-WAN performance SLA)
* ``link-monitor`` GET /api/v2/monitor/system/link-monitor        (classic link-monitor)

Physical interface state and byte counters come from
``/api/v2/monitor/system/interface`` and the active default route(s) from
``/api/v2/monitor/router/ipv4``. The API token needs read-only access to the
"System" and "Network/Router" permission groups (an admin profile with
read-only everywhere is simplest).
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from .config import FortiGateConfig

log = logging.getLogger(__name__)


class FortiGateError(RuntimeError):
    pass


@dataclass
class LinkReading:
    interface: str
    status: str                    # up | down
    latency_ms: float | None = None
    jitter_ms: float | None = None
    loss_pct: float | None = None
    sla_met: bool | None = None    # FortiGate's own SLA verdict when available
    link_up: bool | None = None    # physical/admin link state
    rx_bps: float | None = None
    tx_bps: float | None = None


@dataclass
class Snapshot:
    ts: float
    links: dict[str, LinkReading]
    default_route_ifaces: list[str] | None = None
    health_check: str = ""
    firmware: str = ""
    hostname: str = ""
    errors: list[str] = field(default_factory=list)


def _num(v: Any) -> float | None:
    try:
        return None if v is None else float(v)
    except (TypeError, ValueError):
        return None


class FortiGateClient:
    def __init__(self, cfg: FortiGateConfig, interfaces: list[str]):
        self.cfg = cfg
        self.interfaces = interfaces
        self._client = httpx.AsyncClient(
            base_url=cfg.base_url,
            verify=cfg.verify_tls,
            timeout=cfg.timeout_s,
            headers={"Authorization": f"Bearer {cfg.api_token}", "Accept": "application/json"},
        )
        self._last_counters: dict[str, tuple[float, int, int]] = {}
        self._hc_name: str = cfg.health_check

    async def close(self) -> None:
        await self._client.aclose()

    async def _get(self, path: str, params: dict | None = None) -> dict:
        params = dict(params or {})
        if self.cfg.vdom:
            params["vdom"] = self.cfg.vdom
        try:
            r = await self._client.get(path, params=params)
        except httpx.HTTPError as e:
            raise FortiGateError(f"{path}: {type(e).__name__}: {e}") from None
        if r.status_code in (401, 403):
            raise FortiGateError(f"{path}: HTTP {r.status_code} - check API token, trusted hosts and admin profile")
        if r.status_code != 200:
            raise FortiGateError(f"{path}: HTTP {r.status_code}")
        try:
            body = r.json()
        except ValueError:
            raise FortiGateError(f"{path}: response was not JSON") from None
        if isinstance(body, list):  # multi-vdom responses
            body = body[0] if body else {}
        if body.get("status") not in (None, "success"):
            raise FortiGateError(f"{path}: API status {body.get('status')}")
        return body

    # --- sources -----------------------------------------------------------
    async def _read_sdwan(self) -> tuple[dict[str, LinkReading], str]:
        body = await self._get("/api/v2/monitor/virtual-wan/health-check")
        checks: dict = body.get("results") or {}
        if not checks:
            raise FortiGateError("no SD-WAN health-checks found (is SD-WAN performance SLA configured?)")
        name = self._hc_name if self._hc_name in checks else None
        if name is None:
            if self._hc_name:
                raise FortiGateError(f"health-check '{self._hc_name}' not found; available: {sorted(checks)}")
            # choose the first health-check that covers our interfaces
            name = next((n for n, m in checks.items() if any(i in (m or {}) for i in self.interfaces)), next(iter(checks)))
            self._hc_name = name
            log.info("Using SD-WAN health-check '%s'", name)
        members: dict = checks.get(name) or {}
        out: dict[str, LinkReading] = {}
        for iface in self.interfaces:
            m = members.get(iface)
            if not isinstance(m, dict):
                continue
            sla = m.get("sla_targets_met")
            out[iface] = LinkReading(
                interface=iface,
                status="up" if str(m.get("status", "")).lower() == "up" else "down",
                latency_ms=_num(m.get("latency")),
                jitter_ms=_num(m.get("jitter")),
                loss_pct=_num(m.get("packet_loss")),
                sla_met=(bool(sla) if isinstance(sla, list) else None),
            )
        return out, name

    async def _read_link_monitor(self) -> tuple[dict[str, LinkReading], str]:
        body = await self._get("/api/v2/monitor/system/link-monitor")
        monitors: dict = body.get("results") or {}
        out: dict[str, LinkReading] = {}
        for mname, m in monitors.items():
            if not isinstance(m, dict):
                continue
            if self._hc_name and mname != self._hc_name and len(self.interfaces) == 1:
                continue
            iface = m.get("srcintf") or m.get("interface") or (mname if mname in self.interfaces else None)
            if iface not in self.interfaces:
                # some builds name the monitor after the interface ("wan1_monitor")
                iface = next((i for i in self.interfaces if mname.startswith(i)), None)
            if iface is None or iface in out:
                continue
            out[iface] = LinkReading(
                interface=iface,
                status="up" if str(m.get("status", "")).lower() in ("alive", "up") else "down",
                latency_ms=_num(m.get("latency")),
                jitter_ms=_num(m.get("jitter")),
                loss_pct=_num(m.get("packet_loss")),
            )
        return out, "link-monitor"

    async def _read_interfaces(self, readings: dict[str, LinkReading], now: float) -> None:
        body = await self._get("/api/v2/monitor/system/interface")
        ifs: dict = body.get("results") or {}
        for iface in self.interfaces:
            info = ifs.get(iface)
            if not isinstance(info, dict):
                continue
            r = readings.setdefault(iface, LinkReading(interface=iface, status="down"))
            r.link_up = bool(info.get("link", True))
            if r.link_up is False:
                r.status = "down"
            rx, tx = info.get("rx_bytes"), info.get("tx_bytes")
            if isinstance(rx, int) and isinstance(tx, int):
                prev = self._last_counters.get(iface)
                self._last_counters[iface] = (now, rx, tx)
                if prev and now > prev[0] and rx >= prev[1] and tx >= prev[2]:
                    dt = now - prev[0]
                    r.rx_bps = (rx - prev[1]) * 8 / dt
                    r.tx_bps = (tx - prev[2]) * 8 / dt

    async def _read_default_route(self) -> list[str]:
        body = await self._get("/api/v2/monitor/router/ipv4", {"ip_mask": "0.0.0.0/0"})
        ifaces: list[str] = []
        for route in body.get("results") or []:
            if route.get("ip_mask") in ("0.0.0.0/0", "0.0.0.0/0.0.0.0") and route.get("interface"):
                if route["interface"] not in ifaces:
                    ifaces.append(route["interface"])
        return sorted(ifaces)

    async def snapshot(self) -> Snapshot:
        """Take one reading. Raises FortiGateError if the primary health source fails."""
        now = time.time()
        if self.cfg.source == "sdwan":
            links, hc = await self._read_sdwan()
        else:
            links, hc = await self._read_link_monitor()
        snap = Snapshot(ts=now, links=links, health_check=hc)
        # secondary sources are best-effort: a failure here must not mask link health
        try:
            await self._read_interfaces(links, now)
        except FortiGateError as e:
            snap.errors.append(str(e))
        if self.cfg.track_default_route:
            try:
                snap.default_route_ifaces = await self._read_default_route()
            except FortiGateError as e:
                snap.errors.append(str(e))
        for iface in self.interfaces:  # interface missing from health data => no probe => down
            links.setdefault(iface, LinkReading(interface=iface, status="down"))
        snap.firmware = self._firmware
        snap.hostname = self._hostname
        return snap

    _firmware = ""
    _hostname = ""

    async def identify(self) -> None:
        try:
            body = await self._get("/api/v2/monitor/system/status")
            self._firmware = str(body.get("version", ""))
            res = body.get("results") or {}
            self._hostname = str(res.get("hostname", ""))
            log.info("Connected to FortiGate %s (%s, serial %s)", self._hostname or "?", self._firmware or "?", body.get("serial", "?"))
        except FortiGateError as e:
            log.warning("Could not identify FortiGate: %s", e)
