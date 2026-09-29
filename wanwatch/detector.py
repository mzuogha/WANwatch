"""Degradation and failover detection.

Each link runs a small state machine (HEALTHY / DEGRADED / DOWN) with
hysteresis: a worse state must be seen for N consecutive polls before it is
declared, and recovery needs M consecutive better polls. This keeps a single
lost probe or latency spike from paging anyone, and stops flapping links from
generating a storm of alerts.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .config import AppConfig, LinkConfig
from .fortigate import LinkReading

HEALTHY, DEGRADED, DOWN, UNKNOWN = "healthy", "degraded", "down", "unknown"
_RANK = {HEALTHY: 0, DEGRADED: 1, DOWN: 2}


@dataclass
class Event:
    ts: float
    kind: str          # link_state | failover | failback | route_change | total_outage | outage_cleared | fw_unreachable | fw_reachable
    severity: str      # info | warning | critical
    message: str
    link: str = ""     # interface or "" for global events
    from_state: str = ""
    to_state: str = ""


def classify(reading: LinkReading, link: LinkConfig) -> tuple[str, list[str]]:
    """Classify one reading. Returns (raw_state, reasons)."""
    if reading.status != "up" or (reading.loss_pct is not None and reading.loss_pct >= 100):
        return DOWN, ["link down" if reading.link_up is False else "health probes failing"]
    t = link.thresholds
    reasons = []
    if reading.latency_ms is not None and reading.latency_ms > t.latency_ms:
        reasons.append(f"latency {reading.latency_ms:.0f} ms > {t.latency_ms:.0f}")
    if reading.jitter_ms is not None and reading.jitter_ms > t.jitter_ms:
        reasons.append(f"jitter {reading.jitter_ms:.1f} ms > {t.jitter_ms:.0f}")
    if reading.loss_pct is not None and reading.loss_pct > t.packet_loss_pct:
        reasons.append(f"loss {reading.loss_pct:.1f}% > {t.packet_loss_pct:g}%")
    return (DEGRADED if reasons else HEALTHY), reasons


@dataclass
class LinkTracker:
    link: LinkConfig
    state: str = UNKNOWN
    candidate: str = ""
    count: int = 0
    since: float = 0.0
    reasons: list[str] = field(default_factory=list)

    def update(self, raw: str, reasons: list[str], ts: float, cfg: AppConfig) -> tuple[str, str] | None:
        """Feed one raw classification; return (old, new) when the confirmed state changes."""
        if self.state == UNKNOWN:  # first sample after start: adopt immediately, no alert storm on restart
            self.state, self.since, self.reasons = raw, ts, reasons
            return None
        if raw == self.state:
            self.candidate, self.count, self.reasons = "", 0, reasons if raw != HEALTHY else []
            return None
        if raw != self.candidate:
            self.candidate, self.count = raw, 0
        self.count += 1
        d = cfg.detection
        if _RANK[raw] > _RANK[self.state]:
            needed = d.down_after if raw == DOWN else d.degrade_after
        else:
            needed = d.recover_after
        if self.count >= needed:
            old = self.state
            self.state, self.since, self.reasons = raw, ts, reasons
            self.candidate, self.count = "", 0
            return old, raw
        return None


class Detector:
    def __init__(self, cfg: AppConfig):
        self.cfg = cfg
        self.trackers = {l.interface: LinkTracker(l) for l in cfg.links}
        self.api_failures = 0
        self.fw_reachable: bool | None = None
        self.default_route: list[str] | None = None
        self.total_outage = False
        self.failed_over = False

    def _name(self, iface: str) -> str:
        return self.trackers[iface].link.name

    def on_poll_failure(self, ts: float, error: str) -> list[Event]:
        self.api_failures += 1
        if self.api_failures == self.cfg.detection.unreachable_after and self.fw_reachable is not False:
            self.fw_reachable = False
            return [Event(ts, "fw_unreachable", "critical",
                          f"FortiGate API unreachable for {self.api_failures} consecutive polls: {error}. "
                          "Link health is unknown until it responds.")]
        return []

    def on_snapshot(self, ts: float, readings: dict[str, LinkReading],
                    default_route: list[str] | None) -> tuple[list[Event], dict[str, tuple[str, list[str]]]]:
        events: list[Event] = []
        self.api_failures = 0
        if self.fw_reachable is False:
            events.append(Event(ts, "fw_reachable", "info", "FortiGate API is responding again."))
        self.fw_reachable = True

        raw: dict[str, tuple[str, list[str]]] = {}
        for iface, tr in self.trackers.items():
            state, reasons = classify(readings[iface], tr.link)
            raw[iface] = (state, reasons)
            change = tr.update(state, reasons, ts, self.cfg)
            if change:
                old, new = change
                sev = {DOWN: "critical", DEGRADED: "warning", HEALTHY: "info"}[new]
                why = f" ({'; '.join(reasons)})" if reasons else ""
                verb = {DOWN: "is DOWN", DEGRADED: "is DEGRADED", HEALTHY: "has recovered"}[new]
                events.append(Event(ts, "link_state", sev, f"{tr.link.name} [{iface}] {verb}{why}.",
                                    link=iface, from_state=old, to_state=new))

        events += self._failover_events(ts)
        events += self._route_events(ts, default_route)
        return events, raw

    def _failover_events(self, ts: float) -> list[Event]:
        out: list[Event] = []
        states = {i: t.state for i, t in self.trackers.items()}
        all_down = all(s == DOWN for s in states.values())
        if all_down and not self.total_outage:
            self.total_outage = True
            out.append(Event(ts, "total_outage", "critical", "TOTAL OUTAGE: every WAN link is down. Internet access is lost."))
        elif self.total_outage and not all_down:
            self.total_outage = False
            up = ", ".join(self._name(i) for i, s in states.items() if s != DOWN)
            out.append(Event(ts, "outage_cleared", "info", f"Internet access restored via {up}."))

        primaries = [i for i, t in self.trackers.items() if t.link.role == "primary"]
        secondaries = [i for i, t in self.trackers.items() if t.link.role == "secondary"]
        if not primaries or not secondaries:
            return out
        primary_down = all(states[i] == DOWN for i in primaries)
        backup_up = any(states[i] != DOWN for i in secondaries)
        if primary_down and backup_up and not self.failed_over:
            self.failed_over = True
            to = ", ".join(self._name(i) for i in secondaries if states[i] != DOWN)
            out.append(Event(ts, "failover", "critical", f"FAILOVER: primary link down, traffic now relies on {to}."))
        elif self.failed_over and not primary_down:
            self.failed_over = False
            out.append(Event(ts, "failback", "info",
                             f"FAILBACK: primary link {', '.join(self._name(i) for i in primaries)} is available again."))
        return out

    def _route_events(self, ts: float, route: list[str] | None) -> list[Event]:
        if route is None:
            return []
        prev, self.default_route = self.default_route, route
        if prev is None or prev == route:
            return []
        fmt = lambda r: ", ".join(f"{self._name(i)} [{i}]" if i in self.trackers else i for i in r) or "none"
        sev = "critical" if not route else "info" if set(route) >= set(prev) else "warning"
        return [Event(ts, "route_change", sev,
                      f"Active default route changed: {fmt(prev)} -> {fmt(route)}.")]
