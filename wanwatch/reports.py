"""Daily availability / SLA reports.

Measurement rules (documented in the report footer too):
* Every poll represents the time until the next poll, capped at 2x the poll
  interval. Longer gaps (service stopped, host asleep) count as *unmonitored*.
* Polls where the FortiGate API did not answer are *unknown*, not down: the
  monitor cannot see the links, so it does not guess.
* Availability = (monitored time - down time) / monitored time, using the
  per-poll classification (no hysteresis) so short outages are counted.
* SLA compliance = time within latency/jitter/loss thresholds / monitored time.
* Combined availability = monitored time with at least one WAN link up.
* An outage ends at the first poll that sees the link up, or where monitoring
  stopped/the API went silent, so listed durations always add up to downtime.
"""
from __future__ import annotations

import csv
import io
import statistics
from dataclasses import dataclass, field
from datetime import date, datetime, time as dtime, timedelta
from html import escape
from pathlib import Path
from zoneinfo import ZoneInfo

from .config import AppConfig
from .storage import Store


@dataclass
class Incident:
    start: float
    end: float

    @property
    def seconds(self) -> float:
        return self.end - self.start


@dataclass
class LinkStats:
    interface: str
    name: str
    role: str
    monitored_s: float = 0
    healthy_s: float = 0
    degraded_s: float = 0
    down_s: float = 0
    latencies: list[float] = field(default_factory=list)
    jitters: list[float] = field(default_factory=list)
    losses: list[float] = field(default_factory=list)
    incidents: list[Incident] = field(default_factory=list)

    @property
    def availability(self) -> float | None:
        return None if not self.monitored_s else 100 * (self.monitored_s - self.down_s) / self.monitored_s

    @property
    def sla_compliance(self) -> float | None:
        return None if not self.monitored_s else 100 * self.healthy_s / self.monitored_s

    def pct(self, values: list[float], q: float) -> float | None:
        if not values:
            return None
        s = sorted(values)
        return s[min(len(s) - 1, int(round(q * (len(s) - 1))))]

    def mean(self, values: list[float]) -> float | None:
        return statistics.fmean(values) if values else None


@dataclass
class DailyReport:
    day: date
    tz: str
    start: float
    end: float
    target: float
    links: list[LinkStats]
    monitored_s: float
    unknown_s: float
    combined_up_s: float
    combined_monitored_s: float
    events: list
    generated: float

    @property
    def coverage(self) -> float:
        return 100 * self.monitored_s / (self.end - self.start)

    @property
    def combined_availability(self) -> float | None:
        return None if not self.combined_monitored_s else 100 * self.combined_up_s / self.combined_monitored_s


def day_bounds(day: date, tz: str) -> tuple[float, float]:
    z = ZoneInfo(tz)
    start = datetime.combine(day, dtime(0), tzinfo=z)
    end = datetime.combine(day + timedelta(days=1), dtime(0), tzinfo=z)
    return start.timestamp(), end.timestamp()


def compute(cfg: AppConfig, store: Store, day: date) -> DailyReport:
    start, end = day_bounds(day, cfg.reports.timezone)
    cap = 2 * cfg.detection.poll_interval_s
    polls = store.polls(start, end)
    rows = store.samples(start, end)
    by_ts: dict[float, dict[str, object]] = {}
    for r in rows:
        by_ts.setdefault(r["ts"], {})[r["link"]] = r

    stats = {l.interface: LinkStats(l.interface, l.name, l.role) for l in cfg.links}
    open_inc: dict[str, float | None] = {i: None for i in stats}
    monitored = unknown = comb_up = comb_mon = 0.0

    for idx, p in enumerate(polls):
        ts = p["ts"]
        nxt = polls[idx + 1]["ts"] if idx + 1 < len(polls) else end
        dur = max(0.0, min(nxt, end) - ts)
        dur = min(dur, cap)
        if not p["ok"] or ts not in by_ts:
            unknown += dur
            # visibility lost: close open outages here so incident durations match downtime
            for iface, t0 in open_inc.items():
                if t0 is not None:
                    stats[iface].incidents.append(Incident(t0, ts))
                    open_inc[iface] = None
            continue
        monitored += dur
        samples = by_ts[ts]
        all_known, any_up = True, False
        for iface, st in stats.items():
            s = samples.get(iface)
            if s is None:
                all_known = False
                continue
            st.monitored_s += dur
            raw = s["raw_state"]
            if raw == "down":
                st.down_s += dur
                if open_inc[iface] is None:
                    open_inc[iface] = ts
            else:
                any_up = True
                if open_inc[iface] is not None:
                    st.incidents.append(Incident(open_inc[iface], ts))
                    open_inc[iface] = None
                if raw == "healthy":
                    st.healthy_s += dur
                else:
                    st.degraded_s += dur
                if s["latency"] is not None: st.latencies.append(s["latency"])
                if s["jitter"] is not None: st.jitters.append(s["jitter"])
                if s["loss"] is not None: st.losses.append(s["loss"])
        if all_known:
            comb_mon += dur
            comb_up += dur if any_up else 0
        # an outage running into an unmonitored gap ends where monitoring stopped
        if idx + 1 < len(polls) and (polls[idx + 1]["ts"] - ts) > cap:
            for iface, t0 in open_inc.items():
                if t0 is not None:
                    stats[iface].incidents.append(Incident(t0, ts + cap))
                    open_inc[iface] = None
    last_end = min(end, polls[-1]["ts"] + cap) if polls else end
    for iface, t0 in open_inc.items():
        if t0 is not None:
            stats[iface].incidents.append(Incident(t0, last_end))

    events = [dict(e) for e in store.events(start, end, limit=500)]
    return DailyReport(day, cfg.reports.timezone, start, end, cfg.reports.sla_target_pct,
                       list(stats.values()), monitored, unknown, comb_up, comb_mon,
                       list(reversed(events)), datetime.now().timestamp())


def _f(v: float | None, fmt: str = "{:.3f}", none: str = "n/a") -> str:
    return none if v is None else fmt.format(v)


def _dur(seconds: float) -> str:
    seconds = int(round(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h {m:02d}m {s:02d}s" if h else f"{m}m {s:02d}s"


def render_csv(rep: DailyReport) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["record", "day", "interface", "name", "role", "availability_pct", "sla_compliance_pct",
                "target_pct", "result", "monitored_s", "down_s", "degraded_s", "avg_latency_ms",
                "p95_latency_ms", "avg_jitter_ms", "avg_loss_pct", "max_loss_pct", "incident_count",
                "incident_start", "incident_end", "incident_duration_s"])
    tz = ZoneInfo(rep.tz)
    for l in rep.links:
        a = l.availability
        w.writerow(["summary", rep.day, l.interface, l.name, l.role, _f(a, "{:.4f}", ""), _f(l.sla_compliance, "{:.4f}", ""),
                    rep.target, "" if a is None else ("PASS" if a >= rep.target else "BREACH"),
                    round(l.monitored_s), round(l.down_s), round(l.degraded_s),
                    _f(l.mean(l.latencies), "{:.1f}", ""), _f(l.pct(l.latencies, .95), "{:.1f}", ""),
                    _f(l.mean(l.jitters), "{:.2f}", ""), _f(l.mean(l.losses), "{:.2f}", ""),
                    _f(max(l.losses) if l.losses else None, "{:.1f}", ""), len(l.incidents), "", "", ""])
    ca = rep.combined_availability
    w.writerow(["summary", rep.day, "*", "Combined (any link up)", "", _f(ca, "{:.4f}", ""), "", rep.target,
                "" if ca is None else ("PASS" if ca >= rep.target else "BREACH"),
                round(rep.combined_monitored_s), round(rep.combined_monitored_s - rep.combined_up_s),
                "", "", "", "", "", "", "", "", "", ""])
    for l in rep.links:
        for inc in l.incidents:
            w.writerow(["incident", rep.day, l.interface, l.name, l.role] + [""] * 12 +
                       [datetime.fromtimestamp(inc.start, tz).isoformat(timespec="seconds"),
                        datetime.fromtimestamp(inc.end, tz).isoformat(timespec="seconds"), round(inc.seconds)])
    return buf.getvalue()


def render_html(cfg: AppConfig, rep: DailyReport) -> str:
    tz = ZoneInfo(rep.tz)
    t = lambda ts: datetime.fromtimestamp(ts, tz).strftime("%H:%M:%S")

    def verdict(v: float | None) -> str:
        if v is None:
            return "<span style='color:#6b7785'>no data</span>"
        ok = v >= rep.target
        return (f"<span style='display:inline-block;padding:2px 8px;border-radius:3px;font-weight:600;"
                f"background:{'#dff3ea' if ok else '#fbe3e0'};color:{'#17664a' if ok else '#9c2a1f'}'>"
                f"{'Met' if ok else 'Breached'}</span>")

    th = "style='text-align:left;padding:6px 10px;border-bottom:2px solid #1b2a3a;font-size:12px;color:#44515e'"
    td = "style='padding:6px 10px;border-bottom:1px solid #dfe4e8;font-variant-numeric:tabular-nums'"
    rows = ""
    for l in rep.links:
        rows += (f"<tr><td {td}><b>{escape(l.name)}</b><br><span style='color:#6b7785;font-size:12px'>{escape(l.interface)} &middot; {l.role}</span></td>"
                 f"<td {td}><b>{_f(l.availability, '{:.3f}%')}</b></td><td {td}>{verdict(l.availability)}</td>"
                 f"<td {td}>{_f(l.sla_compliance, '{:.2f}%')}</td><td {td}>{_dur(l.down_s)}</td>"
                 f"<td {td}>{_dur(l.degraded_s)}</td><td {td}>{_f(l.mean(l.latencies), '{:.0f} ms')} / {_f(l.pct(l.latencies, .95), '{:.0f} ms')}</td>"
                 f"<td {td}>{_f(l.mean(l.jitters), '{:.1f} ms')}</td><td {td}>{_f(l.mean(l.losses), '{:.2f}%')}</td>"
                 f"<td {td}>{len(l.incidents)}</td></tr>")
    ca = rep.combined_availability
    rows += (f"<tr style='background:#f3f5f7'><td {td}><b>Internet access</b><br><span style='color:#6b7785;font-size:12px'>at least one link up</span></td>"
             f"<td {td}><b>{_f(ca, '{:.3f}%')}</b></td><td {td}>{verdict(ca)}</td><td {td}></td>"
             f"<td {td}>{_dur(rep.combined_monitored_s - rep.combined_up_s)}</td><td {td} colspan='5'></td></tr>")

    inc_rows = "".join(
        f"<tr><td {td}>{escape(l.name)}</td><td {td}>{t(i.start)}</td><td {td}>{t(i.end)}</td><td {td}>{_dur(i.seconds)}</td></tr>"
        for l in rep.links for i in sorted(l.incidents, key=lambda x: x.start))
    inc_html = (f"<table style='border-collapse:collapse;width:100%;font-size:13px'><tr><th {th}>Link</th><th {th}>Down from</th>"
                f"<th {th}>Until</th><th {th}>Duration</th></tr>{inc_rows}</table>") if inc_rows else "<p>No outages recorded.</p>"
    ev_rows = "".join(
        f"<tr><td {td}>{t(e['ts'])}</td><td {td}>{escape(e['severity'])}</td><td {td}>{escape(e['message'])}</td></tr>"
        for e in rep.events)
    ev_html = (f"<table style='border-collapse:collapse;width:100%;font-size:13px'><tr><th {th}>Time</th><th {th}>Severity</th>"
               f"<th {th}>Event</th></tr>{ev_rows}</table>") if ev_rows else "<p>No alerts were raised.</p>"

    breached = [l.name for l in rep.links if l.availability is not None and l.availability < rep.target]
    headline = (f"{', '.join(breached)} missed the {rep.target:g}% availability target." if breached
                else f"All links met the {rep.target:g}% availability target." if any(l.monitored_s for l in rep.links)
                else "No monitoring data was collected for this day.")
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>{escape(cfg.title)} SLA report {rep.day}</title></head>
<body style="margin:0;background:#eef1f3;font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#1b2a3a">
<div style="max-width:980px;margin:0 auto;background:#fff;padding:28px 32px">
<p style="margin:0;color:#6b7785;font-size:13px">{escape(cfg.title)} &middot; daily WAN availability</p>
<h1 style="margin:4px 0 6px;font-size:26px">{rep.day.strftime('%A %d %B %Y')}</h1>
<p style="margin:0 0 20px;font-size:16px">{escape(headline)}</p>
<div style="overflow-x:auto"><table style="border-collapse:collapse;width:100%;font-size:13px">
<tr><th {th}>Link</th><th {th}>Availability</th><th {th}>Target {rep.target:g}%</th><th {th}>Within SLA thresholds</th>
<th {th}>Down</th><th {th}>Degraded</th><th {th}>Latency avg / p95</th><th {th}>Jitter</th><th {th}>Loss</th><th {th}>Outages</th></tr>
{rows}</table></div>
<p style="font-size:12px;color:#6b7785">Monitoring coverage {rep.coverage:.1f}% of the day ({_dur(rep.unknown_s)} with the firewall API unreachable).
Times are {escape(rep.tz)}.</p>
<h2 style="font-size:17px;margin:26px 0 8px">Outages</h2>{inc_html}
<h2 style="font-size:17px;margin:26px 0 8px">Alerts raised</h2>{ev_html}
<p style="font-size:11px;color:#8a95a1;margin-top:28px">Availability counts every poll where the FortiGate reported the link down.
Polls the firewall did not answer are excluded, not counted as downtime. SLA thresholds are per link and set in the WANWatch configuration.
Generated {datetime.fromtimestamp(rep.generated, tz).strftime('%Y-%m-%d %H:%M %Z')}.</p>
</div></body></html>"""


def summary_line(rep: DailyReport) -> str:
    parts = [f"{l.name} {_f(l.availability, '{:.3f}%')}" for l in rep.links]
    parts.append(f"combined {_f(rep.combined_availability, '{:.3f}%')}")
    return "; ".join(parts)


def generate(cfg: AppConfig, store: Store, day: date) -> tuple[DailyReport, Path, Path]:
    rep = compute(cfg, store, day)
    out = cfg.resolve(cfg.reports.directory)
    out.mkdir(parents=True, exist_ok=True)
    html_p = out / f"wan-sla-{day.isoformat()}.html"
    csv_p = out / f"wan-sla-{day.isoformat()}.csv"
    html_p.write_text(render_html(cfg, rep), encoding="utf-8")
    csv_p.write_text(render_csv(rep), encoding="utf-8", newline="")
    store.save_report(day.isoformat(), str(html_p), str(csv_p), summary_line(rep))
    return rep, html_p, csv_p


def prune(cfg: AppConfig) -> int:
    out = cfg.resolve(cfg.reports.directory)
    if not out.exists():
        return 0
    cutoff = datetime.now().timestamp() - cfg.reports.keep_days * 86400
    n = 0
    for p in out.glob("wan-sla-*.*"):
        if p.stat().st_mtime < cutoff:
            p.unlink(missing_ok=True)
            n += 1
    return n
