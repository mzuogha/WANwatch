import asyncio
import time
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from wanwatch.alerts import AlertManager
from wanwatch.config import ConfigError, load_config
from wanwatch.detector import Detector, Event, classify
from wanwatch.fortigate import LinkReading
from wanwatch import reports
from wanwatch.storage import Store
from wanwatch.web import hash_password, verify_password

CFG = """
title: T
fortigate: {base_url: "https://fw", api_token: "x"}
links:
  - {name: A, interface: wan1, role: primary}
  - {name: B, interface: wan2, role: secondary, thresholds: {latency_ms: 300}}
detection: {poll_interval_s: 10, down_after: 2, degrade_after: 3, recover_after: 2}
reports: {timezone: Africa/Lagos, sla_target_pct: 99.5}
storage: {path: db.sqlite}
"""


@pytest.fixture
def cfg(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text(CFG)
    return load_config(p)


def up(lat=20, jit=1, loss=0):
    return LinkReading("x", "up", lat, jit, loss)


def down():
    return LinkReading("x", "down", loss_pct=100)


def feed(det, seq, t0=1000.0):
    evs = []
    for i, (a, b) in enumerate(seq):
        e, _ = det.on_snapshot(t0 + i * 10, {"wan1": a, "wan2": b}, None)
        evs += e
    return evs


def test_classify_thresholds(cfg):
    a, b = cfg.links
    assert classify(up(), a)[0] == "healthy"
    assert classify(up(lat=200), a)[0] == "degraded"
    assert classify(up(lat=200), b)[0] == "healthy"  # per-link override
    assert classify(up(loss=5), a)[0] == "degraded"
    assert classify(down(), a)[0] == "down"
    assert classify(LinkReading("x", "up", loss_pct=100), a)[0] == "down"


def test_single_blip_does_not_alert(cfg):
    det = Detector(cfg)
    evs = feed(det, [(up(), up()), (down(), up()), (up(), up()), (up(lat=500), up()), (up(), up())])
    assert [e for e in evs if e.kind == "link_state"] == []


def test_down_failover_and_failback(cfg):
    det = Detector(cfg)
    evs = feed(det, [(up(), up()), (down(), up()), (down(), up()), (down(), up()), (up(), up()), (up(), up())])
    kinds = [e.kind for e in evs]
    assert kinds == ["link_state", "failover", "link_state", "failback"]
    assert evs[0].to_state == "down" and evs[0].severity == "critical"
    assert evs[2].to_state == "healthy"


def test_total_outage(cfg):
    det = Detector(cfg)
    evs = feed(det, [(up(), up()), (down(), down()), (down(), down()), (up(), down()), (up(), down())])
    kinds = [e.kind for e in evs]
    assert "total_outage" in kinds and "outage_cleared" in kinds


def test_unreachable_after_n_failures(cfg):
    det = Detector(cfg)
    assert det.on_poll_failure(1, "x") == [] and det.on_poll_failure(2, "x") == []
    assert det.on_poll_failure(3, "x")[0].kind == "fw_unreachable"
    assert det.on_poll_failure(4, "x") == []  # only once
    evs, _ = det.on_snapshot(5, {"wan1": up(), "wan2": up()}, None)
    assert evs[0].kind == "fw_reachable"


def test_route_change(cfg):
    det = Detector(cfg)
    det.on_snapshot(1, {"wan1": up(), "wan2": up()}, ["wan1", "wan2"])
    evs, _ = det.on_snapshot(2, {"wan1": up(), "wan2": up()}, ["wan2"])
    assert evs[0].kind == "route_change" and evs[0].severity == "warning"
    evs, _ = det.on_snapshot(3, {"wan1": up(), "wan2": up()}, ["wan1", "wan2"])
    assert evs[0].severity == "info"


def test_alert_cooldown_and_recovery_pairing(cfg):
    async def go():
        am = AlertManager(cfg)
        down_ev = Event(0, "link_state", "critical", "down", "wan1", "healthy", "down")
        rec = Event(0, "link_state", "info", "rec", "wan1", "down", "healthy")
        assert am._should_send(down_ev)
        assert not am._should_send(down_ev)      # cooldown
        assert am._should_send(rec)              # recovery of a sent problem
        assert not am._should_send(rec)          # min_severity warning, nothing open
        await am.close()
    asyncio.run(go())


def test_daily_report_math(cfg):
    store = Store(cfg.resolve(cfg.storage.path))
    day = date(2026, 9, 1)
    start, end = reports.day_bounds(day, "Africa/Lagos")
    # full day at 10s: wan1 down for 1 hour, 30 minutes of API outage, wan2 always up
    ts = start
    while ts < end:
        in_api_gap = start + 7200 <= ts < start + 9000
        if in_api_gap:
            store.add_poll(ts, [], False, "timeout")
        else:
            w1 = "down" if start + 3600 <= ts < start + 7200 else "healthy"
            store.add_poll(ts, [(ts, "wan1", w1, w1, None if w1 == "down" else 20, 1, 0, 1, None, None),
                                (ts, "wan2", "healthy", "healthy", 40, 2, 0, 1, None, None)], True)
        ts += 10
    rep = reports.compute(cfg, store, day)
    a, b = rep.links
    assert rep.unknown_s == pytest.approx(1800)
    assert a.down_s == pytest.approx(3600)
    assert a.availability == pytest.approx(100 * (84600 - 3600) / 84600)
    assert b.availability == 100
    assert rep.combined_availability == 100
    assert len(a.incidents) == 1 and a.incidents[0].seconds == pytest.approx(3600)
    assert "BREACH" in reports.render_csv(rep)
    assert "missed the 99.5% availability target" in reports.render_html(cfg, rep)
    store.close()


def test_report_counts_unmonitored_gap(cfg):
    store = Store(cfg.resolve(cfg.storage.path))
    day = date(2026, 9, 2)
    start, _ = reports.day_bounds(day, "Africa/Lagos")
    for ts in (start, start + 10, start + 5000):  # 5000s gap: service was stopped
        store.add_poll(ts, [(ts, "wan1", "healthy", "healthy", 5, 1, 0, 1, None, None),
                            (ts, "wan2", "healthy", "healthy", 5, 1, 0, 1, None, None)], True)
    rep = reports.compute(cfg, store, day)
    assert rep.monitored_s == pytest.approx(10 + 20 + 20)  # each capped at 2x interval
    store.close()


def test_password_hash():
    h = hash_password("correct horse battery")
    assert verify_password("correct horse battery", h)
    assert not verify_password("wrong", h)
    assert not verify_password("x", "garbage")


def test_config_errors(tmp_path, monkeypatch):
    p = tmp_path / "c.yaml"
    p.write_text("fortigate: {base_url: https://fw, api_token: '${NOPE}'}\nlinks: [{name: A, interface: wan1}]\n")
    with pytest.raises(ConfigError, match="api_token"):
        load_config(p)
    monkeypatch.setenv("NOPE", "tok")
    assert load_config(p).fortigate.api_token == "tok"
    p.write_text("fortigate: {base_url: https://fw, api_token: t}\nlinks: [{name: A, interface: wan1, colour: red}]\n")
    with pytest.raises(ConfigError, match="unknown key"):
        load_config(p)
