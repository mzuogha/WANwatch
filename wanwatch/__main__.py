"""WANWatch command line.

    python -m wanwatch run      -c config.yaml     start the service (dashboard + monitoring)
    python -m wanwatch check    -c config.yaml     validate config and test the FortiGate API once
    python -m wanwatch report   -c config.yaml [--day YYYY-MM-DD] [--email]
    python -m wanwatch hash-password                create a dashboard password hash
    python -m wanwatch simulate [--port 8443]       run a fake FortiGate for testing
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import logging
import logging.handlers
import sys
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

from . import __version__
from .config import ConfigError, load_config


def setup_logging(cfg) -> None:
    root = logging.getLogger()
    root.setLevel(getattr(logging, cfg.logging.level.upper(), logging.INFO))
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    root.addHandler(console)
    if cfg.logging.file:
        path = cfg.resolve(cfg.logging.file)
        path.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(path, maxBytes=cfg.logging.max_bytes,
                                                  backupCount=cfg.logging.backups, encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)
    for noisy in ("httpx", "httpcore", "uvicorn.access"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def cmd_run(args) -> int:
    import uvicorn
    from .service import MonitorService
    from .web import create_app

    cfg = load_config(args.config)
    setup_logging(cfg)
    log = logging.getLogger("wanwatch")
    log.info("WANWatch %s starting: %d link(s), polling every %ss, config %s",
             __version__, len(cfg.links), cfg.detection.poll_interval_s, args.config)
    if not cfg.web.password_hash:
        log.warning("web.password_hash is empty: the dashboard has NO authentication. "
                    "Run `python -m wanwatch hash-password` and set it before exposing the port.")
    if cfg.fortigate.verify_tls is False:
        log.warning("fortigate.verify_tls is false: the API token is sent without certificate verification.")
    svc = MonitorService(cfg)
    app = create_app(svc)
    ssl = {}
    if cfg.web.tls_cert and cfg.web.tls_key:
        ssl = {"ssl_certfile": str(cfg.resolve(cfg.web.tls_cert)), "ssl_keyfile": str(cfg.resolve(cfg.web.tls_key))}
    uvicorn.run(app, host=cfg.web.host, port=cfg.web.port, log_config=None, access_log=False, **ssl)
    return 0


def cmd_check(args) -> int:
    from .detector import classify
    from .fortigate import FortiGateClient, FortiGateError

    cfg = load_config(args.config)
    print(f"Config OK: {len(cfg.links)} link(s), source={cfg.fortigate.source}, firewall={cfg.fortigate.base_url}")

    async def go():
        c = FortiGateClient(cfg.fortigate, [l.interface for l in cfg.links])
        try:
            await c.identify()
            snap = await c.snapshot()
        finally:
            await c.close()
        print(f"Health-check: {snap.health_check}; default route via: {snap.default_route_ifaces}")
        for l in cfg.links:
            r = snap.links[l.interface]
            state, why = classify(r, l)
            print(f"  {l.name:<20} {l.interface:<10} {state:<9} latency={r.latency_ms} jitter={r.jitter_ms} "
                  f"loss={r.loss_pct} link_up={r.link_up} {'; '.join(why)}")
        for e in snap.errors:
            print(f"  warning: {e}")
    try:
        asyncio.run(go())
    except FortiGateError as e:
        print(f"FortiGate check FAILED: {e}", file=sys.stderr)
        return 2
    return 0


def cmd_report(args) -> int:
    from .service import MonitorService

    cfg = load_config(args.config)
    setup_logging(cfg)
    day = date.fromisoformat(args.day) if args.day else (datetime.now(ZoneInfo(cfg.reports.timezone)) - timedelta(days=1)).date()

    async def go():
        svc = MonitorService(cfg)
        try:
            print(await svc.build_report(day, email=args.email))
        finally:
            await svc.client.close()
            await svc.alerts.close()
    asyncio.run(go())
    return 0


def cmd_hash(_args) -> int:
    from .web import hash_password
    pw = getpass.getpass("New dashboard password: ")
    if len(pw) < 10:
        print("Use at least 10 characters.", file=sys.stderr)
        return 1
    if pw != getpass.getpass("Repeat: "):
        print("Passwords do not match.", file=sys.stderr)
        return 1
    print(hash_password(pw))
    return 0


def cmd_simulate(args) -> int:
    from .simulator import run
    run(args.host, args.port)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="wanwatch", description="FortiGate dual-WAN SLA monitor")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn in (("run", cmd_run), ("check", cmd_check), ("report", cmd_report)):
        sp = sub.add_parser(name)
        sp.add_argument("-c", "--config", default="config.yaml")
        sp.set_defaults(fn=fn)
        if name == "report":
            sp.add_argument("--day", help="YYYY-MM-DD (default: yesterday)")
            sp.add_argument("--email", action="store_true")
    sub.add_parser("hash-password").set_defaults(fn=cmd_hash)
    sim = sub.add_parser("simulate")
    sim.add_argument("--host", default="127.0.0.1")
    sim.add_argument("--port", type=int, default=8443)
    sim.set_defaults(fn=cmd_simulate)
    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except ConfigError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
