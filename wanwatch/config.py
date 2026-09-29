"""Configuration loading and validation.

Values of the form ${VAR} or ${VAR:-default} are expanded from the environment,
so secrets (API token, SMTP password) never need to live in the YAML file.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


class ConfigError(ValueError):
    pass


def _expand(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV_RE.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), value)
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v) for v in value]
    return value


@dataclass
class Thresholds:
    latency_ms: float = 150.0
    jitter_ms: float = 30.0
    packet_loss_pct: float = 2.0


@dataclass
class LinkConfig:
    name: str                 # display name, e.g. "MTN Fibre"
    interface: str            # FortiGate interface, e.g. "wan1"
    role: str = "primary"     # primary | secondary
    thresholds: Thresholds = field(default_factory=Thresholds)


@dataclass
class FortiGateConfig:
    base_url: str
    api_token: str
    verify_tls: bool | str = True      # True/False or path to CA bundle
    timeout_s: float = 8.0
    vdom: str = ""
    source: str = "sdwan"              # sdwan | link-monitor
    health_check: str = ""             # SD-WAN health-check / link-monitor name; "" = first found
    track_default_route: bool = True


@dataclass
class DetectionConfig:
    poll_interval_s: int = 10
    down_after: int = 2        # consecutive DOWN samples before declaring DOWN
    degrade_after: int = 3     # consecutive DEGRADED samples before declaring DEGRADED
    recover_after: int = 5     # consecutive better samples before recovering
    unreachable_after: int = 3 # consecutive API failures before firewall-unreachable alert


@dataclass
class EmailConfig:
    enabled: bool = False
    host: str = ""
    port: int = 587
    starttls: bool = True
    ssl: bool = False
    username: str = ""
    password: str = ""
    sender: str = ""
    recipients: list[str] = field(default_factory=list)


@dataclass
class WebhookConfig:
    url: str
    kind: str = "generic"  # generic | slack | teams


@dataclass
class AlertConfig:
    cooldown_s: int = 300
    min_severity: str = "warning"  # info | warning | critical
    email: EmailConfig = field(default_factory=EmailConfig)
    webhooks: list[WebhookConfig] = field(default_factory=list)


@dataclass
class ReportConfig:
    enabled: bool = True
    time: str = "00:10"             # local time the previous day's report is built
    timezone: str = "Africa/Lagos"
    sla_target_pct: float = 99.5
    directory: str = "reports"
    email: bool = True
    keep_days: int = 400


@dataclass
class WebConfig:
    host: str = "0.0.0.0"
    port: int = 8080
    username: str = "admin"
    password_hash: str = ""       # pbkdf2 hash from `python -m wanwatch hash-password`
    public_metrics: bool = False  # expose /metrics without auth (for Prometheus on a trusted net)
    tls_cert: str = ""
    tls_key: str = ""


@dataclass
class StorageConfig:
    path: str = "data/wanwatch.db"
    retention_days: int = 90


@dataclass
class LoggingConfig:
    level: str = "INFO"
    file: str = "logs/wanwatch.log"
    max_bytes: int = 5_000_000
    backups: int = 5


@dataclass
class AppConfig:
    title: str
    fortigate: FortiGateConfig
    links: list[LinkConfig]
    detection: DetectionConfig
    alerts: AlertConfig
    reports: ReportConfig
    web: WebConfig
    storage: StorageConfig
    logging: LoggingConfig
    base_dir: Path

    def resolve(self, p: str) -> Path:
        path = Path(p)
        return path if path.is_absolute() else (self.base_dir / path)

    def link_by_interface(self, iface: str) -> LinkConfig | None:
        return next((l for l in self.links if l.interface == iface), None)


def _build(cls, data: dict | None, where: str):
    data = data or {}
    known = {f for f in cls.__dataclass_fields__}
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"{where}: unknown key(s) {sorted(unknown)}")
    try:
        return cls(**data)
    except TypeError as e:
        raise ConfigError(f"{where}: {e}") from None


def load_env_file(path: Path) -> None:
    """Load KEY=VALUE lines from wanwatch.env (does not override real env vars)."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def load_config(path: str | Path) -> AppConfig:
    path = Path(path).resolve()
    if not path.exists():
        raise ConfigError(f"config file not found: {path}")
    load_env_file(path.parent / "wanwatch.env")
    raw = _expand(yaml.safe_load(path.read_text(encoding="utf-8")) or {})

    fg = raw.get("fortigate") or {}
    if not fg.get("base_url"):
        raise ConfigError("fortigate.base_url is required")
    if not fg.get("api_token"):
        raise ConfigError("fortigate.api_token is required (tip: api_token: ${FGT_API_TOKEN})")
    fortigate = _build(FortiGateConfig, fg, "fortigate")
    fortigate.base_url = fortigate.base_url.rstrip("/")
    if fortigate.source not in ("sdwan", "link-monitor"):
        raise ConfigError("fortigate.source must be 'sdwan' or 'link-monitor'")

    default_thr = raw.get("default_thresholds") or {}
    links: list[LinkConfig] = []
    for i, l in enumerate(raw.get("links") or []):
        thr = _build(Thresholds, {**default_thr, **(l.get("thresholds") or {})}, f"links[{i}].thresholds")
        links.append(_build(LinkConfig, {**l, "thresholds": thr}, f"links[{i}]"))
    if len(links) < 1:
        raise ConfigError("at least one link must be configured under 'links'")
    if len({l.interface for l in links}) != len(links):
        raise ConfigError("link interfaces must be unique")
    for l in links:
        if l.role not in ("primary", "secondary"):
            raise ConfigError(f"link {l.name}: role must be primary or secondary")

    al = raw.get("alerts") or {}
    alerts = AlertConfig(
        cooldown_s=int(al.get("cooldown_s", 300)),
        min_severity=al.get("min_severity", "warning"),
        email=_build(EmailConfig, al.get("email"), "alerts.email"),
        webhooks=[_build(WebhookConfig, w, f"alerts.webhooks[{i}]") for i, w in enumerate(al.get("webhooks") or [])],
    )
    if alerts.min_severity not in ("info", "warning", "critical"):
        raise ConfigError("alerts.min_severity must be info, warning or critical")
    for w in alerts.webhooks:
        if w.kind not in ("generic", "slack", "teams"):
            raise ConfigError(f"webhook kind '{w.kind}' must be generic, slack or teams")

    detection = _build(DetectionConfig, raw.get("detection"), "detection")
    if detection.poll_interval_s < 2:
        raise ConfigError("detection.poll_interval_s must be >= 2")

    reports = _build(ReportConfig, raw.get("reports"), "reports")
    if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", reports.time):
        raise ConfigError("reports.time must be HH:MM (24h)")
    try:
        from zoneinfo import ZoneInfo
        ZoneInfo(reports.timezone)
    except Exception:
        raise ConfigError(f"reports.timezone '{reports.timezone}' is not a valid IANA zone") from None

    return AppConfig(
        title=raw.get("title", "WANWatch"),
        fortigate=fortigate,
        links=links,
        detection=detection,
        alerts=alerts,
        reports=reports,
        web=_build(WebConfig, raw.get("web"), "web"),
        storage=_build(StorageConfig, raw.get("storage"), "storage"),
        logging=_build(LoggingConfig, raw.get("logging"), "logging"),
        base_dir=path.parent,
    )
