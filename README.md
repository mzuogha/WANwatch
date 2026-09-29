# Fortigate WAN Monitor (WANWatch)

Jump to: [Linux install](#3-install-on-linux), [Windows install](#4-install-on-windows), [Configure](#5-configure), [Troubleshooting](#troubleshooting)

A lightweight service that watches both WAN links on a FortiGate, alerts on degradation,
outages and failover, keeps a history, and emails a daily availability/SLA report. It runs
unattended as a systemd service on Linux or a Windows service, with a live web dashboard.

* **Detection** — polls the FortiGate REST API (SD-WAN performance SLA or link-monitor) every
  10 s. Each link is *healthy*, *degraded* (latency, jitter or loss over its threshold) or
  *down*. Changes are confirmed over several polls (hysteresis) so one lost probe never pages anyone.
* **Failover alerting** — primary down with backup up raises **FAILOVER**; recovery raises
  **FAILBACK**; both links down raises **TOTAL OUTAGE**. Moves of the active default route and
  loss of the firewall API itself are alerted separately.
* **Alerts** — email (SMTP/STARTTLS, Microsoft 365 friendly), Microsoft Teams (Workflows
  webhook, Adaptive Card), Slack and generic JSON webhooks, with cooldown and guaranteed
  recovery notices. Delivery never blocks monitoring.
* **Daily SLA report** — HTML (emailed) + CSV per day: availability %, time within SLA
  thresholds, downtime, avg/p95 latency, jitter, loss, every outage with start/end, combined
  "internet available" figure, pass/breach against your target. Missed reports are caught up
  automatically after downtime.
* **Operations** — SQLite storage with retention, rotating logs, `/healthz` for watchdogs,
  `/metrics` for Prometheus, pbkdf2 password auth, optional HTTPS, no external CDNs (works
  on an isolated management network).

Requires Python 3.10+ and FortiOS 6.4 or later (tested against the 7.x API format).

## 1. Prepare the FortiGate

Create a read-only REST API user (replace the trusted host with the monitoring server's IP):

```
config system accprofile
    edit "wanwatch_ro"
        set sysgrp read
        set netgrp read
    next
end
config system api-user
    edit "wanwatch"
        set accprofile "wanwatch_ro"
        set vdom "root"
        config trusthost
            edit 1
                set ipv4-trusthost 10.10.10.50 255.255.255.255
            next
        end
    next
end
execute api-user generate-key wanwatch
```

Keep the generated key; it goes into `wanwatch.env`. If `check` later reports HTTP 403 on
one endpoint, grant read on the matching permission group for that profile.

WANWatch reads **SD-WAN performance SLA** health-checks (`source: sdwan`, recommended). A
health-check whose members include both WAN interfaces is enough, for example:

```
config system sdwan
    config health-check
        edit "WAN_Health"
            set server "1.1.1.1" "8.8.8.8"
            set members 1 2
            config sla
                edit 1
                    set latency-threshold 150
                    set jitter-threshold 30
                    set packetloss-threshold 2
                next
            end
        next
    end
end
```

Not using SD-WAN? Set `source: link-monitor` and configure `config system link-monitor`
entries on each WAN interface instead.

## 2. Try it without a firewall (optional, 2 minutes)

```bash
pip install -r requirements.txt
python -m wanwatch simulate &                     # fake FortiGate on 127.0.0.1:8443
cp config.example.yaml config.yaml
# edit config.yaml: base_url: http://127.0.0.1:8443, api_token: anything-12chars
python -m wanwatch run -c config.yaml             # dashboard on http://localhost:8080
```

The simulator runs an 8-minute scenario (wan1 degrades then fails over to wan2). Force states with
`curl -X POST "http://127.0.0.1:8443/sim/set?iface=wan1&mode=down"` (healthy / degraded / down / auto)
or cut the "firewall" off with `curl -X POST "http://127.0.0.1:8443/sim/api?mode=offline"`.

## 3. Install on Linux

Tested on Ubuntu 22.04/24.04, Debian 12 and RHEL/Rocky 9. Any distribution with systemd and
Python 3.10+ works.

**Step 1: install prerequisites**

```bash
# Ubuntu / Debian
sudo apt update && sudo apt install -y python3 python3-venv git curl
# RHEL / Rocky / Alma
sudo dnf install -y python3 git curl
python3 --version        # must be 3.10 or newer
```

**Step 2: get the code and run the installer**

```bash
git clone https://github.com/mzuogha/Fortigate-WAN-Monitor.git
cd Fortigate-WAN-Monitor
sudo ./deploy/install-linux.sh
```

The installer creates a `wanwatch` system user, copies the app to `/opt/wanwatch`, builds a
Python virtual environment, and registers the hardened `wanwatch` systemd service (enabled,
not yet started). Existing `config.yaml` and `wanwatch.env` are never overwritten.

**Step 3: add secrets and settings**

```bash
sudo nano /opt/wanwatch/wanwatch.env     # FGT_API_TOKEN=..., SMTP_PASSWORD=..., webhook URLs
sudo nano /opt/wanwatch/config.yaml      # firewall URL, link names, alerts, report time (see section 5)
```

**Step 4: set the dashboard password**

```bash
sudo -u wanwatch /opt/wanwatch/venv/bin/python -m wanwatch hash-password
# paste the printed pbkdf2_sha256$... value into web.password_hash in config.yaml
```

**Step 5: test the firewall connection, then start**

```bash
sudo -u wanwatch /opt/wanwatch/venv/bin/python -m wanwatch check -c /opt/wanwatch/config.yaml
sudo systemctl start wanwatch
systemctl status wanwatch
```

`check` should print one line per link with its state and latency. Open
`http://<server-ip>:8080`, sign in, and press **Send test alert**. If a host firewall is
running, open the port: `sudo ufw allow 8080/tcp` or
`sudo firewall-cmd --add-port=8080/tcp --permanent && sudo firewall-cmd --reload`.

**Day-to-day**

| Task | Command |
|---|---|
| Live log | `journalctl -u wanwatch -f` (also `/opt/wanwatch/logs/wanwatch.log`) |
| Restart after config change | `sudo systemctl restart wanwatch` |
| Build yesterday's report now | `sudo -u wanwatch /opt/wanwatch/venv/bin/python -m wanwatch report -c /opt/wanwatch/config.yaml` |
| Upgrade | `git pull && sudo ./deploy/install-linux.sh && sudo systemctl restart wanwatch` |
| Uninstall (keep data) | `sudo ./deploy/uninstall-linux.sh` |
| Uninstall everything | `sudo ./deploy/uninstall-linux.sh --purge` |

## 4. Install on Windows

Works on Windows 10/11 and Windows Server 2016 or later.

**Step 1: install Python**

Download Python 3.12 from [python.org](https://www.python.org/downloads/windows/). In the
installer choose **Customize installation**, tick **Install Python for all users** and
**Add Python to environment variables**. An all-users install matters: the service runs as
SYSTEM and cannot use a Python installed only in your profile. Check in a new PowerShell
window:

```powershell
py -3 --version     # or: python --version   (3.10 or newer)
```

**Step 2 (recommended): get NSSM**

[NSSM](https://nssm.cc/download) turns WANWatch into a real Windows service with automatic
restart and log rotation. Extract `win64\nssm.exe` and copy it into the `deploy` folder of this
project (or anywhere on PATH, or `winget install NSSM.NSSM`). Without NSSM the installer uses a
SYSTEM scheduled task that starts at boot and restarts on failure instead.

**Step 3: get the code and run the installer**

Download the repository (**Code > Download ZIP**, then extract it) or clone it:

```powershell
git clone https://github.com/mzuogha/Fortigate-WAN-Monitor.git
cd Fortigate-WAN-Monitor
```

Then either double-click `deploy\install-windows.cmd` (it asks for Administrator rights
itself), or from an **Administrator** PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\install-windows.ps1
# optional: -Port 9090  -InstallDir "D:\WANWatch"  -ServiceName "WANWatch"
```

The installer copies the app to `C:\Program Files\WANWatch`, builds a virtual environment,
restricts `config.yaml` and `wanwatch.env` to Administrators and SYSTEM, registers the
service (not yet started) and opens the dashboard port for Domain and Private networks.
Existing `config.yaml` and `wanwatch.env` are never overwritten.

**Step 4: add secrets and settings**

Because both files are locked to administrators, edit them from an Administrator prompt:

```powershell
notepad "C:\Program Files\WANWatch\wanwatch.env"    # FGT_API_TOKEN=..., SMTP_PASSWORD=...
notepad "C:\Program Files\WANWatch\config.yaml"     # firewall URL, links, alerts (see section 5)
```

**Step 5: set the dashboard password**

```powershell
& "C:\Program Files\WANWatch\venv\Scripts\python.exe" -m wanwatch hash-password
# paste the printed pbkdf2_sha256$... value into web.password_hash in config.yaml
```

**Step 6: test the firewall connection, then start**

```powershell
& "C:\Program Files\WANWatch\venv\Scripts\python.exe" -m wanwatch check -c "C:\Program Files\WANWatch\config.yaml"
Start-Service WANWatch          # NSSM install
Start-ScheduledTask WANWatch    # scheduled-task install
```

Open `http://localhost:8080` (or `http://<server-ip>:8080` from another PC), sign in, and
press **Send test alert**.

**Day-to-day**

| Task | NSSM service | Scheduled task |
|---|---|---|
| Status | `Get-Service WANWatch` | `Get-ScheduledTask WANWatch \| Get-ScheduledTaskInfo` |
| Restart after config change | `Restart-Service WANWatch` | `Stop-ScheduledTask WANWatch; Start-ScheduledTask WANWatch` |
| Logs | `C:\Program Files\WANWatch\logs\` | same |
| Upgrade | stop, re-run the installer from the new code, start | same |
| Uninstall (keeps data) | `.\deploy\uninstall-windows.ps1` (Administrator) | same |

## 5. Configure

Everything lives in `config.yaml` (template: [`config.example.yaml`](config.example.yaml)) plus
secrets in `wanwatch.env` (template: [`wanwatch.env.example`](wanwatch.env.example)). Any value
written as `${NAME}` is read from `wanwatch.env` or the environment. The settings most people change:

| Setting | What to set |
|---|---|
| `fortigate.base_url` | `https://<firewall-ip>` (add `:port` if admin HTTPS isn't on 443) |
| `fortigate.verify_tls` | keep `true`; for a self-signed firewall certificate give the path to its exported certificate |
| `fortigate.source` / `health_check` | `sdwan` + your health-check name, or `link-monitor` |
| `links` | one entry per WAN: display `name`, FortiGate `interface` (e.g. `wan1`), `role` primary/secondary |
| `default_thresholds` | latency / jitter / loss that count as degraded (override per link) |
| `alerts.email`, `alerts.webhooks` | where alerts go (email, `teams`, `slack`, `generic`) |
| `reports.time`, `timezone`, `sla_target_pct` | when the daily report is built and the target it's judged against |
| `web.port`, `web.password_hash` | dashboard port and password |

Restart the service after any change.

## Commands

| Command | Purpose |
|---|---|
| `run -c config.yaml` | Start monitoring + dashboard (what the service runs) |
| `check -c config.yaml` | Validate config and test the FortiGate API once |
| `report -c config.yaml [--day YYYY-MM-DD] [--email]` | Build a report now (default: yesterday) |
| `hash-password` | Create a dashboard password hash |
| `simulate [--port 8443]` | Fake FortiGate for testing |

## How detection works

| Setting | Default | Meaning |
|---|---|---|
| `poll_interval_s` | 10 | Seconds between readings |
| `down_after` | 2 | Consecutive failing polls before DOWN (~20 s) |
| `degrade_after` | 3 | Consecutive polls over a threshold before DEGRADED (~30 s) |
| `recover_after` | 5 | Consecutive better polls before recovery (~50 s) |
| `unreachable_after` | 3 | Consecutive API failures before "firewall unreachable" |

A link is down when its health probes fail, packet loss is 100%, or the physical link is down.
On (re)start the current state is adopted silently, so restarts don't send alert storms.
Alerts repeat for the same condition at most once per `cooldown_s`; a worsening
(degraded → down) is always sent, and every delivered problem alert gets its recovery notice.

## How the SLA report is calculated

* Each poll accounts for the time until the next poll (capped at 2× the interval). Gaps longer
  than that — service stopped, host asleep — are reported as unmonitored, not as uptime.
* Polls the firewall API didn't answer are **excluded**, not counted as downtime; the report
  shows monitoring coverage so you can judge completeness.
* **Availability** uses each poll's raw result (no hysteresis), so short outages count.
* **Within SLA thresholds** is the share of time the link was healthy (not degraded or down).
* **Internet access** (combined) is time with at least one link up — the figure that matters
  to users when failover works.

Reports land in `reports/wan-sla-YYYY-MM-DD.{html,csv}` and are kept `keep_days` (default 400).

## HTTP API (basic auth, same credentials as the dashboard)

`GET /api/status` · `GET /api/history?hours=24&points=288` · `GET /api/events?limit=100` ·
`GET /api/reports` · `POST /api/reports/generate?day=YYYY-MM-DD&email=false` ·
`GET /reports/{day}.html|csv` · `POST /api/alerts/test` · `GET /api/stream` (Server-Sent Events) ·
`GET /metrics` (Prometheus; set `public_metrics: true` to scrape without auth) ·
`GET /healthz` (no auth; 503 if polling has stalled — point your watchdog here).

## Security notes

* Use a read-only API profile and restrict its trusted hosts to the monitoring server.
* Keep `verify_tls: true`. For a self-signed FortiGate certificate, export it and set
  `verify_tls: /path/to/fortigate-ca.pem` rather than disabling verification.
* Set `web.password_hash`; the service logs a warning at every start while it is empty.
  Set `tls_cert`/`tls_key` or put the dashboard behind your reverse proxy for HTTPS.
* Five minutes of lockout per source IP after 10 failed sign-ins.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `HTTP 401/403` | Token wrong, source IP not in trusthost, or profile lacks read on that group |
| `no SD-WAN health-checks found` | Configure a performance SLA, or use `source: link-monitor` |
| `health-check 'X' not found` | Name is case-sensitive; `check` prints the available names |
| Link always "down" | The interface name in `links` must match the FortiGate member (`wan1`, `port1`…) |
| `CERTIFICATE_VERIFY_FAILED` | Point `verify_tls` at the firewall's CA/certificate file |
| Reports not emailed | `alerts.email.enabled: true`; test with **Send test alert** |

## Development

```bash
pip install -r requirements.txt pytest
python -m pytest -q
```

Layout: `fortigate.py` (API client) → `detector.py` (state machines) → `service.py` (poll
loop, scheduler) → `storage.py` (SQLite) / `alerts.py` / `reports.py`; `web.py` serves the
dashboard in `static/index.html`.

## License

MIT, see [LICENSE](LICENSE).
