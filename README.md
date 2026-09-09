# sysmon-agent

A single-binary-style CLI that installs a background service on **Ubuntu** and
**Windows**. The service samples CPU, memory, disk and network, records every
login and logout session (SSH, RDP, VNC and local console), starts at boot,
restarts after a crash, and pushes everything to an OTLP/HTTP collector.

Built with `uv`. No agent-side database, no local dashboard: the collector is
the destination.

---

## Install

The installer asks for the collector endpoint, the authentication scheme and the
machine name, verifies the collector answers, writes the configuration, then
registers and starts the service.

### Ubuntu

```bash
sudo ./scripts/install-ubuntu.sh
```

The script builds a venv at `/opt/sysmon-agent/venv`, links
`/usr/local/bin/sysmon-agent`, and runs `sysmon-agent install`. Doing it by hand
is the same three steps:

```bash
sudo uv venv --python 3.11 /opt/sysmon-agent/venv
sudo uv pip install --python /opt/sysmon-agent/venv/bin/python .
sudo /opt/sysmon-agent/venv/bin/sysmon-agent install
```

### Windows

From an elevated PowerShell:

```powershell
.\scripts\install-windows.ps1
```

This builds a venv under `C:\ProgramData\sysmon-agent\venv`, runs pywin32's
post-install step (pip skips it, and the service host needs it), and registers a
real Windows service. If pywin32 cannot be loaded the installer falls back to a
SYSTEM scheduled task that starts at boot and restarts on failure.

### Unattended

Every prompt has a flag:

```bash
sudo sysmon-agent install \
  --endpoint https://otel.example.com:4318 \
  --machine-name edge-01 \
  --auth-type bearer --token "$OTLP_TOKEN" \
  --interval 30 --session-poll 5 \
  --environment production --attribute team=infra \
  --non-interactive
```

Authentication schemes: `none`, `bearer`, `basic`, `header` (any custom header,
for example `X-API-Key`).

---

## Commands

| Command | What it does |
| --- | --- |
| `sysmon-agent install` | Prompt for settings, verify the collector, install and start the service |
| `sysmon-agent remove` | Stop and unregister the service. `--purge` also deletes config, state and logs |
| `sysmon-agent logs` | Show the agent log. `-f` follows, `-n` sets the line count, `--source journal` reads the systemd journal |
| `sysmon-agent status` | Service state, effective configuration and a live system snapshot |
| `sysmon-agent sessions` | List the login sessions detected right now, with their classification |
| `sysmon-agent test` | Check that the collector is reachable and the credentials are accepted |
| `sysmon-agent config` | Print the stored configuration with secrets redacted |
| `sysmon-agent restart` | Restart the background service |
| `sysmon-agent run` | Run in the foreground; this is what the service manager calls |

`install`, `remove` and `restart` need root on Linux and Administrator on Windows.

---

## What gets exported

### Metrics (OTLP/HTTP, default every 30 s)

| Instrument | Attributes |
| --- | --- |
| `system.cpu.utilization`, `system.cpu.time.utilization`, `system.cpu.logical.count`, `system.cpu.load_average` | `state`, `period` |
| `system.memory.usage`, `system.memory.utilization` | `state` |
| `system.paging.usage`, `system.paging.utilization` | `state` |
| `system.filesystem.usage`, `system.filesystem.utilization` | `device`, `mountpoint`, `type`, `state` |
| `system.disk.io`, `system.disk.operations` | `device`, `direction` |
| `system.network.io`, `system.network.packets`, `system.network.errors`, `system.network.dropped` | `device`, `direction` |
| `system.network.connections` | `state` |
| `system.processes.count`, `system.uptime` | — |
| `system.sessions.active` | `session.kind` |
| `system.sessions.events` | `event.name`, `session.kind`, `session.source` |

Pseudo filesystems (tmpfs, squashfs, overlay, /snap, …) are filtered out.

### Session events (OTLP logs)

One log record per event, with `event.name` set to `session.start`,
`session.end`, `session.observed` (a session that was already open when the
agent started), `rdp.disconnected`, `rdp.reconnected`, `agent.start` or
`agent.stop`.

Attributes: `session.id`, `session.kind`, `session.source`, `user.name`,
`enduser.id`, `client.address`, `client.port`, `session.terminal`,
`session.display`, `session.service`, `session.logon_type`, `process.pid`,
`session.started_at`, `session.ended_at`, `session.duration_seconds`.

`session.kind` is one of `ssh`, `rdp`, `vnc`, `console`, `gui`, `remote`,
`unknown`.

### Resource attributes

`service.name`, `service.version`, `service.instance.id`, `host.name` (the
machine name you entered), `host.fqdn`, `host.arch`, `os.type`, `os.description`,
`os.version`, plus `deployment.environment` and any `--attribute KEY=VALUE` pairs.

---

## How sessions are detected

**Ubuntu.** systemd-logind is the source: it reports the session class, type,
seat, remote host and leader process, which is enough to separate SSH from a
local console from an xrdp seat. The leader process name is checked against a
list of VNC servers so a VNC-backed X11 seat is labelled `vnc` rather than `gui`.
On a system without systemd the agent falls back to utmp through psutil, which
still sees SSH, console and X11 logins.

**Windows.** The Security event log is the source: 4624 for logon, 4634 and 4647
for logoff, keyed on the logon id. Logon types map to kinds (2/7/11 console,
10/12 RDP). Service, batch and plain network logons are dropped, as are machine
accounts and the built-in noise accounts (SYSTEM, DWM-*, UMFD-*). The
TerminalServices channel adds RDP disconnect and reconnect events, which are not
logoffs but matter operationally. `quser` seeds the sessions that were already
open when the agent started.

**VNC.** Most VNC servers authenticate on their own and never create an OS login
session, so neither source above sees them. The agent additionally looks for
established TCP connections owned by a VNC server process and reports each one as
a `vnc` session with the client address. When a VNC server does use system
authentication (UltraVNC or TightVNC with MS Logon), the Windows logon is
classified `vnc` from its process name instead.

---

## Reliability

**Ubuntu.** A systemd unit with `Restart=always`, `RestartSec=5` and
`StartLimitIntervalSec=0`, so systemd never stops retrying, and
`WantedBy=multi-user.target` for start at boot. Unit file:
`/etc/systemd/system/sysmon-agent.service`.

**Windows.** A service with `SERVICE_AUTO_START` and SCM failure actions
`restart/5s, restart/10s, restart/30s` with a daily failure-count reset. The
scheduled-task fallback uses a boot trigger with `RestartOnFailure` (999
attempts, one minute apart) and no execution time limit.

Export failures never stop the agent: the OTLP batch processors retry, and
metric collection continues. The exporter's own logs are deliberately kept out
of the exported log stream so a collector outage cannot feed itself.

---

## Files

| | Ubuntu | Windows |
| --- | --- | --- |
| Config | `/etc/sysmon-agent/config.json` (0600) | `C:\ProgramData\sysmon-agent\config.json` (SYSTEM + Administrators) |
| Logs | `/var/log/sysmon-agent/agent.log` | `C:\ProgramData\sysmon-agent\logs\agent.log` |
| State | `/var/lib/sysmon-agent` | `C:\ProgramData\sysmon-agent\state` |

The log file rotates at 10 MB, keeping five generations. On Ubuntu the same
output also reaches the journal, so `sysmon-agent logs --source journal` works.

Set `SYSMON_AGENT_HOME` to relocate all three, which is how you run the agent
without root for a smoke test:

```bash
SYSMON_AGENT_HOME=/tmp/sysmon sysmon-agent run
```

---

## Requirements and limits

- Python 3.9+ managed by `uv`; the installer pins 3.11 for the service venv.
- Ubuntu 16.04+ (any systemd release) or Windows 10 / Server 2016+.
- The service runs as root / LocalSystem. It has to: utmp, logind, the Security
  event log and per-process network counters are all privileged reads.
- Windows session tracking needs the Security log to actually audit logons.
  "Audit logon events" is on by default on Windows client and server; if it was
  turned off, no 4624 records exist to read.
- The Windows agent polls the event log rather than subscribing, so a logon and
  logoff that both happen inside one poll interval are seen as neither. Lower
  `--session-poll` if that matters.
- A VNC session that neither creates an OS logon nor keeps a TCP connection
  attributable to a known VNC server process cannot be detected.

---

## Development

```bash
uv venv && uv pip install -e .
uv run python -m unittest discover -s tests -v
```

The suite covers Windows event-log parsing, session diffing, classification on
both platforms, config handling and the generated service definitions, so the
platform-specific logic is testable without those platforms.
