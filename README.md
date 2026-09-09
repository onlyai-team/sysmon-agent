# sysmon-agent

A single-binary-style CLI that installs a background service on **Ubuntu** and
**Windows**. The service samples CPU, memory, disk and network, records every
login and logout session (SSH, RDP, VNC and local console), starts at boot,
restarts after a crash, and pushes all three OTLP signals (metrics, logs and
traces) to an OTLP/HTTP collector over HTTP.

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

Other install flags: `--log-format json|text` (json is the default),
`--no-traces` to export metrics and logs only, `--trace-polls` to span each
session poll while debugging,
`--no-per-cpu` to report host CPU totals instead of one series per core,
`--environment`, `--attribute KEY=VALUE`, `--ca-bundle`, `--no-verify-tls`.

---

## Updating

An upgrade keeps the configuration; it never re-asks for the endpoint or the
token. Copy the new source over the old folder first, then:

```bash
sudo ./scripts/install-ubuntu.sh --update
```

```powershell
.\scripts\install-windows.ps1 -Update
```

Both stop the running agent before touching the virtual environment (on Windows
its files stay locked while the service runs), reuse the existing venv, reinstall
the package, re-register the service and start it again. The script prints the
new version and the service status when it finishes.

To change a setting rather than the code, re-run `install` without `--update`
and answer the prompts; the stored values are offered as the defaults.

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

Names and attributes follow the OpenTelemetry host metrics conventions, the same
set the collector's `hostmetrics` receiver emits, so standard dashboards work
without remapping.

| Instrument | Unit | Attributes |
| --- | --- | --- |
| `system.cpu.time` | s | `cpu`, `state` |
| `system.cpu.utilization` | 1 | `cpu`, `state` |
| `system.cpu.logical.count` | {cpu} | — |
| `system.cpu.load_average.1m` / `.5m` / `.15m` | {thread} | — |
| `system.memory.usage` | By | `state` |
| `system.memory.utilization` | 1 | — |
| `system.paging.usage` | By | `state` |
| `system.paging.utilization` | 1 | — |
| `system.paging.operations` | {operation} | `direction`, `type` |
| `system.filesystem.usage` | By | `device`, `mountpoint`, `type`, `mode`, `state` |
| `system.filesystem.utilization` | 1 | `device`, `mountpoint`, `type`, `mode` |
| `system.filesystem.inodes.usage` | {inode} | `device`, `mountpoint`, `type`, `mode`, `state` |
| `system.disk.io` | By | `device`, `direction` |
| `system.disk.operations` | {operation} | `device`, `direction` |
| `system.disk.operation_time` | s | `device`, `direction` |
| `system.disk.io_time` | s | `device` |
| `system.disk.merged` | {operation} | `device`, `direction` |
| `system.network.io` | By | `device`, `direction` |
| `system.network.packets` | {packet} | `device`, `direction` |
| `system.network.errors` | {error} | `device`, `direction` |
| `system.network.dropped` | {packet} | `device`, `direction` |
| `system.network.connections` | {connection} | `protocol`, `state` |
| `system.processes.count` | {process} | `status` |
| `system.processes.created` | {process} | — |
| `system.uptime` | s | — |
| `system.sessions.active` | {session} | `session.kind` |
| `system.sessions.events` | {event} | `event.name`, `session.kind`, `session.source` |

`state` values on `system.cpu.time` follow the convention: `user`, `system`,
`idle`, `nice`, `wait`, `interrupt`, `softirq`, `steal`.

Some instruments have no data source on every platform and simply report
nothing there: `system.disk.io_time`, `system.disk.merged`,
`system.paging.operations` and `system.processes.created` are Linux only, and
`system.filesystem.inodes.usage` does not exist on Windows.

CPU metrics carry one series per logical core. On a machine with many cores that
multiplies cardinality, so `--no-per-cpu` drops the `cpu` attribute and reports
host totals instead.

Pseudo filesystems (tmpfs, squashfs, overlay, /snap, …) are filtered out.

### Session events (OTLP logs)

Every event is exported twice over: as a JSON object in the log record body, and
as OTel attributes on the same record. Use whichever your pipeline reads.

```json
{
  "time": "2026-09-09T09:41:12.204Z",
  "level": "INFO",
  "logger": "sysmon.events",
  "message": "Login: ssh alice from 203.0.113.5 (session logind:47)",
  "event.name": "session.start",
  "session.id": "logind:47",
  "session.kind": "ssh",
  "session.source": "systemd-logind",
  "user.name": "alice",
  "enduser.id": "alice",
  "client.address": "203.0.113.5",
  "session.terminal": "pts/0",
  "process.pid": 40122,
  "session.started_at": "2026-09-09T09:41:12Z"
}
```

A logout carries `session.ended_at` and `session.duration_seconds` as well.

`event.name` is what you route on:

| `event.name` | Meaning |
| --- | --- |
| `session.start` | A login |
| `session.end` | A logout, with the duration |
| `session.observed` | A session that was already open when the agent started |
| `rdp.disconnected` / `rdp.reconnected` | The RDP session stayed alive but the client detached or came back |
| `agent.start` / `agent.stop` | The agent itself |

`session.kind` is one of `ssh`, `rdp`, `vnc`, `console`, `gui`, `remote`,
`unknown`.

To alert on remote logins, match `event.name = session.start` and
`session.kind` in (`ssh`, `rdp`, `vnc`), then read `user.name` and
`client.address` for the notification text.

Pass `--log-format text` at install time if you would rather have prose lines;
the body then reads `Login: ssh alice from 203.0.113.5 (session logind:47)` and
the attributes are unchanged.

### Traces (OTLP spans)

Each login opens a span that closes at logout, so a trace backend shows one span
per session with its real duration. The span name is `session <kind>`, for
example `session ssh`, which keeps cardinality low; the user and client address
are attributes, carrying the same keys the log record uses.

Session logs are emitted inside their span, so every `session.start` and
`session.end` record carries the trace id and span id. A log line in the alert
links straight to the session span.

Two things follow from spans only being exported when they end:

- A login shows up in traces at **logout**, not at login. Alert on the logs, use
  the traces to see how long sessions ran and which hosts they came from.
- Sessions still open when the agent stops are ended with
  `session.open_at_agent_stop = true` and carry no duration, since that end time
  is a shutdown and not a logout.

`--trace-polls` adds a `session.poll` span per poll, with a child `exec` span for
every `loginctl`, `wevtutil` or `quser` call and the exit code. That is a
debugging tool for a machine where session detection misbehaves; it is off by
default because it produces a span every few seconds. `--no-traces` turns the
signal off entirely.

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

The log file holds the same JSON records that go to the collector, one object
per line, so `tail -f` piped into `jq` is a working local notifier. It rotates
at 10 MB, keeping five generations. On Ubuntu the same
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
