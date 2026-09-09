"""systemd unit management for Ubuntu / any systemd Linux."""

from __future__ import annotations

import logging
import shlex
from pathlib import Path
from typing import List

from .. import SERVICE_DESCRIPTION, SERVICE_NAME
from ..paths import log_dir, state_dir
from ..util import AgentError, agent_command, have, run

LOG = logging.getLogger("sysmon.service")

UNIT_PATH = Path("/etc/systemd/system/%s.service" % SERVICE_NAME)

UNIT_TEMPLATE = """\
[Unit]
Description={description}
Documentation=man:{name}(8)
After=network-online.target systemd-logind.service
Wants=network-online.target

[Service]
Type=simple
ExecStart={exec_start}
Restart=always
RestartSec=5
StartLimitIntervalSec=0
User=root
Group=root
WorkingDirectory=/
StandardOutput=journal
StandardError=journal
SyslogIdentifier={name}
KillSignal=SIGTERM
TimeoutStopSec=20
LogsDirectory={name}
StateDirectory={name}

[Install]
WantedBy=multi-user.target
"""


def _systemctl(*args: str, check: bool = False):
    result = run(["systemctl"] + list(args))
    if check and result.returncode != 0:
        raise AgentError("systemctl %s failed: %s"
                         % (" ".join(args), (result.stderr or result.stdout).strip()))
    return result


def available() -> bool:
    return have("systemctl") and Path("/run/systemd/system").exists()


def install() -> None:
    if not available():
        raise AgentError(
            "systemd was not detected. This installer supports systemd Linux "
            "(Ubuntu 16.04+) and Windows."
        )
    exec_start = " ".join(shlex.quote(part) for part in agent_command("run"))
    unit = UNIT_TEMPLATE.format(
        description=SERVICE_DESCRIPTION, name=SERVICE_NAME, exec_start=exec_start
    )
    for directory in (state_dir(), log_dir()):
        directory.mkdir(parents=True, exist_ok=True)
    UNIT_PATH.write_text(unit, encoding="utf-8")
    UNIT_PATH.chmod(0o644)
    LOG.info("Wrote %s", UNIT_PATH)

    _systemctl("daemon-reload", check=True)
    _systemctl("enable", SERVICE_NAME, check=True)
    _systemctl("restart", SERVICE_NAME, check=True)


def remove() -> List[str]:
    steps = []
    if available():
        _systemctl("stop", SERVICE_NAME)
        steps.append("stopped service")
        _systemctl("disable", SERVICE_NAME)
        steps.append("disabled service")
    if UNIT_PATH.exists():
        UNIT_PATH.unlink()
        steps.append("removed %s" % UNIT_PATH)
    if available():
        _systemctl("daemon-reload")
        _systemctl("reset-failed", SERVICE_NAME)
    return steps


def installed() -> bool:
    return UNIT_PATH.exists()


def status() -> str:
    if not installed():
        return "not installed"
    active = _systemctl("is-active", SERVICE_NAME).stdout.strip() or "unknown"
    enabled = _systemctl("is-enabled", SERVICE_NAME).stdout.strip() or "unknown"
    return "%s (boot: %s)" % (active, enabled)


def detail() -> str:
    return _systemctl("status", SERVICE_NAME, "--no-pager", "-l").stdout


def restart() -> None:
    _systemctl("restart", SERVICE_NAME, check=True)


def stop() -> None:
    _systemctl("stop", SERVICE_NAME, check=True)


def start() -> None:
    _systemctl("start", SERVICE_NAME, check=True)


def journal_command(lines: int, follow: bool) -> List[str]:
    cmd = ["journalctl", "-u", SERVICE_NAME, "-n", str(lines), "--no-pager"]
    if follow:
        cmd.append("-f")
    return cmd
