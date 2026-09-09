"""Service-manager abstraction: systemd on Linux, SCM / Task Scheduler on Windows."""

from __future__ import annotations

from typing import List

from ..paths import IS_WINDOWS
from ..util import AgentError

if IS_WINDOWS:
    from . import windows as backend
else:
    from . import systemd as backend


def available() -> bool:
    return backend.available()


def require_available() -> None:
    if not available():
        raise AgentError(
            "No supported service manager found. sysmon-agent installs as a "
            "systemd unit on Linux or as a Windows service; this machine is neither."
        )


def install() -> None:
    require_available()
    backend.install()


def remove() -> List[str]:
    return backend.remove()


def installed() -> bool:
    return backend.installed()


def status() -> str:
    return backend.status()


def detail() -> str:
    return backend.detail()


def start() -> None:
    require_available()
    backend.start()


def stop() -> None:
    backend.stop()


def restart() -> None:
    require_available()
    backend.restart()
