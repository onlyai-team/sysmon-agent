"""Session record and event shapes shared by every platform tracker."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

# Session kinds we classify into.
KIND_SSH = "ssh"
KIND_RDP = "rdp"
KIND_VNC = "vnc"
KIND_CONSOLE = "console"
KIND_GUI = "gui"
KIND_REMOTE = "remote"
KIND_UNKNOWN = "unknown"

EVENT_START = "session.start"
EVENT_END = "session.end"
EVENT_OBSERVED = "session.observed"


@dataclass
class Session:
    """One login session, as seen by the platform tracker."""

    id: str
    user: str = ""
    kind: str = KIND_UNKNOWN
    remote_host: str = ""
    remote_port: str = ""
    terminal: str = ""
    display: str = ""
    service: str = ""
    logon_type: str = ""
    pid: Optional[int] = None
    started_at: Optional[float] = None
    source: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def attributes(self, event: str, ended_at: Optional[float] = None) -> Dict[str, Any]:
        attrs: Dict[str, Any] = {
            "event.name": event,
            "session.id": self.id,
            "session.kind": self.kind,
            "session.source": self.source,
            "enduser.id": self.user,
            "user.name": self.user,
        }
        if self.remote_host:
            attrs["client.address"] = self.remote_host
        if self.remote_port:
            attrs["client.port"] = self.remote_port
        if self.terminal:
            attrs["session.terminal"] = self.terminal
        if self.display:
            attrs["session.display"] = self.display
        if self.service:
            attrs["session.service"] = self.service
        if self.logon_type:
            attrs["session.logon_type"] = self.logon_type
        if self.pid:
            attrs["process.pid"] = int(self.pid)
        if self.started_at:
            attrs["session.started_at"] = iso(self.started_at)
        if ended_at:
            attrs["session.ended_at"] = iso(ended_at)
            if self.started_at:
                attrs["session.duration_seconds"] = round(ended_at - self.started_at, 3)
        for key, value in (self.extra or {}).items():
            if value in ("", None):
                continue
            attrs["session.%s" % key] = value if isinstance(
                value, (str, int, float, bool)) else str(value)
        return attrs

    def summary(self) -> str:
        where = self.remote_host or self.terminal or self.display or "local"
        return "%s %s from %s (session %s)" % (
            self.kind, self.user or "?", where, self.id)


def iso(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(epoch)) + "Z"
