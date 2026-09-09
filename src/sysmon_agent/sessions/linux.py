"""Linux session tracking: systemd-logind first, utmp as a fallback."""

from __future__ import annotations

import json
import logging
import re
from typing import Dict, List, Optional

import psutil

from ..util import have, run
from .base import SessionTracker
from .vnc import VNC_PROCESS_HINTS, vnc_server_present
from .model import (KIND_CONSOLE, KIND_GUI, KIND_REMOTE, KIND_RDP, KIND_SSH,
                    KIND_UNKNOWN, KIND_VNC, Session)

LOG = logging.getLogger("sysmon.sessions.linux")

_RDP_PROCESS_HINTS = ("xrdp", "rdp", "freerdp", "grdctl", "gnome-remote-desktop")

_SESSION_PROPERTIES = (
    "Id", "User", "Name", "Remote", "RemoteHost", "RemoteUser", "Service", "Type",
    "Class", "TTY", "Display", "Leader", "Timestamp", "Active", "State", "Seat",
)


class LogindSessionTracker(SessionTracker):
    """Reads systemd-logind, which knows about ssh, tty, x11/wayland and xrdp seats."""

    source_name = "systemd-logind"

    def supported(self) -> bool:
        if not have("loginctl"):
            return False
        result = run(["loginctl", "list-sessions", "--no-legend"])
        return result.returncode == 0

    def poll(self) -> List[Session]:
        sessions = []
        for session_id in self._session_ids():
            props = self._show_session(session_id)
            if not props:
                continue
            sessions.append(self._to_session(session_id, props))
        return sessions

    # ------------------------------------------------------------- loginctl

    def _session_ids(self) -> List[str]:
        result = run(["loginctl", "list-sessions", "--output=json"])
        if result.returncode == 0 and result.stdout.strip().startswith("["):
            try:
                return [str(entry["session"]) for entry in json.loads(result.stdout)
                        if entry.get("session")]
            except (ValueError, KeyError, TypeError):
                pass
        result = run(["loginctl", "list-sessions", "--no-legend"])
        if result.returncode != 0:
            raise RuntimeError("loginctl list-sessions failed: %s" % result.stderr.strip())
        ids = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if parts:
                ids.append(parts[0])
        return ids

    def _show_session(self, session_id: str) -> Dict[str, str]:
        args = ["loginctl", "show-session", session_id]
        for prop in _SESSION_PROPERTIES:
            args.extend(["-p", prop])
        result = run(args)
        if result.returncode != 0:
            return {}
        props = {}
        for line in result.stdout.splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                props[key.strip()] = value.strip()
        return props

    # -------------------------------------------------------- classification

    def _to_session(self, session_id: str, props: Dict[str, str]) -> Session:
        leader = _to_int(props.get("Leader"))
        leader_name = _process_name(leader)
        kind = _classify(props, leader_name)
        started = _process_start_time(leader) or _parse_timestamp(props.get("Timestamp"))
        return Session(
            id="logind:%s" % session_id,
            user=props.get("Name") or props.get("User") or "",
            kind=kind,
            remote_host=props.get("RemoteHost", ""),
            terminal=props.get("TTY", ""),
            display=props.get("Display", ""),
            service=props.get("Service", ""),
            pid=leader,
            started_at=started,
            source=self.source_name,
            extra={
                "class": props.get("Class", ""),
                "type": props.get("Type", ""),
                "seat": props.get("Seat", ""),
                "leader_process": leader_name or "",
                "remote": props.get("Remote", "no"),
            },
        )


def _classify(props: Dict[str, str], leader_name: Optional[str]) -> str:
    service = (props.get("Service") or "").lower()
    session_type = (props.get("Type") or "").lower()
    remote = (props.get("Remote") or "no").lower() == "yes"
    haystack = " ".join(filter(None, [service, leader_name or ""])).lower()

    if any(hint in haystack for hint in VNC_PROCESS_HINTS):
        return KIND_VNC
    if any(hint in haystack for hint in _RDP_PROCESS_HINTS):
        return KIND_RDP
    if "sshd" in service or (remote and session_type in ("tty", "unspecified", "")):
        return KIND_SSH
    if session_type in ("x11", "wayland", "mir"):
        return KIND_VNC if _vnc_server_running() else KIND_GUI
    if session_type == "tty":
        return KIND_CONSOLE
    if remote:
        return KIND_REMOTE
    return KIND_UNKNOWN


class UtmpSessionTracker(SessionTracker):
    """Fallback for systems without systemd: read utmp through psutil."""

    source_name = "utmp"

    def supported(self) -> bool:
        try:
            psutil.users()
            return True
        except Exception:
            return False

    def poll(self) -> List[Session]:
        sessions = []
        for user in psutil.users():
            terminal = user.terminal or ""
            host = (user.host or "").strip()
            session_id = "utmp:%s:%s:%s:%d" % (user.name, terminal, host, int(user.started))
            remote = "" if host.lower() in _LOCAL_HOSTS or host.startswith(":") else host
            sessions.append(Session(
                id=session_id,
                user=user.name,
                kind=_classify_utmp(terminal, host),
                remote_host=remote,
                terminal=terminal,
                display=host if host.startswith(":") else "",
                pid=getattr(user, "pid", None),
                started_at=user.started,
                source=self.source_name,
            ))
        return sessions


_LOCAL_HOSTS = ("", "localhost", "localhost.localdomain", "127.0.0.1", "::1", "-")


def _classify_utmp(terminal: str, host: str) -> str:
    host = (host or "").strip()
    if host.lower() in _LOCAL_HOSTS:
        host = ""
    if host.startswith(":"):
        return KIND_VNC if _vnc_server_running() else KIND_GUI
    if host:
        if terminal.startswith("pts"):
            return KIND_SSH
        return KIND_REMOTE
    if terminal.startswith(("tty", "console")):
        return KIND_CONSOLE
    return KIND_UNKNOWN


# ------------------------------------------------------------------- helpers

_vnc_cache = {"at": 0.0, "value": False}


def _vnc_server_running() -> bool:
    """Cheap cached check so an X11 seat driven by a VNC server is labelled vnc."""
    import time

    now = time.time()
    if now - _vnc_cache["at"] >= 30:
        _vnc_cache.update({"at": now, "value": vnc_server_present()})
    return bool(_vnc_cache["value"])


def _process_name(pid: Optional[int]) -> Optional[str]:
    if not pid:
        return None
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        try:  # the login shell's parent tells us more than the shell itself
            parent = proc.parent()
            if parent is not None:
                name = "%s %s" % (parent.name(), name)
        except Exception:
            pass
        return name
    except Exception:
        return None


def _process_start_time(pid: Optional[int]) -> Optional[float]:
    """The leader process creation time is a far more reliable clock than loginctl text."""
    if not pid:
        return None
    try:
        return psutil.Process(pid).create_time()
    except Exception:
        return None


def _to_int(value: Optional[str]) -> Optional[int]:
    try:
        return int(value) if value else None
    except (TypeError, ValueError):
        return None


_TIMESTAMP_RE = re.compile(r"^\d+$")


def _parse_timestamp(value: Optional[str]) -> Optional[float]:
    """loginctl reports Timestamp as a human string; TimestampMonotonic is useless here."""
    if not value:
        return None
    value = value.strip()
    if _TIMESTAMP_RE.match(value):
        return int(value) / 1e6
    import time as _time

    # "Tue 2026-09-09 10:04:11 +07" -> drop the trailing zone token, parse local time.
    tokens = value.split()
    if len(tokens) >= 3:
        candidate = " ".join(tokens[:3])
        try:
            return _time.mktime(_time.strptime(candidate, "%a %Y-%m-%d %H:%M:%S"))
        except (ValueError, OverflowError):
            pass
    return None


def build_tracker(poll_seconds: int, on_event=None) -> SessionTracker:
    logind = LogindSessionTracker(poll_seconds, on_event)
    if logind.supported():
        LOG.info("Using systemd-logind for session tracking")
        return logind
    LOG.info("systemd-logind unavailable; falling back to utmp")
    return UtmpSessionTracker(poll_seconds, on_event)
