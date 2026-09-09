"""Detect live VNC connections.

VNC servers usually authenticate on their own and never create an OS login
session, so neither logind nor the Windows Security log sees them. This probe
looks for established TCP connections owned by a VNC server process and reports
each one as a session, which is the only way those remote logins become visible.
"""

from __future__ import annotations

import logging
import time
from typing import List

import psutil

from .model import KIND_VNC, Session

LOG = logging.getLogger("sysmon.sessions.vnc")

VNC_PROCESS_HINTS = (
    "vnc", "winvnc", "tvnserver", "x11vnc", "xvnc", "vncserver",
    "vncserverui", "vino-server", "krfb", "vncagent",
)
_LOOPBACK = ("127.0.0.1", "::1", "localhost")


def _connections(proc: psutil.Process):
    getter = getattr(proc, "net_connections", None) or getattr(proc, "connections")
    return getter(kind="inet")


def probe_vnc_connections() -> List[Session]:
    sessions: List[Session] = []
    try:
        processes = list(psutil.process_iter(["name", "username", "create_time"]))
    except Exception as exc:
        LOG.debug("process_iter failed: %s", exc)
        return sessions

    for proc in processes:
        name = (proc.info.get("name") or "").lower()
        if not any(hint in name for hint in VNC_PROCESS_HINTS):
            continue
        try:
            connections = _connections(proc)
        except (psutil.AccessDenied, psutil.NoSuchProcess, PermissionError, OSError):
            continue
        for conn in connections:
            if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
                continue
            remote_ip = conn.raddr[0]
            if remote_ip in _LOOPBACK:
                continue
            sessions.append(Session(
                id="vnc:%s:%s:%s" % (proc.pid, remote_ip, conn.raddr[1]),
                user=proc.info.get("username") or "",
                kind=KIND_VNC,
                remote_host=remote_ip,
                remote_port=str(conn.raddr[1]),
                service=proc.info.get("name") or "",
                pid=proc.pid,
                started_at=proc.info.get("create_time") or time.time(),
                source="vnc-connection-probe",
                extra={"local_port": str(conn.laddr[1]) if conn.laddr else ""},
            ))
    return sessions


def vnc_server_present() -> bool:
    try:
        for proc in psutil.process_iter(["name"]):
            if any(hint in (proc.info.get("name") or "").lower() for hint in VNC_PROCESS_HINTS):
                return True
    except Exception:
        pass
    return False
