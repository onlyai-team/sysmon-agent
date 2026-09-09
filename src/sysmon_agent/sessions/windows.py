"""Windows session tracking.

Sources, in order of authority:
  1. Security event log 4624 / 4634 / 4647  -> interactive, RDP and unlock logons
  2. TerminalServices-LocalSessionManager   -> RDP connect / disconnect / reconnect
  3. 'quser'                                -> baseline of sessions open before we started
  4. VNC connection probe                   -> VNC servers never create an OS logon
"""

from __future__ import annotations

import logging
import re
import time
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Set

from ..util import have, run
from .base import SessionTracker
from .model import (KIND_CONSOLE, KIND_GUI, KIND_RDP, KIND_REMOTE, KIND_UNKNOWN,
                    KIND_VNC, Session)
from .vnc import VNC_PROCESS_HINTS, probe_vnc_connections

LOG = logging.getLogger("sysmon.sessions.windows")

_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
_TS_CHANNEL = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"

_LOGON_EVENTS = (4624,)
_LOGOFF_EVENTS = (4634, 4647)
_SECURITY_EVENTS = _LOGON_EVENTS + _LOGOFF_EVENTS
_TS_EVENTS = (21, 22, 23, 24, 25)

# Logon types worth reporting as a human session.
_LOGON_TYPE_KIND = {
    "2": KIND_CONSOLE,      # interactive at the keyboard
    "7": KIND_CONSOLE,      # workstation unlock
    "10": KIND_RDP,         # RemoteInteractive
    "11": KIND_CONSOLE,     # cached interactive (domain account, offline)
    "12": KIND_RDP,         # cached remote interactive
    "13": KIND_CONSOLE,     # cached unlock
}
_LOGON_TYPE_NAME = {
    "2": "Interactive", "3": "Network", "4": "Batch", "5": "Service",
    "7": "Unlock", "8": "NetworkCleartext", "9": "NewCredentials",
    "10": "RemoteInteractive", "11": "CachedInteractive",
    "12": "CachedRemoteInteractive", "13": "CachedUnlock",
}
_TS_EVENT_NAME = {
    "21": "session.logon", "22": "shell.start", "23": "session.logoff",
    "24": "session.disconnected", "25": "session.reconnected",
}

_NOISE_ACCOUNTS = {
    "system", "local service", "network service", "anonymous logon",
    "dwm-1", "dwm-2", "dwm-3", "font driver host", "window manager",
}
_NOISE_PREFIXES = ("dwm-", "umfd-", "font driver host")

# Query window: how far back each poll looks. Generous overlap, deduped by record id.
_LOOKBACK_PADDING_MS = 30_000
_MAX_EVENTS_PER_POLL = 400


class WindowsSessionTracker(SessionTracker):
    source_name = "windows-eventlog"

    def __init__(self, poll_seconds: int = 5, on_event=None):
        super().__init__(poll_seconds, on_event)
        self._sessions_by_logon: Dict[str, Session] = {}
        self._seen_records: Set[str] = set()
        self._seen_order: List[str] = []
        self._rdp_addresses: Dict[str, str] = {}
        self._last_poll = time.time()
        self._seeded = False
        self._security_ok = True
        self._last_reconcile = 0.0

    def supported(self) -> bool:
        if not have("wevtutil"):
            LOG.error("wevtutil not found; Windows session tracking is unavailable.")
            return False
        return True

    # ------------------------------------------------------------------ poll

    def poll(self) -> List[Session]:
        if not self._seeded:
            self._seed_from_quser()
            self._seeded = True

        window_ms = int((time.time() - self._last_poll) * 1000) + _LOOKBACK_PADDING_MS
        self._last_poll = time.time()

        self._consume_terminal_services(window_ms)
        self._consume_security(window_ms)
        # quser is a subprocess and the baseline shrinks slowly; 30s is plenty.
        if time.time() - self._last_reconcile >= 30:
            self._last_reconcile = time.time()
            self._reconcile_baseline()

        sessions = list(self._sessions_by_logon.values())
        sessions.extend(probe_vnc_connections())
        return sessions

    # -------------------------------------------------------- security log

    def _consume_security(self, window_ms: int) -> None:
        events = self._query(
            "Security",
            "*[System[(%s) and TimeCreated[timediff(@SystemTime) <= %d]]]"
            % (" or ".join("EventID=%d" % e for e in _SECURITY_EVENTS), window_ms),
        )
        if events is None:
            if self._security_ok:
                LOG.error("Cannot read the Security event log. The agent must run as "
                          "LocalSystem or a member of Administrators.")
                self._security_ok = False
            return
        self._security_ok = True
        for event in events:
            record_id, event_id, when, data = event
            if not self._first_time(record_id):
                continue
            if event_id in _LOGON_EVENTS:
                self._handle_logon(data, when)
            else:
                self._handle_logoff(data)

    def _handle_logon(self, data: Dict[str, str], when: Optional[float]) -> None:
        logon_id = (data.get("TargetLogonId") or "").strip()
        user = data.get("TargetUserName", "")
        if not logon_id or logon_id == "0x0" or _is_noise(user):
            return
        logon_type = (data.get("LogonType") or "").strip()
        process = (data.get("ProcessName") or "") + " " + (data.get("LogonProcessName") or "")
        kind = _classify(logon_type, process, data.get("IpAddress", ""))
        if kind is None:
            return  # service / batch / plain network logon: not a human session

        address = _clean_address(data.get("IpAddress", ""))
        if not address and kind == KIND_RDP:
            address = self._rdp_addresses.get(user.lower(), "")

        domain = data.get("TargetDomainName", "")
        self._sessions_by_logon[logon_id] = Session(
            id="win:logon:%s" % logon_id,
            user=("%s\\%s" % (domain, user)) if domain and domain != "-" else user,
            kind=kind,
            remote_host=address,
            terminal=data.get("WorkstationName", ""),
            service=(data.get("LogonProcessName") or "").strip(),
            logon_type="%s (%s)" % (logon_type, _LOGON_TYPE_NAME.get(logon_type, "unknown")),
            started_at=when or time.time(),
            source=self.source_name,
            extra={
                "logon_id": logon_id,
                "process": (data.get("ProcessName") or "").strip(),
                "elevated": data.get("ElevatedToken", ""),
            },
        )

    def _handle_logoff(self, data: Dict[str, str]) -> None:
        logon_id = (data.get("TargetLogonId") or "").strip()
        self._sessions_by_logon.pop(logon_id, None)

    # ----------------------------------------------------- terminal services

    def _consume_terminal_services(self, window_ms: int) -> None:
        events = self._query(
            _TS_CHANNEL,
            "*[System[(%s) and TimeCreated[timediff(@SystemTime) <= %d]]]"
            % (" or ".join("EventID=%d" % e for e in _TS_EVENTS), window_ms),
        )
        if not events:
            return
        for record_id, event_id, when, data in events:
            if not self._first_time(record_id):
                continue
            user = data.get("User", "")
            address = _clean_address(data.get("Address", ""))
            if address and user:
                self._rdp_addresses[user.split("\\")[-1].lower()] = address
            name = _TS_EVENT_NAME.get(str(event_id), "session.event")
            if event_id in (24, 25):
                # Disconnect and reconnect are not logon or logoff, but they
                # matter: the RDP session stays alive with nobody attached.
                verb = name.split(".")[-1]
                session = Session(
                    id="win:ts:%s" % data.get("SessionID", "?"),
                    user=user,
                    kind=KIND_RDP,
                    remote_host=address,
                    source="terminal-services",
                    started_at=when,
                )
                self.emit_event(
                    "rdp.%s" % verb,
                    session,
                    "RDP %s: %s from %s (terminal session %s)"
                    % (verb, user or "?", address or "unknown",
                       data.get("SessionID", "?")),
                )

    # ---------------------------------------------------------- quser baseline

    def _seed_from_quser(self) -> None:
        for session in _quser_sessions():
            self._sessions_by_logon.setdefault("baseline:%s" % session.extra["win_session_id"],
                                               session)

    def _reconcile_baseline(self) -> None:
        """Drop baseline entries once quser stops reporting them, or once the
        Security log has produced a real session for the same user."""
        baseline_keys = [k for k in self._sessions_by_logon if k.startswith("baseline:")]
        if not baseline_keys:
            return
        live_ids = {s.extra["win_session_id"] for s in _quser_sessions()}
        event_users = {
            s.user.split("\\")[-1].lower()
            for key, s in self._sessions_by_logon.items() if not key.startswith("baseline:")
        }
        for key in baseline_keys:
            session = self._sessions_by_logon[key]
            gone = session.extra["win_session_id"] not in live_ids
            superseded = session.user.split("\\")[-1].lower() in event_users
            if gone or superseded:
                del self._sessions_by_logon[key]

    # ------------------------------------------------------------- wevtutil

    def _query(self, channel: str, xpath: str):
        result = run([
            "wevtutil", "qe", channel, "/q:%s" % xpath, "/f:xml", "/rd:true",
            "/c:%d" % _MAX_EVENTS_PER_POLL,
        ], timeout=45)
        if result.returncode != 0:
            LOG.debug("wevtutil %s failed: %s", channel, result.stderr.strip()[:300])
            return None
        return _parse_events(result.stdout)

    def _first_time(self, record_id: str) -> bool:
        """Deduplicate: consecutive polls overlap on purpose."""
        if record_id in self._seen_records:
            return False
        self._seen_records.add(record_id)
        self._seen_order.append(record_id)
        if len(self._seen_order) > 5000:
            for old in self._seen_order[:2000]:
                self._seen_records.discard(old)
            del self._seen_order[:2000]
        return True


# --------------------------------------------------------------------- parsing


def _parse_events(xml_text: str):
    """wevtutil emits a bare sequence of <Event> elements; wrap them to parse."""
    xml_text = xml_text.strip()
    if not xml_text:
        return []
    try:
        root = ET.fromstring("<Events>%s</Events>" % xml_text)
    except ET.ParseError as exc:
        LOG.debug("Event XML parse error: %s", exc)
        return []

    events = []
    for element in root:
        system = element.find("%sSystem" % _NS)
        if system is None:
            continue
        event_id_el = system.find("%sEventID" % _NS)
        record_el = system.find("%sEventRecordID" % _NS)
        time_el = system.find("%sTimeCreated" % _NS)
        try:
            event_id = int((event_id_el.text or "0").strip()) if event_id_el is not None else 0
        except ValueError:
            continue
        record_id = "%s:%s" % (
            _channel_of(system), record_el.text if record_el is not None else "?")
        when = _parse_system_time(
            time_el.get("SystemTime") if time_el is not None else None)
        events.append((record_id, event_id, when, _event_data(element)))
    events.reverse()  # /rd:true gives newest first; replay in chronological order
    return events


def _channel_of(system) -> str:
    channel_el = system.find("%sChannel" % _NS)
    return (channel_el.text or "?") if channel_el is not None else "?"


def _event_data(element) -> Dict[str, str]:
    data: Dict[str, str] = {}
    event_data = element.find("%sEventData" % _NS)
    if event_data is not None:
        for item in event_data.findall("%sData" % _NS):
            name = item.get("Name")
            if name:
                data[name] = (item.text or "").strip()
    user_data = element.find("%sUserData" % _NS)
    if user_data is not None:
        for child in user_data:
            for item in child:
                tag = item.tag.split("}")[-1]
                data[tag] = (item.text or "").strip()
    return data


_SYSTEM_TIME_RE = re.compile(r"(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})")


def _parse_system_time(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    match = _SYSTEM_TIME_RE.match(value)
    if not match:
        return None
    try:
        parsed = time.strptime("%s %s" % match.groups(), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    import calendar

    return calendar.timegm(parsed)  # SystemTime is UTC


# -------------------------------------------------------------- classification


def _classify(logon_type: str, process_hint: str, address: str) -> Optional[str]:
    hint = (process_hint or "").lower()
    if any(marker in hint for marker in VNC_PROCESS_HINTS):
        return KIND_VNC
    kind = _LOGON_TYPE_KIND.get(logon_type)
    if kind is None:
        return None
    if kind == KIND_CONSOLE and _clean_address(address):
        # An "interactive" logon carrying a remote address is remote control software.
        return KIND_REMOTE
    return kind


def _is_noise(user: str) -> bool:
    lowered = (user or "").strip().lower()
    if not lowered or lowered == "-":
        return True
    if lowered.endswith("$"):  # machine account
        return True
    if lowered in _NOISE_ACCOUNTS:
        return True
    return any(lowered.startswith(prefix) for prefix in _NOISE_PREFIXES)


def _clean_address(address: str) -> str:
    address = (address or "").strip()
    if address in ("", "-", "::1", "127.0.0.1", "0.0.0.0"):
        return ""
    return address


# ------------------------------------------------------------------- quser


_QUSER_RE = re.compile(
    r"^\s*>?(?P<user>\S+)\s+(?P<sessionname>\S*)\s+(?P<id>\d+)\s+(?P<state>\S+)\s+"
    r"(?P<idle>\S+)\s+(?P<logon>.+?)\s*$"
)


def _quser_sessions() -> List[Session]:
    if not have("quser"):
        return []
    result = run(["quser"], timeout=20)
    if result.returncode != 0 or not result.stdout.strip():
        return []
    sessions = []
    for line in result.stdout.splitlines()[1:]:
        match = _QUSER_RE.match(line)
        if not match:
            continue
        fields = match.groupdict()
        session_name = (fields["sessionname"] or "").lower()
        if session_name.startswith("rdp"):
            kind = KIND_RDP
        elif session_name == "console":
            kind = KIND_VNC if _vnc_on_console() else KIND_CONSOLE
        elif session_name in ("", "-"):
            kind = KIND_UNKNOWN
        else:
            kind = KIND_GUI
        sessions.append(Session(
            id="win:session:%s" % fields["id"],
            user=fields["user"],
            kind=kind,
            terminal=fields["sessionname"],
            source="quser",
            extra={"win_session_id": fields["id"],
                   "state": fields["state"],
                   "logon_time": fields["logon"].strip()},
        ))
    return sessions


_console_vnc_cache = {"at": 0.0, "value": False}


def _vnc_on_console() -> bool:
    from .vnc import vnc_server_present

    now = time.time()
    if now - _console_vnc_cache["at"] < 30:
        return bool(_console_vnc_cache["value"])
    value = vnc_server_present() and bool(probe_vnc_connections())
    _console_vnc_cache.update({"at": now, "value": value})
    return value


def build_tracker(poll_seconds: int, on_event=None) -> SessionTracker:
    return WindowsSessionTracker(poll_seconds, on_event)
