"""Polling loop shared by the platform trackers."""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Dict, List, Optional

from .model import EVENT_END, EVENT_OBSERVED, EVENT_START, Session

LOG = logging.getLogger("sysmon.sessions")
EVENTS = logging.getLogger("sysmon.events")


class SessionTracker(threading.Thread):
    """Diffs the platform session list on a timer and emits start/end events."""

    source_name = "generic"

    def __init__(self, poll_seconds: int = 5, on_event: Optional[Callable] = None):
        super().__init__(name="session-tracker", daemon=True)
        self.poll_seconds = max(1, int(poll_seconds))
        self.on_event = on_event
        # NB: not '_stop' - threading.Thread uses that name internally.
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._sessions: Dict[str, Session] = {}
        self._failures = 0

    # ------------------------------------------------------ platform hook

    def poll(self) -> List[Session]:
        """Return the sessions currently open. Implemented per platform."""
        raise NotImplementedError

    def supported(self) -> bool:
        return True

    # ------------------------------------------------------------ public

    def active_counts(self) -> Dict[str, int]:
        with self._lock:
            counts: Dict[str, int] = {}
            for session in self._sessions.values():
                counts[session.kind] = counts.get(session.kind, 0) + 1
            return counts

    def active_sessions(self) -> List[Session]:
        with self._lock:
            return list(self._sessions.values())

    def stop(self) -> None:
        self._stop_event.set()

    # ------------------------------------------------------------- loop

    def run(self) -> None:
        if not self.supported():
            LOG.warning("Session tracking is not available on this system; disabled.")
            return
        self._prime()
        while not self._stop_event.wait(self.poll_seconds):
            try:
                self._tick()
                self._failures = 0
            except Exception as exc:
                self._failures += 1
                level = logging.ERROR if self._failures in (1, 10) else logging.DEBUG
                LOG.log(level, "Session poll failed (%d in a row): %s", self._failures, exc)

    def _prime(self) -> None:
        """Record what is already logged in, without claiming those are new logins."""
        try:
            current = {s.id: s for s in self.poll()}
        except Exception as exc:
            LOG.error("Initial session poll failed: %s", exc)
            return
        with self._lock:
            self._sessions = current
        for session in current.values():
            self._emit(EVENT_OBSERVED, session)

    def _tick(self) -> None:
        current = {s.id: s for s in self.poll()}
        now = time.time()
        with self._lock:
            previous = self._sessions
            self._sessions = current
        for session_id, session in current.items():
            if session_id not in previous:
                self._emit(EVENT_START, session)
        for session_id, session in previous.items():
            if session_id not in current:
                self._emit(EVENT_END, session, ended_at=now)

    def _emit(self, event: str, session: Session, ended_at: Optional[float] = None) -> None:
        if not session.source:
            session.source = self.source_name
        attributes = session.attributes(event, ended_at=ended_at)
        verb = {EVENT_START: "Login", EVENT_END: "Logout",
                EVENT_OBSERVED: "Existing session"}[event]
        message = "%s: %s" % (verb, session.summary())
        EVENTS.info(message, extra=attributes)
        if self.on_event is not None:
            try:
                self.on_event(event, session, attributes)
            except Exception as exc:
                LOG.debug("Session event hook failed: %s", exc)
