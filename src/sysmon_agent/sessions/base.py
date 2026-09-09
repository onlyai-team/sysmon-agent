"""Polling loop shared by the platform trackers, plus session spans."""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from opentelemetry import trace as trace_api
from opentelemetry.trace import Status, StatusCode

from .model import EVENT_END, EVENT_OBSERVED, EVENT_START, Session

LOG = logging.getLogger("sysmon.sessions")
EVENTS = logging.getLogger("sysmon.events")

# Attributes that describe the event rather than the session; a span covers the
# whole session, so these would be misleading on it.
_EVENT_ONLY_ATTRIBUTES = ("event.name",)


class SessionTracker(threading.Thread):
    """Diffs the platform session list on a timer and emits start/end events.

    Each login also opens a span that closes at logout, so a trace backend shows
    one span per session with its real duration. A span is only exported once it
    ends, which is why the logs, not the traces, are what you alert on.
    """

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
        self._tracer = None
        self._trace_polls = False
        self._spans: Dict[str, Any] = {}

    # ------------------------------------------------------ platform hook

    def poll(self) -> List[Session]:
        """Return the sessions currently open. Implemented per platform."""
        raise NotImplementedError

    def supported(self) -> bool:
        return True

    # ------------------------------------------------------------ public

    def set_tracing(self, tracer, trace_polls: bool = False) -> None:
        """Called by the agent once telemetry is up; a None tracer disables spans."""
        self._tracer = tracer
        self._trace_polls = bool(trace_polls) and tracer is not None

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
        try:
            while not self._stop_event.wait(self.poll_seconds):
                try:
                    self._tick()
                    self._failures = 0
                except Exception as exc:
                    self._failures += 1
                    level = logging.ERROR if self._failures in (1, 10) else logging.DEBUG
                    LOG.log(level, "Session poll failed (%d in a row): %s",
                            self._failures, exc)
        finally:
            self._close_open_spans()

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
        if not self._trace_polls:
            self._diff()
            return
        with self._tracer.start_as_current_span("session.poll") as span:
            span.set_attribute("session.source", self.source_name)
            try:
                started, ended, total = self._diff()
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR, str(exc)))
                raise
            span.set_attribute("session.active_count", total)
            span.set_attribute("session.started_count", started)
            span.set_attribute("session.ended_count", ended)

    def _diff(self):
        current = {s.id: s for s in self.poll()}
        now = time.time()
        with self._lock:
            previous = self._sessions
            self._sessions = current
        started = ended = 0
        for session_id, session in current.items():
            if session_id not in previous:
                self._emit(EVENT_START, session)
                started += 1
        for session_id, session in previous.items():
            if session_id not in current:
                self._emit(EVENT_END, session, ended_at=now)
                ended += 1
        return started, ended, len(current)

    # ------------------------------------------------------------ emission

    def _emit(self, event: str, session: Session, ended_at: Optional[float] = None) -> None:
        if not session.source:
            session.source = self.source_name
        attributes = session.attributes(event, ended_at=ended_at)
        verb = {EVENT_START: "Login", EVENT_END: "Logout",
                EVENT_OBSERVED: "Existing session"}.get(event, "Session event")
        message = "%s: %s" % (verb, session.summary())

        if event == EVENT_END:
            span = self._spans.pop(session.id, None)
        else:
            span = self._open_span(session, attributes)

        # Emitting inside the span's context stamps trace and span ids onto the
        # log record, so a log line links back to its session span.
        if span is not None:
            with trace_api.use_span(span, end_on_exit=False):
                EVENTS.info(message, extra=attributes)
        else:
            EVENTS.info(message, extra=attributes)

        if span is not None and event == EVENT_END:
            self._close_span(span, attributes, ended_at)

        if self.on_event is not None:
            try:
                self.on_event(event, session, attributes)
            except Exception as exc:
                LOG.debug("Session event hook failed: %s", exc)

    def emit_event(self, event_name: str, session: Session, message: str,
                   extra: Optional[Dict[str, Any]] = None) -> None:
        """A session-adjacent event that is neither a login nor a logout.

        RDP detach and re-attach go through here so they reach the same places
        start and end do; the platform trackers must not log them directly.
        """
        attributes = session.attributes(event_name)
        if extra:
            attributes.update(extra)
        EVENTS.info(message, extra=attributes)
        if self.on_event is not None:
            try:
                self.on_event(event_name, session, attributes)
            except Exception as exc:
                LOG.debug("Session event hook failed: %s", exc)

    # --------------------------------------------------------------- spans

    def _open_span(self, session: Session, attributes: Dict[str, Any]):
        if self._tracer is None:
            return None
        start = session.started_at or time.time()
        try:
            span = self._tracer.start_span(
                "session %s" % session.kind,
                start_time=int(start * 1e9),
                attributes=_span_attributes(attributes),
            )
        except Exception as exc:
            LOG.debug("Could not start a session span: %s", exc)
            return None
        self._spans[session.id] = span
        return span

    @staticmethod
    def _close_span(span, attributes: Dict[str, Any], ended_at: Optional[float]) -> None:
        try:
            for key in ("session.ended_at", "session.duration_seconds"):
                if key in attributes:
                    span.set_attribute(key, attributes[key])
            span.end(end_time=int(ended_at * 1e9) if ended_at else None)
        except Exception as exc:
            LOG.debug("Could not end a session span: %s", exc)

    def _close_open_spans(self) -> None:
        """The agent is stopping while these sessions are still open.

        Ending them here keeps the spans from being lost, but their end time is
        the agent's shutdown, not a logout, so they say so.
        """
        for session_id, span in list(self._spans.items()):
            try:
                span.set_attribute("session.open_at_agent_stop", True)
                span.end()
            except Exception:
                pass
            self._spans.pop(session_id, None)


def _span_attributes(attributes: Dict[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in attributes.items()
            if key not in _EVENT_ONLY_ATTRIBUTES}
