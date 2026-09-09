"""The long-running agent: collect metrics, watch sessions, export over OTLP."""

from __future__ import annotations

import contextlib
import logging
import platform
import threading
import time
from typing import Optional

from . import __version__
from .config import Config
from .metrics import SystemMetrics
from .sessions import build_tracker
from .telemetry import Telemetry
from .util import set_tracer

LOG = logging.getLogger("sysmon.agent")
EVENTS = logging.getLogger("sysmon.events")


class Agent:
    """Owns the telemetry pipeline and the session tracker for one process."""

    def __init__(self, config: Config):
        config.validate()
        self.config = config
        self.telemetry = Telemetry(config)
        self.tracker = None
        self.metrics = None
        self._tracer = None
        self._session_events = None

    def run(self, stop_event: Optional[threading.Event] = None) -> int:
        stop = stop_event or threading.Event()
        started = time.time()

        self.telemetry.start()
        self._tracer = self.telemetry.tracer("sysmon.agent")

        # A span that closes during startup, so traces show up on every service
        # start instead of waiting for the first logout.
        with self._span("agent.startup") as span:
            self._start_pipeline(span)

        EVENTS.info(
            "Agent started on %s" % self.config.machine_name,
            extra={
                "event.name": "agent.start",
                "agent.version": __version__,
                "agent.platform": platform.platform(),
                "otlp.endpoint": self.config.endpoint,
                "traces.enabled": self.config.traces_enabled,
                "metrics.interval_seconds": self.config.metrics_interval_seconds,
                "sessions.poll_seconds": self.config.session_poll_seconds,
            },
        )
        LOG.info("Agent %s running; exporting to %s every %ds",
                 __version__, self.config.endpoint, self.config.metrics_interval_seconds)

        try:
            while not stop.wait(self.config.heartbeat_seconds):
                self._heartbeat(started)
        except KeyboardInterrupt:
            LOG.info("Interrupted")
        finally:
            self.stop(started)
        return 0

    # ------------------------------------------------------------- startup

    def _start_pipeline(self, span) -> None:
        meter = self.telemetry.meter()
        self._session_events = meter.create_counter(
            "system.sessions.events",
            unit="{event}",
            description="Login session start/end events observed",
        )

        self.tracker = build_tracker(
            self.config.session_poll_seconds, on_event=self._on_session_event
        )
        session_tracer = self.telemetry.tracer("sysmon.sessions")
        self.tracker.set_tracing(session_tracer, self.config.trace_polls)
        if session_tracer is not None and self.config.trace_polls:
            # Only then: this traces every loginctl / wevtutil / quser call.
            set_tracer(self.telemetry.tracer("sysmon.exec"))

        self.metrics = SystemMetrics(meter, session_tracker=self.tracker,
                                     per_cpu=self.config.per_cpu_metrics)
        self.metrics.register()
        self.tracker.start()

        if span is not None:
            span.set_attribute("agent.version", __version__)
            span.set_attribute("agent.platform", platform.platform())
            span.set_attribute("otlp.endpoint", self.config.endpoint)
            span.set_attribute("session.source", self.tracker.source_name)
            span.set_attribute("metrics.interval_seconds",
                               self.config.metrics_interval_seconds)

    # ----------------------------------------------------------- heartbeat

    def _heartbeat(self, started: float) -> None:
        """Periodic health check. It is also a span, so the trace stream stays
        alive on a machine where nobody logs in or out for hours."""
        with self._span("agent.heartbeat") as span:
            counts = self.tracker.active_counts() if self.tracker else {}
            uptime = int(time.time() - started)
            if span is not None:
                span.set_attribute("agent.version", __version__)
                span.set_attribute("agent.uptime_seconds", uptime)
                span.set_attribute("session.active_count", sum(counts.values()))
                for kind, count in counts.items():
                    span.set_attribute("session.active.%s" % kind, count)
            LOG.info("Heartbeat: uptime %ds, active sessions %s",
                     uptime, counts or "none")

    def _span(self, name: str):
        if self._tracer is None:
            return contextlib.nullcontext()
        return self._tracer.start_as_current_span(name)

    # -------------------------------------------------------------- events

    def _on_session_event(self, event, session, attributes) -> None:
        if self._session_events is None:
            return
        try:
            self._session_events.add(1, {
                "event.name": event,
                "session.kind": session.kind,
                "session.source": session.source,
            })
        except Exception as exc:
            LOG.debug("Session counter failed: %s", exc)

    # ------------------------------------------------------------ shutdown

    def stop(self, started: Optional[float] = None) -> None:
        LOG.info("Shutting down")
        if self.tracker is not None:
            self.tracker.stop()
            self.tracker.join(timeout=5)
        EVENTS.info(
            "Agent stopping on %s" % self.config.machine_name,
            extra={
                "event.name": "agent.stop",
                "agent.version": __version__,
                "agent.uptime_seconds": round(time.time() - started, 1) if started else 0,
            },
        )
        self.telemetry.flush()
        self.telemetry.shutdown()
