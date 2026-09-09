"""The long-running agent: collect metrics, watch sessions, export over OTLP."""

from __future__ import annotations

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

LOG = logging.getLogger("sysmon.agent")
EVENTS = logging.getLogger("sysmon.events")

HEARTBEAT_SECONDS = 300


class Agent:
    """Owns the telemetry pipeline and the session tracker for one process."""

    def __init__(self, config: Config):
        config.validate()
        self.config = config
        self.telemetry = Telemetry(config)
        self.tracker = None
        self.metrics = None
        self._session_events = None

    def run(self, stop_event: Optional[threading.Event] = None) -> int:
        stop = stop_event or threading.Event()
        started = time.time()

        self.telemetry.start()
        meter = self.telemetry.meter()
        self._session_events = meter.create_counter(
            "system.sessions.events",
            unit="{event}",
            description="Login session start/end events observed",
        )

        self.tracker = build_tracker(
            self.config.session_poll_seconds, on_event=self._on_session_event
        )
        self.metrics = SystemMetrics(meter, session_tracker=self.tracker,
                                     per_cpu=self.config.per_cpu_metrics)
        self.metrics.register()
        self.tracker.start()

        EVENTS.info(
            "Agent started on %s" % self.config.machine_name,
            extra={
                "event.name": "agent.start",
                "agent.version": __version__,
                "agent.platform": platform.platform(),
                "otlp.endpoint": self.config.endpoint,
                "metrics.interval_seconds": self.config.metrics_interval_seconds,
                "sessions.poll_seconds": self.config.session_poll_seconds,
            },
        )
        LOG.info("Agent %s running; exporting to %s every %ds",
                 __version__, self.config.endpoint, self.config.metrics_interval_seconds)

        try:
            while not stop.wait(HEARTBEAT_SECONDS):
                self._heartbeat(started)
        except KeyboardInterrupt:
            LOG.info("Interrupted")
        finally:
            self.stop(started)
        return 0

    def _heartbeat(self, started: float) -> None:
        counts = self.tracker.active_counts() if self.tracker else {}
        LOG.info("Heartbeat: uptime %ds, active sessions %s",
                 int(time.time() - started), counts or "none")

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
