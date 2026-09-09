"""Session spans: one span per login, closed at logout, correlated with the logs."""

import json
import logging
import time
import unittest

from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import InMemoryLogExporter, SimpleLogRecordProcessor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from sysmon_agent.config import Config
from sysmon_agent.logsetup import build_formatter
from sysmon_agent.sessions.base import SessionTracker
from sysmon_agent.sessions.model import KIND_RDP, KIND_SSH, Session


class Scripted(SessionTracker):
    source_name = "scripted"

    def __init__(self, frames, tracer=None, trace_polls=False):
        super().__init__(poll_seconds=1)
        self.frames = frames
        self.set_tracing(tracer, trace_polls)

    def poll(self):
        return self.frames.pop(0) if self.frames else []


def ssh(session_id="s1", started=None):
    return Session(id=session_id, user="alice", kind=KIND_SSH,
                   remote_host="203.0.113.5", terminal="pts/0",
                   started_at=started or (time.time() - 60))


def tracing():
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return exporter, provider.get_tracer("test")


class SessionSpanTests(unittest.TestCase):
    def test_a_completed_session_becomes_one_span(self):
        exporter, tracer = tracing()
        tracker = Scripted([[], [ssh()], []], tracer)
        tracker._prime()
        tracker._tick()
        tracker._tick()

        spans = exporter.get_finished_spans()
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0].name, "session ssh")

    def test_an_open_session_has_not_been_exported_yet(self):
        exporter, tracer = tracing()
        tracker = Scripted([[], [ssh()]], tracer)
        tracker._prime()
        tracker._tick()
        self.assertEqual(exporter.get_finished_spans(), ())

    def test_span_duration_is_the_session_duration(self):
        exporter, tracer = tracing()
        started = time.time() - 3600  # logged in an hour ago
        tracker = Scripted([[], [ssh(started=started)], []], tracer)
        tracker._prime()
        tracker._tick()
        tracker._tick()

        span = exporter.get_finished_spans()[0]
        duration_seconds = (span.end_time - span.start_time) / 1e9
        self.assertAlmostEqual(duration_seconds, 3600, delta=5)

    def test_span_carries_the_session_attributes(self):
        exporter, tracer = tracing()
        tracker = Scripted([[], [ssh()], []], tracer)
        tracker._prime()
        tracker._tick()
        tracker._tick()

        attributes = dict(exporter.get_finished_spans()[0].attributes)
        self.assertEqual(attributes["session.kind"], "ssh")
        self.assertEqual(attributes["user.name"], "alice")
        self.assertEqual(attributes["client.address"], "203.0.113.5")
        self.assertIn("session.duration_seconds", attributes)
        # 'event.name' describes one event, not the whole session.
        self.assertNotIn("event.name", attributes)

    def test_span_name_is_low_cardinality(self):
        exporter, tracer = tracing()
        sessions = [ssh("s%d" % i) for i in range(3)]
        sessions.append(Session(id="s9", user="bob", kind=KIND_RDP,
                                remote_host="198.51.100.4",
                                started_at=time.time() - 10))
        tracker = Scripted([[], sessions, []], tracer)
        tracker._prime()
        tracker._tick()
        tracker._tick()
        names = {span.name for span in exporter.get_finished_spans()}
        self.assertEqual(names, {"session ssh", "session rdp"})

    def test_sessions_still_open_at_shutdown_are_flagged_not_lost(self):
        exporter, tracer = tracing()
        tracker = Scripted([[ssh()]], tracer)
        tracker._prime()
        tracker._close_open_spans()

        spans = exporter.get_finished_spans()
        self.assertEqual(len(spans), 1)
        attributes = dict(spans[0].attributes)
        self.assertTrue(attributes["session.open_at_agent_stop"])
        # It was not a logout, so it must not claim a session duration.
        self.assertNotIn("session.duration_seconds", attributes)

    def test_tracing_off_means_no_spans_and_no_errors(self):
        tracker = Scripted([[], [ssh()], []])
        tracker._prime()
        tracker._tick()
        tracker._tick()  # must not raise with a None tracer


class PollSpanTests(unittest.TestCase):
    def test_poll_spans_are_opt_in(self):
        exporter, tracer = tracing()
        tracker = Scripted([[], [], []], tracer, trace_polls=False)
        tracker._prime()
        tracker._tick()
        self.assertEqual(exporter.get_finished_spans(), ())

    def test_poll_span_counts_the_work(self):
        exporter, tracer = tracing()
        tracker = Scripted([[], [ssh()]], tracer, trace_polls=True)
        tracker._prime()
        tracker._tick()

        polls = [s for s in exporter.get_finished_spans() if s.name == "session.poll"]
        self.assertEqual(len(polls), 1)
        attributes = dict(polls[0].attributes)
        self.assertEqual(attributes["session.started_count"], 1)
        self.assertEqual(attributes["session.ended_count"], 0)
        self.assertEqual(attributes["session.active_count"], 1)
        self.assertEqual(attributes["session.source"], "scripted")

    def test_failed_poll_is_recorded_on_the_span(self):
        exporter, tracer = tracing()

        class Broken(Scripted):
            def poll(self):
                raise OSError("loginctl went away")

        tracker = Broken([], tracer, trace_polls=True)
        with self.assertRaises(OSError):
            tracker._tick()
        span = [s for s in exporter.get_finished_spans() if s.name == "session.poll"][0]
        self.assertEqual(span.status.status_code.name, "ERROR")
        self.assertTrue(span.events)  # the exception was recorded


class AgentSpanTests(unittest.TestCase):
    """Regression: with the defaults, a machine where nobody logs out produced
    no spans at all, so the traces signal looked dead."""

    def agent(self, exporter, provider, heartbeat=10):
        from sysmon_agent.agent import Agent

        config = Config(endpoint="http://127.0.0.1:4318", machine_name="test",
                        heartbeat_seconds=heartbeat)
        agent = Agent.__new__(Agent)
        agent.config = config
        agent.tracker = None
        agent._tracer = provider.get_tracer("test")
        return agent

    def test_heartbeat_emits_a_span_with_no_session_activity(self):
        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        agent = self.agent(exporter, provider)

        agent._heartbeat(time.time() - 42)

        spans = exporter.get_finished_spans()
        self.assertEqual([s.name for s in spans], ["agent.heartbeat"])
        attributes = dict(spans[0].attributes)
        self.assertGreaterEqual(attributes["agent.uptime_seconds"], 42)
        self.assertEqual(attributes["session.active_count"], 0)

    def test_heartbeat_without_a_tracer_still_logs(self):
        agent = self.agent(None, TracerProvider())
        agent._tracer = None
        agent._heartbeat(time.time())  # must not raise


class LogTraceCorrelationTests(unittest.TestCase):
    def test_session_logs_carry_the_trace_and_span_ids(self):
        _, tracer = tracing()
        log_exporter = InMemoryLogExporter()
        logger_provider = LoggerProvider()
        logger_provider.add_log_record_processor(SimpleLogRecordProcessor(log_exporter))
        handler = LoggingHandler(level=logging.INFO, logger_provider=logger_provider)
        handler.setFormatter(build_formatter(Config()))

        events = logging.getLogger("sysmon.events")
        events.addHandler(handler)
        previous, events.propagate = events.propagate, False
        events.setLevel(logging.INFO)
        try:
            tracker = Scripted([[], [ssh()], []], tracer)
            tracker._prime()
            tracker._tick()
            tracker._tick()
        finally:
            events.removeHandler(handler)
            events.propagate = previous
        logger_provider.shutdown()

        records = [log.log_record for log in log_exporter.get_finished_logs()]
        self.assertTrue(records)
        for record in records:
            payload = json.loads(record.body)
            if payload.get("event.name") in ("session.start", "session.end"):
                self.assertNotEqual(record.trace_id, 0, payload["event.name"])
                self.assertNotEqual(record.span_id, 0, payload["event.name"])


if __name__ == "__main__":
    unittest.main()
