"""JSON log records: the log file and the exported log body must be parseable."""

import json
import logging
import unittest

from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import InMemoryLogExporter, SimpleLogRecordProcessor

from sysmon_agent.config import Config
from sysmon_agent.logsetup import JsonFormatter, build_formatter
from sysmon_agent.sessions.model import EVENT_START, Session
from sysmon_agent.util import AgentError


def record(message="hello", **extra):
    made = logging.LogRecord("sysmon.events", logging.INFO, __file__, 1, message,
                             None, None)
    made.__dict__.update(extra)
    return made


class JsonFormatterTests(unittest.TestCase):
    def setUp(self):
        self.formatter = JsonFormatter()

    def parse(self, **extra):
        return json.loads(self.formatter.format(record(**extra)))

    def test_base_fields(self):
        payload = self.parse()
        self.assertEqual(payload["message"], "hello")
        self.assertEqual(payload["level"], "INFO")
        self.assertEqual(payload["logger"], "sysmon.events")
        self.assertTrue(payload["time"].endswith("Z"))

    def test_event_attributes_are_flattened_with_dotted_names(self):
        attributes = Session(id="s1", user="alice", kind="ssh",
                             remote_host="203.0.113.5", terminal="pts/0",
                             started_at=1788923742.0).attributes(EVENT_START)
        payload = self.parse(**attributes)
        self.assertEqual(payload["event.name"], "session.start")
        self.assertEqual(payload["session.kind"], "ssh")
        self.assertEqual(payload["client.address"], "203.0.113.5")
        self.assertEqual(payload["user.name"], "alice")

    def test_numbers_keep_their_type(self):
        payload = self.parse(**{"process.pid": 4321, "session.duration_seconds": 12.5})
        self.assertEqual(payload["process.pid"], 4321)
        self.assertEqual(payload["session.duration_seconds"], 12.5)

    def test_non_serialisable_values_do_not_break_the_record(self):
        payload = self.parse(**{"weird": object()})
        self.assertIsInstance(payload["weird"], str)

    def test_unicode_is_not_escaped(self):
        payload = json.loads(self.formatter.format(record("phiên đăng nhập")))
        self.assertEqual(payload["message"], "phiên đăng nhập")

    def test_exceptions_are_included(self):
        try:
            raise ValueError("boom")
        except ValueError:
            import sys
            made = record("failed")
            made.exc_info = sys.exc_info()
            payload = json.loads(self.formatter.format(made))
        self.assertIn("ValueError: boom", payload["exception"])

    def test_every_line_is_one_object(self):
        self.assertNotIn("\n", self.formatter.format(record("a\nb")).rstrip())


class FormatterSelectionTests(unittest.TestCase):
    def test_json_is_the_default(self):
        self.assertIsInstance(build_formatter(Config()), JsonFormatter)

    def test_text_can_be_chosen(self):
        formatter = build_formatter(Config(log_format="text"))
        self.assertNotIsInstance(formatter, JsonFormatter)
        self.assertIn("hello", formatter.format(record()))

    def test_unknown_format_is_rejected(self):
        config = Config(endpoint="https://c:4318", machine_name="h", log_format="yaml")
        with self.assertRaises(AgentError):
            config.validate()


class ExportedBodyTests(unittest.TestCase):
    """The collector must receive the body as JSON, not as prose."""

    def test_body_is_json_with_the_event_fields(self):
        exporter = InMemoryLogExporter()
        provider = LoggerProvider()
        provider.add_log_record_processor(SimpleLogRecordProcessor(exporter))
        handler = LoggingHandler(level=logging.INFO, logger_provider=provider)
        handler.setFormatter(build_formatter(Config()))

        logger = logging.getLogger("sysmon.events.test")
        logger.setLevel(logging.INFO)
        logger.addHandler(handler)
        logger.propagate = False
        try:
            logger.info("Login: ssh alice from 203.0.113.5",
                        extra={"event.name": "session.start", "session.kind": "ssh",
                               "client.address": "203.0.113.5", "user.name": "alice"})
        finally:
            logger.removeHandler(handler)
        provider.shutdown()

        logs = exporter.get_finished_logs()
        self.assertEqual(len(logs), 1)
        payload = json.loads(logs[0].log_record.body)
        self.assertEqual(payload["event.name"], "session.start")
        self.assertEqual(payload["client.address"], "203.0.113.5")
        self.assertEqual(payload["user.name"], "alice")

        # The attributes are still attributes; the JSON body is additional.
        attributes = dict(logs[0].log_record.attributes or {})
        self.assertEqual(attributes.get("event.name"), "session.start")


if __name__ == "__main__":
    unittest.main()
