"""The webhook fires on session enter and exit only, and nothing else."""

import base64
import json
import threading
import time
import logging
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sysmon_agent.config import Config
from sysmon_agent.sessions.model import (EVENT_END, EVENT_OBSERVED, EVENT_START,
                                         KIND_RDP, KIND_SSH, Session)
from sysmon_agent.util import AgentError
from sysmon_agent.webhook import (ACTION_ENTER, ACTION_EXIT, WebhookNotifier,
                                  action_for, build_payload)


class Endpoint:
    """A real HTTP server, so delivery is proved rather than mocked."""

    def __init__(self, status=200):
        self.received = []
        self.headers = []
        self.status = status
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                outer.received.append(json.loads(body.decode("utf-8")))
                outer.headers.append(dict(self.headers))
                self.send_response(outer.status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self):
        return "http://127.0.0.1:%d/hook" % self.port

    def wait(self, count=1, timeout=5.0):
        deadline = time.time() + timeout
        while time.time() < deadline and len(self.received) < count:
            time.sleep(0.02)
        return self.received

    def close(self):
        self.server.shutdown()


def ssh_session():
    return Session(id="s1", user="alice", kind=KIND_SSH, remote_host="203.0.113.5",
                   terminal="pts/0", started_at=time.time() - 60, source="systemd-logind")


RESOURCE = {"service.name": "sysmon-agent", "host.name": "edge-01",
            "os.type": "linux", "deployment.environment": "prod"}


class ActionMappingTests(unittest.TestCase):
    def test_login_and_logout(self):
        self.assertEqual(action_for(EVENT_START), ACTION_ENTER)
        self.assertEqual(action_for(EVENT_END), ACTION_EXIT)

    def test_rdp_reconnect_counts_as_entering(self):
        self.assertEqual(action_for("rdp.reconnected"), ACTION_ENTER)

    def test_rdp_disconnect_counts_as_leaving(self):
        self.assertEqual(action_for("rdp.disconnected"), ACTION_EXIT)

    def test_everything_else_is_ignored(self):
        for event in (EVENT_OBSERVED, "agent.start", "agent.stop", "shell.start"):
            self.assertIsNone(action_for(event), event)


class PayloadTests(unittest.TestCase):
    def payload(self, event=EVENT_START):
        attributes = ssh_session().attributes(event)
        return build_payload(action_for(event), attributes, "Login: ssh alice", RESOURCE)

    def test_carries_the_same_keys_as_the_otel_record(self):
        payload = self.payload()
        for key in ("event.name", "session.id", "session.kind", "session.source",
                    "user.name", "enduser.id", "client.address", "session.terminal"):
            self.assertIn(key, payload, key)

    def test_action_and_time(self):
        payload = self.payload()
        self.assertEqual(payload["action"], ACTION_ENTER)
        self.assertEqual(payload["event.name"], EVENT_START)
        self.assertTrue(payload["time"].endswith("Z"))

    def test_resource_identifies_the_machine(self):
        self.assertEqual(self.payload()["resource"]["host.name"], "edge-01")

    def test_exit_payload_has_the_duration(self):
        attributes = ssh_session().attributes(EVENT_END, ended_at=time.time())
        payload = build_payload(ACTION_EXIT, attributes, "Logout", RESOURCE)
        self.assertEqual(payload["action"], ACTION_EXIT)
        self.assertIn("session.duration_seconds", payload)

    def test_payload_is_json_serialisable(self):
        json.dumps(self.payload())


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.endpoint = Endpoint()
        self.addCleanup(self.endpoint.close)

    def notifier(self, **overrides):
        settings = dict(endpoint="https://c:4318", machine_name="edge-01",
                        webhook_url=self.endpoint.url)
        settings.update(overrides)
        config = Config(**settings)
        config.validate()
        notifier = WebhookNotifier(config, RESOURCE)
        notifier.start()
        self.addCleanup(notifier.stop, 5)
        return notifier

    def send(self, notifier, event, session=None):
        session = session or ssh_session()
        return notifier.notify(event, "message", session.attributes(event))

    def test_an_enter_event_is_delivered(self):
        notifier = self.notifier()
        self.assertTrue(self.send(notifier, EVENT_START))
        received = self.endpoint.wait(1)
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]["action"], ACTION_ENTER)
        self.assertEqual(received[0]["user.name"], "alice")

    def test_observed_sessions_are_not_delivered(self):
        notifier = self.notifier()
        self.assertFalse(self.send(notifier, EVENT_OBSERVED))
        time.sleep(0.2)
        self.assertEqual(self.endpoint.received, [])

    def test_bearer_auth_header(self):
        notifier = self.notifier(webhook_auth_type="bearer", webhook_token="tok")
        self.send(notifier, EVENT_START)
        self.endpoint.wait(1)
        self.assertEqual(self.endpoint.headers[0]["Authorization"], "Bearer tok")

    def test_basic_auth_header_matches_the_otlp_scheme(self):
        notifier = self.notifier(webhook_auth_type="basic",
                                 webhook_username="u", webhook_password="p")
        self.send(notifier, EVENT_START)
        self.endpoint.wait(1)
        expected = "Basic %s" % base64.b64encode(b"u:p").decode()
        self.assertEqual(self.endpoint.headers[0]["Authorization"], expected)

    def test_custom_header_auth(self):
        notifier = self.notifier(webhook_auth_type="header",
                                 webhook_header_name="X-Api-Key",
                                 webhook_header_value="k")
        self.send(notifier, EVENT_START)
        self.endpoint.wait(1)
        self.assertEqual(self.endpoint.headers[0]["X-Api-Key"], "k")

    def test_content_type_is_json(self):
        notifier = self.notifier()
        self.send(notifier, EVENT_START)
        self.endpoint.wait(1)
        self.assertEqual(self.endpoint.headers[0]["Content-Type"], "application/json")

    def test_enter_then_exit(self):
        notifier = self.notifier()
        self.send(notifier, EVENT_START)
        self.send(notifier, EVENT_END)
        received = self.endpoint.wait(2)
        self.assertEqual([r["action"] for r in received], [ACTION_ENTER, ACTION_EXIT])

    def test_rdp_reconnect_is_delivered_as_an_enter(self):
        notifier = self.notifier()
        session = Session(id="win:ts:3", user="CORP\\\\bob", kind=KIND_RDP,
                          remote_host="198.51.100.4", source="terminal-services")
        self.send(notifier, "rdp.reconnected", session)
        received = self.endpoint.wait(1)
        self.assertEqual(received[0]["action"], ACTION_ENTER)
        self.assertEqual(received[0]["session.kind"], KIND_RDP)

    def test_a_rejecting_endpoint_does_not_raise(self):
        self.endpoint.close()
        self.endpoint = Endpoint(status=400)
        notifier = self.notifier()
        with self.assertLogs("sysmon.webhook", level="ERROR"):
            self.send(notifier, EVENT_START)
            self.endpoint.wait(1)
            time.sleep(0.3)
        self.assertEqual(notifier.failed, 1)   # counted, not retried, not raised

    def test_no_url_means_no_worker(self):
        config = Config(endpoint="https://c:4318", machine_name="h")
        notifier = WebhookNotifier(config, RESOURCE)
        notifier.start()
        self.assertFalse(self.send(notifier, EVENT_START))
        notifier.stop()


class AgentWiringTests(unittest.TestCase):
    """The agent must hand every session event to the notifier, including the
    RDP ones the Windows tracker raises outside the login/logout path."""

    def setUp(self):
        self.endpoint = Endpoint()
        self.addCleanup(self.endpoint.close)

        from sysmon_agent.agent import Agent

        config = Config(endpoint="https://c:4318", machine_name="edge-01",
                        webhook_url=self.endpoint.url)
        config.validate()
        self.agent = Agent.__new__(Agent)
        self.agent.config = config
        self.agent._session_events = None
        self.agent.webhook = WebhookNotifier(config, RESOURCE)
        self.agent.webhook.start()
        self.addCleanup(self.agent.webhook.stop, 5)

    def fire(self, event, session=None):
        session = session or ssh_session()
        self.agent._on_session_event(event, session, session.attributes(event))

    def test_login_reaches_the_endpoint_with_a_readable_message(self):
        self.fire(EVENT_START)
        received = self.endpoint.wait(1)
        self.assertEqual(received[0]["action"], ACTION_ENTER)
        self.assertTrue(received[0]["message"].startswith("Login:"))

    def test_logout_reaches_the_endpoint(self):
        self.fire(EVENT_END)
        self.assertEqual(self.endpoint.wait(1)[0]["action"], ACTION_EXIT)

    def test_rdp_reconnect_reaches_the_endpoint_as_an_enter(self):
        session = Session(id="win:ts:3", user="bob", kind=KIND_RDP,
                          remote_host="198.51.100.4", source="terminal-services")
        self.fire("rdp.reconnected", session)
        received = self.endpoint.wait(1)
        self.assertEqual(received[0]["action"], ACTION_ENTER)
        self.assertTrue(received[0]["message"].startswith("RDP reconnected:"))

    def test_startup_baseline_and_agent_events_are_not_sent(self):
        self.fire(EVENT_OBSERVED)
        self.agent._on_session_event("agent.start", ssh_session(), {})
        time.sleep(0.25)
        self.assertEqual(self.endpoint.received, [])


class ConfigTests(unittest.TestCase):
    def base(self, **overrides):
        settings = dict(endpoint="https://c:4318", machine_name="h")
        settings.update(overrides)
        return Config(**settings)

    def test_webhook_is_optional(self):
        self.base().validate()
        self.assertFalse(self.base().webhook_enabled())

    def test_url_scheme_is_checked(self):
        with self.assertRaises(AgentError):
            self.base(webhook_url="example.com/hook").validate()

    def test_missing_webhook_credentials_are_caught(self):
        for auth in ("bearer", "basic", "header"):
            with self.assertRaises(AgentError):
                self.base(webhook_url="https://h/x", webhook_auth_type=auth).validate()

    def test_webhook_secrets_are_redacted(self):
        config = self.base(webhook_url="https://h/x", webhook_auth_type="bearer",
                           webhook_token="s3cret")
        self.assertNotIn("s3cret", json.dumps(config.redacted()))

    def test_otlp_credentials_are_independent_of_the_webhook(self):
        config = self.base(auth_type="bearer", token="otlp-token",
                           webhook_url="https://h/x", webhook_auth_type="header",
                           webhook_header_name="X-Key", webhook_header_value="hook-key")
        config.validate()
        self.assertEqual(config.headers(), {"Authorization": "Bearer otlp-token"})
        self.assertEqual(config.webhook_headers(), {"X-Key": "hook-key"})


if __name__ == "__main__":
    unittest.main()
