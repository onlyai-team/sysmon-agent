"""Configuration: endpoint shaping, auth headers, validation, persistence."""

import base64
import json
import tempfile
import unittest
from pathlib import Path

from sysmon_agent import config as config_module
from sysmon_agent import util
from sysmon_agent.config import Config
from sysmon_agent.util import AgentError


class EndpointTests(unittest.TestCase):
    def test_base_url_gets_the_signal_path(self):
        config = Config(endpoint="https://otel.example.com:4318")
        self.assertEqual(config.signal_endpoint("metrics"),
                         "https://otel.example.com:4318/v1/metrics")
        self.assertEqual(config.signal_endpoint("logs"),
                         "https://otel.example.com:4318/v1/logs")

    def test_trailing_slash_and_v1_are_handled(self):
        for endpoint in ("https://c:4318/", "https://c:4318/v1", "https://c:4318/v1/"):
            self.assertEqual(Config(endpoint=endpoint).signal_endpoint("metrics"),
                             "https://c:4318/v1/metrics")

    def test_full_signal_url_is_left_alone(self):
        config = Config(endpoint="https://c:4318/v1/metrics")
        self.assertEqual(config.signal_endpoint("metrics"), "https://c:4318/v1/metrics")

    def test_path_prefixed_gateway(self):
        config = Config(endpoint="https://gateway.example.com/otlp")
        self.assertEqual(config.signal_endpoint("logs"),
                         "https://gateway.example.com/otlp/v1/logs")


class AuthTests(unittest.TestCase):
    def test_none(self):
        self.assertEqual(Config(auth_type="none", token="x").headers(), {})

    def test_bearer(self):
        headers = Config(auth_type="bearer", token="abc123").headers()
        self.assertEqual(headers, {"Authorization": "Bearer abc123"})

    def test_basic(self):
        headers = Config(auth_type="basic", username="u", password="p").headers()
        expected = base64.b64encode(b"u:p").decode()
        self.assertEqual(headers, {"Authorization": "Basic %s" % expected})

    def test_custom_header(self):
        headers = Config(auth_type="header", header_name="X-Api-Key",
                         header_value="k").headers()
        self.assertEqual(headers, {"X-Api-Key": "k"})


class ValidationTests(unittest.TestCase):
    def valid(self, **overrides):
        base = dict(endpoint="https://c:4318", machine_name="host-1")
        base.update(overrides)
        return Config(**base)

    def test_valid_config_passes(self):
        self.valid().validate()

    def test_endpoint_required(self):
        with self.assertRaises(AgentError):
            Config(machine_name="h").validate()

    def test_endpoint_scheme_checked(self):
        with self.assertRaises(AgentError):
            self.valid(endpoint="otel.example.com:4318").validate()

    def test_missing_credentials_are_caught(self):
        with self.assertRaises(AgentError):
            self.valid(auth_type="bearer").validate()
        with self.assertRaises(AgentError):
            self.valid(auth_type="basic").validate()
        with self.assertRaises(AgentError):
            self.valid(auth_type="header").validate()

    def test_unknown_auth_type(self):
        with self.assertRaises(AgentError):
            self.valid(auth_type="oauth2").validate()

    def test_intervals_must_be_positive(self):
        with self.assertRaises(AgentError):
            self.valid(metrics_interval_seconds=0).validate()


class PersistenceTests(unittest.TestCase):
    def test_round_trip_and_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            original = Config(endpoint="https://c:4318", machine_name="host-1",
                              auth_type="bearer", token="s3cret",
                              extra_attributes={"team": "infra"})
            original.save(path)
            loaded = Config.load(path)
            self.assertEqual(loaded.endpoint, original.endpoint)
            self.assertEqual(loaded.token, "s3cret")
            self.assertEqual(loaded.extra_attributes, {"team": "infra"})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_unknown_keys_from_a_newer_version_are_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"endpoint": "https://c:4318",
                                        "future_option": True}))
            self.assertEqual(Config.load(path).endpoint, "https://c:4318")

    def test_secrets_are_redacted_for_display(self):
        config = Config(auth_type="bearer", token="s3cret", password="p",
                        header_value="h")
        redacted = config.redacted()
        self.assertNotIn("s3cret", json.dumps(redacted))
        self.assertNotIn("s3cret", str(redacted))
        self.assertEqual(redacted["token"], "***redacted***")

    def test_missing_file_gives_a_clear_error(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(AgentError) as caught:
                Config.load(Path(directory) / "absent.json")
            self.assertIn("install", str(caught.exception))


class WindowsPermissionTests(unittest.TestCase):
    """Regression: locking down the config directory once removed inherited
    permissions from the whole install tree, including the venv, and left an
    elevated Administrator unable to stat sysmon-agent.exe."""

    def setUp(self):
        self.calls = []
        self.results = {}

        class Result:
            def __init__(self, returncode):
                self.returncode = returncode
                self.stdout = ""
                self.stderr = "Access is denied."

        def fake_run(cmd, **kwargs):
            self.calls.append(list(cmd))
            return Result(self.results.get(len(self.calls), 0))

        self.patched = []
        for name, value in (("IS_WINDOWS", True), ("run", fake_run)):
            self.patched.append((name, getattr(config_module, name)))
            setattr(config_module, name, value)

    def tearDown(self):
        for name, value in self.patched:
            setattr(config_module, name, value)

    def restrict(self, path=Path(r"C:\ProgramData\sysmon-agent\config.json")):
        config_module._restrict_permissions(path)

    def test_only_the_file_is_touched(self):
        self.restrict()
        for call in self.calls:
            self.assertNotIn(r"C:\ProgramData\sysmon-agent", call)
        self.assertEqual(len(self.calls), 1)

    def test_uses_well_known_sids_not_localised_names(self):
        self.restrict()
        icacls = " ".join(self.calls[0])
        self.assertIn("*S-1-5-18:F", icacls)         # LocalSystem
        self.assertIn("*S-1-5-32-544:F", icacls)     # built-in Administrators
        self.assertNotIn("Administrators:F", icacls)

    def test_failed_grant_restores_inheritance(self):
        self.results = {1: 1}  # icacls fails
        with self.assertLogs("sysmon.config", level="WARNING"):
            self.restrict()
        self.assertEqual(self.calls[1][-1], "/inheritance:e")


class PathExistsTests(unittest.TestCase):
    def test_permission_error_is_not_fatal(self):
        class Denied:
            def exists(self):
                raise PermissionError(5, "Access is denied")

        self.assertFalse(util.path_exists(Denied()))


if __name__ == "__main__":
    unittest.main()
