"""CLI plumbing: flag-driven configuration and log tailing."""

import argparse
import io
import sys
import tempfile
import unittest
from pathlib import Path

from sysmon_agent import cli
from dataclasses import asdict

from sysmon_agent.config import Config


def namespace(**overrides):
    defaults = dict(
        endpoint=None, machine_name=None, auth_type=None, token=None, username=None,
        password=None, header_name=None, header_value=None, interval=None,
        session_poll=None, environment=None, attribute=None, ca_bundle=None,
        no_verify_tls=False, skip_check=True, non_interactive=True,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class BuildConfigTests(unittest.TestCase):
    def test_flags_only(self):
        args = namespace(endpoint="https://c:4318", machine_name="edge-01",
                         auth_type="bearer", token="tok", interval=15,
                         session_poll=2, environment="prod",
                         attribute=["team=infra", "site=hcm"])
        config = cli.build_config(args, None)
        config.validate()
        self.assertEqual(config.endpoint, "https://c:4318")
        self.assertEqual(config.machine_name, "edge-01")
        self.assertEqual(config.headers(), {"Authorization": "Bearer tok"})
        self.assertEqual(config.metrics_interval_seconds, 15)
        self.assertEqual(config.session_poll_seconds, 2)
        self.assertEqual(config.extra_attributes, {"team": "infra", "site": "hcm"})

    def test_existing_values_are_kept_when_no_flag_is_given(self):
        existing = Config(endpoint="https://old:4318", machine_name="old-name",
                          auth_type="bearer", token="old-token")
        config = cli.build_config(namespace(machine_name="new-name"), existing)
        self.assertEqual(config.machine_name, "new-name")
        self.assertEqual(config.endpoint, "https://old:4318")
        self.assertEqual(config.token, "old-token")

    def test_no_verify_tls_flag(self):
        config = cli.build_config(
            namespace(endpoint="https://c:4318", no_verify_tls=True), None)
        self.assertFalse(config.verify_tls)
        self.assertIs(config.tls_verify(), False)

    def test_malformed_attribute_is_skipped(self):
        config = cli.build_config(
            namespace(endpoint="https://c:4318", attribute=["broken", "k=v"]), None)
        self.assertEqual(config.extra_attributes, {"k": "v"})


class UpdateFlowTests(unittest.TestCase):
    """'install --non-interactive --skip-check' is how an upgrade re-registers
    the service, so it must leave every stored answer untouched."""

    def test_update_changes_nothing(self):
        existing = Config(endpoint="https://c:4318", machine_name="edge-01",
                          auth_type="bearer", token="tok", environment="prod",
                          metrics_interval_seconds=15, session_poll_seconds=2,
                          log_format="text", per_cpu_metrics=False,
                          extra_attributes={"team": "infra"})
        before = asdict(existing)
        after = asdict(cli.build_config(namespace(), existing))
        self.assertEqual(after, before)


class TailTests(unittest.TestCase):
    def test_shows_the_last_n_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "agent.log"
            path.write_text("".join("line %d\n" % i for i in range(1, 21)))
            captured, sys.stdout = sys.stdout, io.StringIO()
            try:
                cli._tail(path, lines=5, follow=False)
                output = sys.stdout.getvalue()
            finally:
                sys.stdout = captured
            self.assertEqual(output.splitlines(), ["line %d" % i for i in range(16, 21)])


class ParserTests(unittest.TestCase):
    def test_every_documented_command_exists(self):
        parser = cli.build_parser()
        for command in ("install", "remove", "logs", "status", "sessions", "run",
                        "test", "config", "restart"):
            args = parser.parse_args([command])
            self.assertTrue(callable(args.func), command)

    def test_install_accepts_a_full_non_interactive_invocation(self):
        args = cli.build_parser().parse_args([
            "install", "--endpoint", "https://c:4318", "--machine-name", "edge-01",
            "--auth-type", "basic", "--username", "u", "--password", "p",
            "--interval", "20", "--non-interactive", "--skip-check",
        ])
        self.assertEqual(args.auth_type, "basic")
        self.assertTrue(args.non_interactive)

    def test_logs_defaults(self):
        args = cli.build_parser().parse_args(["logs"])
        self.assertEqual(args.lines, 100)
        self.assertFalse(args.follow)
        self.assertEqual(args.source, "auto")

    def test_remove_purge_flag(self):
        self.assertTrue(cli.build_parser().parse_args(["remove", "--purge"]).purge)


if __name__ == "__main__":
    unittest.main()
