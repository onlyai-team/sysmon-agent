"""The generated systemd unit and Windows task definition must be well formed.

Neither platform is available in the test environment, so this checks the exact
text that gets written: an absolute ExecStart, restart-on-crash, start-at-boot.
"""

import logging
import shlex
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from sysmon_agent import SERVICE_DESCRIPTION, SERVICE_NAME
from sysmon_agent.service import systemd
from sysmon_agent.service import windows as winservice
from sysmon_agent.util import agent_command


class AgentCommandTests(unittest.TestCase):
    def test_command_is_absolute_and_runs_the_agent(self):
        command = agent_command("run")
        self.assertTrue(Path(command[0]).is_absolute(), command)
        self.assertEqual(command[-1], "run")


class SystemdUnitTests(unittest.TestCase):
    def unit(self):
        exec_start = " ".join(shlex.quote(part) for part in agent_command("run"))
        return systemd.UNIT_TEMPLATE.format(
            description=SERVICE_DESCRIPTION, name=SERVICE_NAME, exec_start=exec_start)

    def test_sections_present(self):
        unit = self.unit()
        for section in ("[Unit]", "[Service]", "[Install]"):
            self.assertIn(section, unit)

    def test_restarts_on_crash_forever(self):
        unit = self.unit()
        self.assertIn("Restart=always", unit)
        self.assertIn("RestartSec=5", unit)
        # Without this, systemd gives up after 5 restarts in 10 seconds.
        self.assertIn("StartLimitIntervalSec=0", unit)

    def test_starts_at_boot(self):
        self.assertIn("WantedBy=multi-user.target", self.unit())

    def test_waits_for_network_and_logind(self):
        unit = self.unit()
        self.assertIn("After=network-online.target systemd-logind.service", unit)
        self.assertIn("Wants=network-online.target", unit)

    def test_exec_start_is_absolute(self):
        line = [l for l in self.unit().splitlines() if l.startswith("ExecStart=")][0]
        path = shlex.split(line[len("ExecStart="):])[0]
        self.assertTrue(Path(path).is_absolute(), line)

    def test_runs_as_root(self):
        # utmp, logind and the journal all need it.
        self.assertIn("User=root", self.unit())

    def test_unit_path(self):
        self.assertEqual(str(systemd.UNIT_PATH),
                         "/etc/systemd/system/sysmon-agent.service")


class WindowsTaskTests(unittest.TestCase):
    def xml(self):
        command = agent_command("run")
        return winservice._TASK_XML.format(
            description=SERVICE_DESCRIPTION, name=winservice.TASK_NAME,
            command=winservice._escape(command[0]),
            arguments=winservice._escape(" ".join(command[1:])))

    def test_is_valid_xml(self):
        ET.fromstring(self.xml().split("?>", 1)[1])

    def test_runs_as_local_system_at_boot(self):
        xml = self.xml()
        self.assertIn("<UserId>S-1-5-18</UserId>", xml)   # LocalSystem
        self.assertIn("<BootTrigger>", xml)

    def test_restarts_on_failure_without_a_time_limit(self):
        xml = self.xml()
        self.assertIn("<RestartOnFailure>", xml)
        self.assertIn("<Count>999</Count>", xml)
        self.assertIn("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>", xml)

    def test_no_duplicate_instances(self):
        self.assertIn("<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>",
                      self.xml())

    def test_special_characters_are_escaped(self):
        self.assertEqual(winservice._escape('a&b<c>'), "a&amp;b&lt;c&gt;")

    def test_service_failure_actions_never_give_up(self):
        self.assertEqual(winservice._FAILURE_ACTIONS,
                         "restart/5000/restart/10000/restart/30000")


class WindowsReinstallTests(unittest.TestCase):
    """sc create and pywin32 both fail when the name is already registered, so
    an upgrade has to unregister first."""

    def setUp(self):
        self.original = {name: getattr(winservice, name)
                         for name in ("_mode", "remove", "_install_task",
                                      "pywin32_error", "time")}
        self.actions = []

        class NoSleep:
            @staticmethod
            def sleep(seconds):
                pass

        self.log_level = logging.getLogger("sysmon.service").level
        logging.getLogger("sysmon.service").setLevel(logging.CRITICAL)
        winservice.time = NoSleep
        winservice.pywin32_error = lambda: "No module named win32serviceutil"
        winservice.remove = lambda: self.actions.append("remove") or ["removed"]
        winservice._install_task = lambda: self.actions.append("install")

    def tearDown(self):
        for name, value in self.original.items():
            setattr(winservice, name, value)
        logging.getLogger("sysmon.service").setLevel(self.log_level)

    def test_existing_registration_is_removed_first(self):
        winservice._mode = lambda: "task"
        winservice.install()
        self.assertEqual(self.actions, ["remove", "install"])

    def test_fresh_install_does_not_call_remove(self):
        winservice._mode = lambda: None
        winservice.install()
        self.assertEqual(self.actions, ["install"])


if __name__ == "__main__":
    unittest.main()
