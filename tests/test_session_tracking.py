"""Session diffing: a login must produce a start event, a logout an end event."""

import unittest

from sysmon_agent.sessions.base import SessionTracker
from sysmon_agent.sessions.linux import _classify, _classify_utmp
from sysmon_agent.sessions.model import (EVENT_END, EVENT_OBSERVED, EVENT_START,
                                         KIND_CONSOLE, KIND_GUI, KIND_RDP, KIND_SSH,
                                         KIND_VNC, Session)


class FakeTracker(SessionTracker):
    source_name = "fake"

    def __init__(self):
        super().__init__(poll_seconds=1, on_event=self.record)
        self.queue = []
        self.events = []

    def poll(self):
        return self.queue.pop(0) if self.queue else []

    def record(self, event, session, attributes):
        self.events.append((event, session.id, attributes))


def ssh_session(session_id="1", user="alice", host="203.0.113.5"):
    return Session(id=session_id, user=user, kind=KIND_SSH, remote_host=host,
                   terminal="pts/0", started_at=1788923742.0)


class TrackerDiffTests(unittest.TestCase):
    def setUp(self):
        self.tracker = FakeTracker()

    def test_existing_sessions_are_not_reported_as_new_logins(self):
        self.tracker.queue = [[ssh_session()]]
        self.tracker._prime()
        self.assertEqual([e[0] for e in self.tracker.events], [EVENT_OBSERVED])

    def test_new_session_emits_start(self):
        self.tracker.queue = [[], [ssh_session()]]
        self.tracker._prime()
        self.tracker._tick()
        self.assertEqual([e[0] for e in self.tracker.events], [EVENT_START])

    def test_disappearing_session_emits_end_with_duration(self):
        self.tracker.queue = [[], [ssh_session()], []]
        self.tracker._prime()
        self.tracker._tick()
        self.tracker._tick()
        kinds = [e[0] for e in self.tracker.events]
        self.assertEqual(kinds, [EVENT_START, EVENT_END])
        end_attributes = self.tracker.events[-1][2]
        self.assertIn("session.duration_seconds", end_attributes)
        self.assertIn("session.ended_at", end_attributes)
        self.assertEqual(end_attributes["client.address"], "203.0.113.5")

    def test_stable_session_emits_nothing(self):
        self.tracker.queue = [[ssh_session()], [ssh_session()], [ssh_session()]]
        self.tracker._prime()
        self.tracker._tick()
        self.tracker._tick()
        self.assertEqual([e[0] for e in self.tracker.events], [EVENT_OBSERVED])

    def test_active_counts_by_kind(self):
        self.tracker.queue = [[
            ssh_session("1"), ssh_session("2", user="bob"),
            Session(id="3", user="carol", kind=KIND_RDP),
        ]]
        self.tracker._prime()
        self.assertEqual(self.tracker.active_counts(), {KIND_SSH: 2, KIND_RDP: 1})

    def test_initial_poll_failure_is_swallowed(self):
        class Broken(FakeTracker):
            def poll(self):
                raise OSError("loginctl went away")

        broken = Broken()
        with self.assertLogs("sysmon.sessions", level="ERROR"):
            broken._prime()  # a dead session source must not stop the agent
        self.assertEqual(broken.events, [])

    def test_attributes_carry_semantic_keys(self):
        attributes = ssh_session().attributes(EVENT_START)
        self.assertEqual(attributes["event.name"], EVENT_START)
        self.assertEqual(attributes["session.kind"], KIND_SSH)
        self.assertEqual(attributes["user.name"], "alice")
        self.assertEqual(attributes["client.address"], "203.0.113.5")
        self.assertEqual(attributes["session.terminal"], "pts/0")
        self.assertTrue(attributes["session.started_at"].endswith("Z"))


class LinuxClassificationTests(unittest.TestCase):
    def test_ssh_from_logind(self):
        props = {"Service": "sshd", "Type": "tty", "Remote": "yes",
                 "RemoteHost": "203.0.113.5"}
        self.assertEqual(_classify(props, "sshd bash"), KIND_SSH)

    def test_local_console(self):
        props = {"Service": "login", "Type": "tty", "Remote": "no"}
        self.assertEqual(_classify(props, "login bash"), KIND_CONSOLE)

    def test_xrdp_is_rdp(self):
        props = {"Service": "xrdp-sesman", "Type": "x11", "Remote": "no"}
        self.assertEqual(_classify(props, "xrdp-sesman Xorg"), KIND_RDP)

    def test_vnc_leader_process(self):
        props = {"Service": "systemd-user", "Type": "x11", "Remote": "no"}
        self.assertEqual(_classify(props, "Xvnc xstartup"), KIND_VNC)

    def test_utmp_fallback(self):
        self.assertEqual(_classify_utmp("pts/1", "203.0.113.5"), KIND_SSH)
        self.assertEqual(_classify_utmp("tty1", ""), KIND_CONSOLE)
        self.assertEqual(_classify_utmp("tty2", "localhost"), KIND_CONSOLE)
        self.assertIn(_classify_utmp(":0", ":0"), (KIND_GUI, KIND_VNC))


if __name__ == "__main__":
    unittest.main()
