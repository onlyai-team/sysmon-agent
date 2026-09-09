"""Windows Security / TerminalServices event parsing.

These run on any OS: the XML samples below are verbatim shapes emitted by
wevtutil on Windows Server 2019 / Windows 11.
"""

import unittest

from sysmon_agent.sessions import windows as win
from sysmon_agent.sessions.model import KIND_CONSOLE, KIND_RDP, KIND_REMOTE, KIND_VNC

NS = 'http://schemas.microsoft.com/win/2004/08/events/event'


def security_event(event_id, record_id, **data):
    fields = "".join('<Data Name="%s">%s</Data>' % (k, v) for k, v in data.items())
    return (
        '<Event xmlns="%s"><System><Provider Name="Microsoft-Windows-Security-Auditing"/>'
        '<EventID>%d</EventID><Channel>Security</Channel>'
        '<TimeCreated SystemTime="2026-09-09T03:15:42.1234567Z"/>'
        '<EventRecordID>%d</EventRecordID></System>'
        '<EventData>%s</EventData></Event>' % (NS, event_id, record_id, fields)
    )


def ts_event(event_id, record_id, user, session_id, address):
    return (
        '<Event xmlns="%s"><System><Provider Name="Microsoft-Windows-TerminalServices-'
        'LocalSessionManager"/><EventID>%d</EventID>'
        '<Channel>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</Channel>'
        '<TimeCreated SystemTime="2026-09-09T03:16:00.0000000Z"/>'
        '<EventRecordID>%d</EventRecordID></System>'
        '<UserData><EventXML xmlns="Event_NS"><User>%s</User><SessionID>%s</SessionID>'
        '<Address>%s</Address></EventXML></UserData></Event>'
        % (NS, event_id, record_id, user, session_id, address)
    )


LOGON_RDP = dict(
    TargetUserName="alice", TargetDomainName="CORP", TargetLogonId="0x4a1b2",
    LogonType="10", IpAddress="203.0.113.9", IpPort="51344",
    WorkstationName="ALICE-LT", LogonProcessName="User32", ProcessName="C:\\Windows\\System32\\svchost.exe")
LOGON_CONSOLE = dict(
    TargetUserName="bob", TargetDomainName="WORKSTATION", TargetLogonId="0x7c3d1",
    LogonType="2", IpAddress="-", WorkstationName="WORKSTATION",
    LogonProcessName="User32", ProcessName="C:\\Windows\\System32\\winlogon.exe")
LOGON_SERVICE = dict(
    TargetUserName="svc-backup", TargetDomainName="CORP", TargetLogonId="0x9911",
    LogonType="5", IpAddress="-", LogonProcessName="Advapi", ProcessName="services.exe")
LOGON_MACHINE = dict(
    TargetUserName="WORKSTATION$", TargetDomainName="CORP", TargetLogonId="0x3e7",
    LogonType="2", IpAddress="-", LogonProcessName="User32", ProcessName="winlogon.exe")
LOGON_VNC = dict(
    TargetUserName="carol", TargetDomainName="WORKSTATION", TargetLogonId="0x5f00a",
    LogonType="2", IpAddress="198.51.100.7", LogonProcessName="Advapi",
    ProcessName="C:\\Program Files\\TightVNC\\tvnserver.exe")


class ParseTests(unittest.TestCase):
    def test_parses_id_record_and_data(self):
        events = win._parse_events(security_event(4624, 501, **LOGON_RDP))
        self.assertEqual(len(events), 1)
        record_id, event_id, when, data = events[0]
        self.assertEqual(event_id, 4624)
        self.assertEqual(record_id, "Security:501")
        self.assertEqual(data["TargetUserName"], "alice")
        self.assertEqual(data["IpAddress"], "203.0.113.9")
        self.assertIsNotNone(when)

    def test_reverses_into_chronological_order(self):
        # wevtutil /rd:true returns newest first.
        xml = security_event(4624, 9, **LOGON_RDP) + security_event(4624, 8, **LOGON_CONSOLE)
        events = win._parse_events(xml)
        self.assertEqual([e[0] for e in events], ["Security:8", "Security:9"])

    def test_reads_userdata_from_terminalservices(self):
        events = win._parse_events(ts_event(25, 77, "CORP\\alice", "3", "203.0.113.9"))
        _, event_id, _, data = events[0]
        self.assertEqual(event_id, 25)
        self.assertEqual(data["User"], "CORP\\alice")
        self.assertEqual(data["Address"], "203.0.113.9")

    def test_empty_and_broken_input(self):
        self.assertEqual(win._parse_events(""), [])
        self.assertEqual(win._parse_events("<Event><oops"), [])

    def test_system_time_is_utc(self):
        events = win._parse_events(security_event(4624, 1, **LOGON_RDP))
        # 2026-09-09T03:15:42Z
        self.assertEqual(int(events[0][2]), 1788923742)


class ClassifyTests(unittest.TestCase):
    def test_logon_types(self):
        self.assertEqual(win._classify("10", "User32", "203.0.113.9"), KIND_RDP)
        self.assertEqual(win._classify("2", "winlogon.exe", "-"), KIND_CONSOLE)
        self.assertEqual(win._classify("7", "winlogon.exe", ""), KIND_CONSOLE)
        self.assertEqual(win._classify("11", "winlogon.exe", ""), KIND_CONSOLE)

    def test_service_batch_and_network_are_ignored(self):
        for logon_type in ("3", "4", "5", "8", "9"):
            self.assertIsNone(win._classify(logon_type, "services.exe", "-"))

    def test_vnc_process_wins(self):
        self.assertEqual(win._classify("2", "tvnserver.exe", "198.51.100.7"), KIND_VNC)
        self.assertEqual(win._classify("3", "winvnc.exe", "198.51.100.7"), KIND_VNC)

    def test_interactive_logon_with_remote_address_is_remote(self):
        self.assertEqual(win._classify("2", "Advapi", "198.51.100.7"), KIND_REMOTE)

    def test_noise_accounts(self):
        for account in ("SYSTEM", "WORKSTATION$", "DWM-1", "UMFD-0", "ANONYMOUS LOGON", "-", ""):
            self.assertTrue(win._is_noise(account), account)
        for account in ("alice", "bob.smith", "svc-backup"):
            self.assertFalse(win._is_noise(account), account)

    def test_local_addresses_are_dropped(self):
        for address in ("-", "::1", "127.0.0.1", "0.0.0.0", ""):
            self.assertEqual(win._clean_address(address), "")
        self.assertEqual(win._clean_address("203.0.113.9"), "203.0.113.9")


class TrackerStateTests(unittest.TestCase):
    def setUp(self):
        self.tracker = win.WindowsSessionTracker(poll_seconds=1)

    def feed(self, xml):
        for record_id, event_id, when, data in win._parse_events(xml):
            if not self.tracker._first_time(record_id):
                continue
            if event_id in win._LOGON_EVENTS:
                self.tracker._handle_logon(data, when)
            else:
                self.tracker._handle_logoff(data)

    def sessions(self):
        return self.tracker._sessions_by_logon

    def test_logon_then_logoff(self):
        self.feed(security_event(4624, 1, **LOGON_RDP))
        self.assertIn("0x4a1b2", self.sessions())
        session = self.sessions()["0x4a1b2"]
        self.assertEqual(session.kind, KIND_RDP)
        self.assertEqual(session.user, "CORP\\alice")
        self.assertEqual(session.remote_host, "203.0.113.9")
        self.assertIn("RemoteInteractive", session.logon_type)

        self.feed(security_event(4634, 2, TargetUserName="alice",
                                 TargetDomainName="CORP", TargetLogonId="0x4a1b2",
                                 LogonType="10"))
        self.assertNotIn("0x4a1b2", self.sessions())

    def test_user_initiated_logoff_4647(self):
        self.feed(security_event(4624, 3, **LOGON_CONSOLE))
        self.assertIn("0x7c3d1", self.sessions())
        self.feed(security_event(4647, 4, TargetUserName="bob",
                                 TargetLogonId="0x7c3d1"))
        self.assertNotIn("0x7c3d1", self.sessions())

    def test_service_and_machine_logons_are_skipped(self):
        self.feed(security_event(4624, 5, **LOGON_SERVICE))
        self.feed(security_event(4624, 6, **LOGON_MACHINE))
        self.assertEqual(self.sessions(), {})

    def test_duplicate_records_are_ignored(self):
        xml = security_event(4624, 7, **LOGON_RDP)
        self.feed(xml)
        self.feed(xml)  # overlapping poll window replays the same record
        self.assertEqual(len(self.sessions()), 1)

    def test_vnc_logon_classified(self):
        self.feed(security_event(4624, 8, **LOGON_VNC))
        self.assertEqual(self.sessions()["0x5f00a"].kind, KIND_VNC)

    def test_seen_record_cache_is_bounded(self):
        for index in range(6000):
            self.tracker._first_time("Security:%d" % index)
        self.assertLessEqual(len(self.tracker._seen_records), 5000)


class QuserTests(unittest.TestCase):
    SAMPLE = (
        " USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME\n"
        ">administrator         console             1  Active      none   9/9/2026 8:02 AM\n"
        " alice                 rdp-tcp#3           2  Active        12   9/9/2026 9:41 AM\n"
        " bob                                       3  Disc          45   9/9/2026 7:10 AM\n"
    )

    def test_parses_all_rows(self):
        rows = [win._QUSER_RE.match(line).groupdict()
                for line in self.SAMPLE.splitlines()[1:]]
        self.assertEqual([r["user"] for r in rows], ["administrator", "alice", "bob"])
        self.assertEqual([r["id"] for r in rows], ["1", "2", "3"])
        self.assertEqual(rows[1]["sessionname"], "rdp-tcp#3")
        self.assertEqual(rows[2]["state"], "Disc")


if __name__ == "__main__":
    unittest.main()
