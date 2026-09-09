"""Windows service entry point, hosted by python.exe / pythonw.exe.

The Service Control Manager launches this module with no arguments; it then
hands control to pywin32's dispatcher. Running it with arguments falls through
to pywin32's own install/remove/start command line, which is handy for debugging.
"""

from __future__ import annotations

import sys
import threading

from . import SERVICE_DESCRIPTION, SERVICE_DISPLAY_NAME, SERVICE_NAME


class SysmonAgentService:  # pragma: no cover - replaced below when pywin32 exists
    pass


try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil

    class SysmonAgentService(win32serviceutil.ServiceFramework):  # type: ignore[no-redef]
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self._wait_handle = win32event.CreateEvent(None, 0, 0, None)
            self._stop = threading.Event()
            self._agent = None

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self._stop.set()
            win32event.SetEvent(self._wait_handle)

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            try:
                self._run()
            except Exception as exc:  # surface startup failures in the Event Log
                servicemanager.LogErrorMsg("sysmon-agent failed: %r" % (exc,))
                raise

        def _run(self):
            from .agent import Agent
            from .config import Config
            from .logsetup import configure

            config = Config.load()
            configure(config, console=False)
            self._agent = Agent(config)
            self._agent.run(stop_event=self._stop)

except ImportError:  # pywin32 absent: the scheduled-task fallback is used instead
    servicemanager = None  # type: ignore[assignment]


def main() -> int:
    if servicemanager is None:
        print("pywin32 is not installed; this entry point needs it.", file=sys.stderr)
        return 1
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(SysmonAgentService)
        servicemanager.StartServiceCtrlDispatcher()
        return 0
    win32serviceutil.HandleCommandLine(SysmonAgentService)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
