"""Windows service management.

Preferred path: a real Windows service via pywin32, with Service Control
Manager failure actions so the SCM restarts the agent if it crashes.
Fallback (no pywin32): a SYSTEM scheduled task triggered at boot with
restart-on-failure, which gives the same behaviour without pywin32.
"""

from __future__ import annotations

import logging
import os
import sys
import tempfile
from pathlib import Path
from typing import List, Optional

from .. import SERVICE_DESCRIPTION, SERVICE_DISPLAY_NAME, SERVICE_NAME
from ..util import AgentError, agent_command, run

LOG = logging.getLogger("sysmon.service")

TASK_NAME = SERVICE_NAME
_SERVICE_CLASS = "sysmon_agent.winservice.SysmonAgentService"

# Restart after 5s, then 10s, then every 30s; never stop trying.
_FAILURE_ACTIONS = "restart/5000/restart/10000/restart/30000"


def pywin32_error() -> Optional[str]:
    """None when pywin32 is usable, otherwise why it is not.

    An installed pywin32 still fails to import when its post-install step never
    ran, because pywintypes cannot find its DLLs. That is a different problem
    from a missing package and needs a different fix, so report the real error.
    """
    try:
        import win32serviceutil  # noqa: F401
        import win32service  # noqa: F401
        import servicemanager  # noqa: F401
        return None
    except ImportError as exc:
        return str(exc)
    except Exception as exc:
        return "%s: %s" % (type(exc).__name__, exc)


def has_pywin32() -> bool:
    return pywin32_error() is None


def pywin32_hint(error: str) -> str:
    """Turn the import error into the command that fixes it."""
    python = str(Path(sys.executable).with_name("python.exe"))
    postinstall = str(Path(sys.executable).parent / "pywin32_postinstall.py")
    if "pywintypes" in error or "DLL" in error:
        return ('pywin32 is installed but its post-install step never ran. Fix it with:'
                '\n    "%s" "%s" -install' % (python, postinstall))
    return ('Install it into the agent environment with:'
            '\n    uv pip install --python "%s" pywin32' % python)


# ---------------------------------------------------------------- real service


def _install_service() -> None:
    import win32service
    import win32serviceutil

    python = str(Path(sys.executable).resolve())
    # pythonw.exe has no console and is the right host for a service.
    pythonw = Path(python).with_name("pythonw.exe")
    exe_name = str(pythonw) if pythonw.exists() else python

    try:
        win32serviceutil.InstallService(
            pythonClassString=_SERVICE_CLASS,
            serviceName=SERVICE_NAME,
            displayName=SERVICE_DISPLAY_NAME,
            startType=win32service.SERVICE_AUTO_START,
            description=SERVICE_DESCRIPTION,
            exeName=exe_name,
            exeArgs="-u -m sysmon_agent.winservice",
        )
    except Exception as exc:
        raise AgentError("Could not register the Windows service: %s" % exc)

    # Auto-restart on crash, and never give up (reset the failure count daily).
    run(["sc.exe", "failure", SERVICE_NAME, "reset=", "86400",
         "actions=", _FAILURE_ACTIONS])
    run(["sc.exe", "failureflag", SERVICE_NAME, "1"])
    run(["sc.exe", "start", SERVICE_NAME])


def _remove_service() -> List[str]:
    steps = []
    result = run(["sc.exe", "stop", SERVICE_NAME])
    if result.returncode == 0:
        steps.append("stopped service")
    result = run(["sc.exe", "delete", SERVICE_NAME])
    if result.returncode == 0:
        steps.append("deleted service")
    return steps


def _service_state() -> Optional[str]:
    result = run(["sc.exe", "query", SERVICE_NAME])
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        if "STATE" in line.upper():
            parts = line.split(":", 1)[-1].split()
            return parts[-1].lower() if parts else "unknown"
    return "unknown"


# -------------------------------------------------------------- scheduled task

_TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>{description}</Description>
    <URI>\\{name}</URI>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
      <Delay>PT30S</Delay>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>5</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{arguments}</Arguments>
    </Exec>
  </Actions>
</Task>
"""


def _install_task() -> None:
    command = agent_command("run")
    xml = _TASK_XML.format(
        description=SERVICE_DESCRIPTION,
        name=TASK_NAME,
        command=_escape(command[0]),
        arguments=_escape(" ".join(command[1:])),
    )
    handle, path = tempfile.mkstemp(suffix=".xml")
    os.close(handle)
    Path(path).write_text(xml, encoding="utf-16")
    try:
        result = run(["schtasks", "/Create", "/TN", TASK_NAME, "/XML", path, "/F"])
        if result.returncode != 0:
            raise AgentError("schtasks could not create the task: %s"
                             % (result.stderr or result.stdout).strip())
        run(["schtasks", "/Run", "/TN", TASK_NAME])
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _remove_task() -> List[str]:
    steps = []
    if run(["schtasks", "/End", "/TN", TASK_NAME]).returncode == 0:
        steps.append("stopped scheduled task")
    if run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"]).returncode == 0:
        steps.append("deleted scheduled task")
    return steps


def _task_state() -> Optional[str]:
    result = run(["schtasks", "/Query", "/TN", TASK_NAME, "/FO", "LIST"])
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        if line.lower().startswith("status"):
            return line.split(":", 1)[-1].strip().lower()
    return "unknown"


def _escape(value: str) -> str:
    return (value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


# ------------------------------------------------------------------- public API


def available() -> bool:
    return os.name == "nt"


def install() -> None:
    error = pywin32_error()
    if error is None:
        LOG.info("Installing Windows service via pywin32")
        _install_service()
        return
    LOG.warning("Cannot use a Windows service: %s", error)
    LOG.warning("%s", pywin32_hint(error))
    LOG.warning("Falling back to a SYSTEM scheduled task, which starts at boot "
                "and restarts on failure.")
    _install_task()


def remove() -> List[str]:
    steps = _remove_service()
    steps.extend(_remove_task())
    return steps


def _mode() -> Optional[str]:
    if _service_state() is not None:
        return "service"
    if _task_state() is not None:
        return "task"
    return None


def installed() -> bool:
    return _mode() is not None


def status() -> str:
    mode = _mode()
    if mode == "service":
        return "%s (Windows service, auto-start)" % _service_state()
    if mode == "task":
        return "%s (scheduled task, at boot)" % _task_state()
    return "not installed"


def detail() -> str:
    mode = _mode()
    if mode == "service":
        return run(["sc.exe", "qc", SERVICE_NAME]).stdout + \
            run(["sc.exe", "query", SERVICE_NAME]).stdout
    if mode == "task":
        return run(["schtasks", "/Query", "/TN", TASK_NAME, "/FO", "LIST", "/V"]).stdout
    return "not installed"


def restart() -> None:
    if _mode() == "service":
        run(["sc.exe", "stop", SERVICE_NAME])
        result = run(["sc.exe", "start", SERVICE_NAME])
        if result.returncode != 0:
            raise AgentError("sc start failed: %s" % result.stdout.strip())
        return
    run(["schtasks", "/End", "/TN", TASK_NAME])
    run(["schtasks", "/Run", "/TN", TASK_NAME])


def start() -> None:
    if _mode() == "service":
        run(["sc.exe", "start", SERVICE_NAME])
    else:
        run(["schtasks", "/Run", "/TN", TASK_NAME])


def stop() -> None:
    if _mode() == "service":
        run(["sc.exe", "stop", SERVICE_NAME])
    else:
        run(["schtasks", "/End", "/TN", TASK_NAME])
