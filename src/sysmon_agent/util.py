"""Small helpers shared across the package."""

from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from .paths import IS_WINDOWS


class AgentError(Exception):
    """User-facing error; the CLI prints it without a traceback."""


_TRACER = None


def set_tracer(tracer) -> None:
    """Trace subprocess calls. Only the agent sets this, and only when asked:
    the trackers shell out to loginctl / wevtutil / quser on every poll."""
    global _TRACER
    _TRACER = tracer


def run(cmd: Sequence[str], check: bool = False, timeout: int = 60) -> subprocess.CompletedProcess:
    """Run a command, capturing text output and never raising on decode issues."""
    if _TRACER is None:
        return _run(cmd, check, timeout)
    with _TRACER.start_as_current_span("exec %s" % Path(cmd[0]).name) as span:
        result = _run(cmd, check, timeout)
        span.set_attribute("process.executable.name", Path(cmd[0]).name)
        span.set_attribute("process.command_args", " ".join(map(str, cmd))[:200])
        span.set_attribute("process.exit_code", result.returncode)
        return result


def _run(cmd: Sequence[str], check: bool, timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(cmd),
        check=check,
        timeout=timeout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        errors="replace",
    )


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


def is_admin() -> bool:
    if IS_WINDOWS:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def require_admin(action: str) -> None:
    if is_admin():
        return
    if IS_WINDOWS:
        raise AgentError(
            "'%s' needs Administrator rights. "
            "Re-run this command from an elevated PowerShell or cmd window." % action
        )
    raise AgentError("'%s' needs root. Re-run with sudo." % action)


def path_exists(path: Path) -> bool:
    """Path.exists() raises PermissionError on Windows when the ACL denies stat."""
    try:
        return path.exists()
    except OSError:
        return False


def console_script() -> Optional[Path]:
    """Locate the installed 'sysmon-agent' console script, if there is one."""
    argv0 = sys.argv[0] if sys.argv else ""
    if argv0:
        candidate = Path(argv0).resolve()
        if candidate.stem.lower() == "sysmon-agent" and path_exists(candidate):
            return candidate
    bindir = Path(sys.executable).parent
    for name in ("sysmon-agent.exe", "sysmon-agent"):
        candidate = bindir / name
        if path_exists(candidate):
            return candidate.resolve()
    return None


def agent_command(subcommand: str = "run") -> List[str]:
    """The absolute command line a service manager should use to start the agent."""
    script = console_script()
    if script is not None:
        return [str(script), subcommand]
    return [str(Path(sys.executable).resolve()), "-m", "sysmon_agent", subcommand]


def human_bytes(value: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(value) < 1024.0:
            return "%.1f %s" % (value, unit)
        value /= 1024.0
    return "%.1f PiB" % value
