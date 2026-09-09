"""Filesystem locations used by the agent, per platform."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from . import SERVICE_NAME

IS_WINDOWS = os.name == "nt"
IS_LINUX = sys.platform.startswith("linux")

# Escape hatch for development / testing on a non-privileged machine.
_HOME_OVERRIDE = os.environ.get("SYSMON_AGENT_HOME")


def _home() -> "Path | None":
    return Path(_HOME_OVERRIDE).expanduser() if _HOME_OVERRIDE else None


def config_dir() -> Path:
    home = _home()
    if home:
        return home / "config"
    if IS_WINDOWS:
        return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / SERVICE_NAME
    return Path("/etc") / SERVICE_NAME


def state_dir() -> Path:
    home = _home()
    if home:
        return home / "state"
    if IS_WINDOWS:
        return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / SERVICE_NAME / "state"
    return Path("/var/lib") / SERVICE_NAME


def log_dir() -> Path:
    home = _home()
    if home:
        return home / "logs"
    if IS_WINDOWS:
        return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / SERVICE_NAME / "logs"
    return Path("/var/log") / SERVICE_NAME


def config_file() -> Path:
    return config_dir() / "config.json"


def log_file() -> Path:
    return log_dir() / "agent.log"


def ensure_dirs() -> None:
    for directory in (config_dir(), state_dir(), log_dir()):
        directory.mkdir(parents=True, exist_ok=True)
