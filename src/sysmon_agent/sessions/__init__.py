"""Login-session tracking, one implementation per platform."""

from __future__ import annotations

import logging

from ..paths import IS_WINDOWS
from .base import SessionTracker
from .model import Session

LOG = logging.getLogger("sysmon.sessions")


def build_tracker(poll_seconds: int = 5, on_event=None) -> SessionTracker:
    """Return the best session tracker for this platform."""
    if IS_WINDOWS:
        from .windows import build_tracker as _build
        return _build(poll_seconds, on_event)
    from .linux import build_tracker as _build
    return _build(poll_seconds, on_event)


__all__ = ["SessionTracker", "Session", "build_tracker"]
