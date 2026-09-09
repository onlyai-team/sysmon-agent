"""Local logging: rotating file plus stderr, independent of the OTLP pipeline."""

from __future__ import annotations

import logging
import logging.handlers
import sys
from typing import Optional

from .config import Config
from .paths import log_file

_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
_configured = False


def configure(config: Optional[Config] = None, console: bool = True) -> None:
    """Attach handlers to the 'sysmon' logger tree. Safe to call twice."""
    global _configured
    if _configured:
        return

    level = getattr(logging, (config.log_level if config else "INFO").upper(), logging.INFO)
    logger = logging.getLogger("sysmon")
    logger.setLevel(level)
    logger.propagate = False
    formatter = logging.Formatter(_FORMAT)

    try:
        path = log_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            str(path),
            maxBytes=config.log_max_bytes if config else 10 * 1024 * 1024,
            backupCount=config.log_backup_count if config else 5,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except (OSError, PermissionError) as exc:
        print("sysmon-agent: cannot write log file: %s" % exc, file=sys.stderr)

    if console:
        stream = logging.StreamHandler(sys.stderr)
        stream.setFormatter(formatter)
        logger.addHandler(stream)

    # The OTLP exporter is chatty on transient failures; keep it at WARNING and
    # out of the 'sysmon' tree so its errors are never re-exported.
    logging.getLogger("opentelemetry").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    _configured = True
