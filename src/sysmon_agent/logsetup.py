"""Local logging: rotating file plus stderr, independent of the OTLP pipeline."""

from __future__ import annotations

import json
import logging
import logging.handlers
import sys
import time
from typing import Any, Dict, Optional

from .config import Config
from .paths import log_file

_TEXT_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
_configured = False

# Everything the logging module puts on a record itself. Anything else came
# from an 'extra' dict, which is where the event attributes live.
_RESERVED = {
    "args", "asctime", "created", "exc_info", "exc_text", "filename", "funcName",
    "levelname", "levelno", "lineno", "module", "msecs", "msg", "message", "name",
    "pathname", "process", "processName", "relativeCreated", "stack_info",
    "taskName", "thread", "threadName",
}


class JsonFormatter(logging.Formatter):
    """One JSON object per record, with the event attributes flattened in.

    Attribute keys keep their dotted OTel names (`event.name`, `session.kind`,
    `client.address`), so a record read from the log file and the same record
    read from the collector carry identical field names.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "time": _iso(record.created),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key in _RESERVED or key.startswith("_") or key in payload:
                continue
            payload[key] = _plain(value)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


def _iso(epoch: float) -> str:
    base = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(epoch))
    return "%s.%03dZ" % (base, int((epoch % 1) * 1000))


def _plain(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def build_formatter(config: Optional[Config]) -> logging.Formatter:
    if config is not None and config.log_format == "text":
        return logging.Formatter(_TEXT_FORMAT)
    return JsonFormatter()


def configure(config: Optional[Config] = None, console: bool = True) -> None:
    """Attach handlers to the 'sysmon' logger tree. Safe to call twice."""
    global _configured
    if _configured:
        return

    level = getattr(logging, (config.log_level if config else "INFO").upper(), logging.INFO)
    logger = logging.getLogger("sysmon")
    logger.setLevel(level)
    logger.propagate = False
    formatter = build_formatter(config)

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
