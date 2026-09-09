"""Agent configuration: load, save, validate, redact."""

from __future__ import annotations

import base64
import json
import logging
import os
import socket
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from .paths import IS_WINDOWS, config_file
from .util import AgentError, run

_LOG = logging.getLogger("sysmon.config")

AUTH_NONE = "none"
AUTH_BEARER = "bearer"
AUTH_BASIC = "basic"
AUTH_HEADER = "header"
AUTH_TYPES = (AUTH_NONE, AUTH_BEARER, AUTH_BASIC, AUTH_HEADER)

LOG_FORMATS = ("json", "text")

_SECRET_KEYS = ("token", "password", "header_value",
                "webhook_token", "webhook_password", "webhook_header_value")


def auth_headers(auth_type: str, token: str, username: str, password: str,
                 header_name: str, header_value: str) -> Dict[str, str]:
    """The four supported schemes, shared by the OTLP exporters and the webhook."""
    if auth_type == AUTH_BEARER and token:
        return {"Authorization": "Bearer %s" % token}
    if auth_type == AUTH_BASIC and username:
        raw = ("%s:%s" % (username, password)).encode("utf-8")
        return {"Authorization": "Basic %s" % base64.b64encode(raw).decode("ascii")}
    if auth_type == AUTH_HEADER and header_name:
        return {header_name: header_value}
    return {}


@dataclass
class Config:
    endpoint: str = ""
    machine_name: str = field(default_factory=socket.gethostname)
    auth_type: str = AUTH_NONE
    token: str = ""
    username: str = ""
    password: str = ""
    header_name: str = ""
    header_value: str = ""
    metrics_interval_seconds: int = 30
    per_cpu_metrics: bool = True
    traces_enabled: bool = True
    trace_polls: bool = False
    heartbeat_seconds: int = 300
    webhook_url: str = ""
    webhook_auth_type: str = AUTH_NONE
    webhook_token: str = ""
    webhook_username: str = ""
    webhook_password: str = ""
    webhook_header_name: str = ""
    webhook_header_value: str = ""
    webhook_timeout_seconds: int = 10
    webhook_verify_tls: bool = True
    session_poll_seconds: int = 5
    export_timeout_seconds: int = 15
    verify_tls: bool = True
    ca_bundle: str = ""
    log_level: str = "INFO"
    log_format: str = "json"
    log_max_bytes: int = 10 * 1024 * 1024
    log_backup_count: int = 5
    environment: str = ""
    extra_attributes: Dict[str, str] = field(default_factory=dict)

    # ---------------------------------------------------------------- helpers

    def headers(self) -> Dict[str, str]:
        """Headers attached to every OTLP request."""
        return auth_headers(self.auth_type, self.token, self.username,
                            self.password, self.header_name, self.header_value)

    def webhook_headers(self) -> Dict[str, str]:
        """Headers attached to every webhook POST; same schemes as OTLP."""
        return auth_headers(self.webhook_auth_type, self.webhook_token,
                            self.webhook_username, self.webhook_password,
                            self.webhook_header_name, self.webhook_header_value)

    def webhook_enabled(self) -> bool:
        return bool(self.webhook_url)

    def webhook_tls_verify(self) -> Any:
        if not self.webhook_verify_tls:
            return False
        return self.ca_bundle or True

    def signal_endpoint(self, signal: str) -> str:
        """Full OTLP/HTTP URL for 'metrics' or 'logs'."""
        base = self.endpoint.strip().rstrip("/")
        if base.endswith("/v1/%s" % signal):
            return base
        if base.endswith("/v1"):
            return "%s/%s" % (base, signal)
        return "%s/v1/%s" % (base, signal)

    def tls_verify(self) -> Any:
        if not self.verify_tls:
            return False
        return self.ca_bundle or True

    def validate(self) -> None:
        if not self.endpoint:
            raise AgentError("No OTLP endpoint configured. Run 'sysmon-agent install' first.")
        if not self.endpoint.startswith(("http://", "https://")):
            raise AgentError(
                "OTLP endpoint must start with http:// or https:// (got %r)." % self.endpoint
            )
        if self.auth_type not in AUTH_TYPES:
            raise AgentError("Unknown auth type %r; expected one of %s."
                             % (self.auth_type, ", ".join(AUTH_TYPES)))
        if self.auth_type == AUTH_BEARER and not self.token:
            raise AgentError("Bearer auth selected but no token is set.")
        if self.auth_type == AUTH_BASIC and not self.username:
            raise AgentError("Basic auth selected but no username is set.")
        if self.auth_type == AUTH_HEADER and not self.header_name:
            raise AgentError("Custom header auth selected but no header name is set.")
        if not self.machine_name:
            raise AgentError("Machine name must not be empty.")
        if self.metrics_interval_seconds < 1:
            raise AgentError("Metrics interval must be at least 1 second.")
        if self.session_poll_seconds < 1:
            raise AgentError("Session poll interval must be at least 1 second.")
        if self.heartbeat_seconds < 10:
            raise AgentError("Heartbeat interval must be at least 10 seconds.")
        if self.webhook_url:
            if not self.webhook_url.startswith(("http://", "https://")):
                raise AgentError("Webhook URL must start with http:// or https:// "
                                 "(got %r)." % self.webhook_url)
            if self.webhook_auth_type not in AUTH_TYPES:
                raise AgentError("Unknown webhook auth type %r; expected one of %s."
                                 % (self.webhook_auth_type, ", ".join(AUTH_TYPES)))
            if self.webhook_auth_type == AUTH_BEARER and not self.webhook_token:
                raise AgentError("Webhook bearer auth selected but no token is set.")
            if self.webhook_auth_type == AUTH_BASIC and not self.webhook_username:
                raise AgentError("Webhook basic auth selected but no username is set.")
            if self.webhook_auth_type == AUTH_HEADER and not self.webhook_header_name:
                raise AgentError("Webhook custom header auth selected but no header "
                                 "name is set.")
            if self.webhook_timeout_seconds < 1:
                raise AgentError("Webhook timeout must be at least 1 second.")
        if self.log_format not in LOG_FORMATS:
            raise AgentError("Unknown log format %r; expected one of %s."
                             % (self.log_format, ", ".join(LOG_FORMATS)))
        if self.ca_bundle and not Path(self.ca_bundle).exists():
            raise AgentError("CA bundle not found: %s" % self.ca_bundle)

    def redacted(self) -> Dict[str, Any]:
        data = asdict(self)
        for key in _SECRET_KEYS:
            if data.get(key):
                data[key] = "***redacted***"
        return data

    # ------------------------------------------------------------ persistence

    def save(self, path: Optional[Path] = None) -> Path:
        target = path or config_file()
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(self), indent=2, sort_keys=True), encoding="utf-8")
        os.replace(str(tmp), str(target))
        _restrict_permissions(target)
        return target

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "Config":
        target = path or config_file()
        if not target.exists():
            raise AgentError(
                "Config not found at %s. Run 'sysmon-agent install' first." % target
            )
        try:
            raw = json.loads(target.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise AgentError("Config at %s is not valid JSON: %s" % (target, exc))
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in raw.items() if k in known})

    @classmethod
    def exists(cls, path: Optional[Path] = None) -> bool:
        return (path or config_file()).exists()


def _restrict_permissions(target: Path) -> None:
    """Lock down the config FILE; it holds collector credentials.

    Only the file. The directory is deliberately left alone: on Windows it also
    holds the agent's virtual environment, and stripping inheritance there once
    locked Administrators out of the whole install.
    """
    if not IS_WINDOWS:
        try:
            os.chmod(str(target), 0o600)
        except OSError as exc:
            _LOG.warning("Could not chmod %s: %s", target, exc)
        return

    # Well-known SIDs, because the group names are localised: S-1-5-18 is
    # LocalSystem and S-1-5-32-544 is the built-in Administrators group.
    result = run(["icacls", str(target), "/inheritance:r",
                  "/grant:r", "*S-1-5-18:F", "/grant:r", "*S-1-5-32-544:F"])
    if result.returncode != 0:
        # Put inheritance back rather than leave a file nobody can open.
        run(["icacls", str(target), "/inheritance:e"])
        _LOG.warning(
            "Could not restrict permissions on %s (icacls: %s). The file keeps "
            "its inherited permissions; review who can read it.",
            target, (result.stderr or result.stdout).strip()[:200])
