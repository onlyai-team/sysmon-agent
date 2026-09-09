"""OpenTelemetry wiring: resource, metric provider, logger provider, OTLP/HTTP export."""

from __future__ import annotations

import logging
import platform
import socket
from typing import Optional, Tuple

import requests
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource

from . import SERVICE_NAME, __version__
from .config import Config

LOG = logging.getLogger("sysmon.telemetry")


def build_resource(config: Config) -> Resource:
    attributes = {
        "service.name": SERVICE_NAME,
        "service.version": __version__,
        "service.instance.id": config.machine_name,
        "host.name": config.machine_name,
        "host.arch": platform.machine(),
        "os.type": _os_type(),
        "os.description": platform.platform(),
        "os.version": platform.release(),
        "telemetry.sdk.language": "python",
    }
    fqdn = socket.getfqdn()
    if fqdn and fqdn != config.machine_name:
        attributes["host.fqdn"] = fqdn
    if config.environment:
        attributes["deployment.environment"] = config.environment
    for key, value in (config.extra_attributes or {}).items():
        attributes[str(key)] = str(value)
    return Resource.create(attributes)


def _os_type() -> str:
    system = platform.system().lower()
    return {"darwin": "darwin", "windows": "windows", "linux": "linux"}.get(system, system)


def _session(config: Config) -> Optional[requests.Session]:
    """A requests session honouring the TLS settings, when the exporter accepts one."""
    verify = config.tls_verify()
    if verify is True:
        return None
    session = requests.Session()
    session.verify = verify
    if verify is False:
        try:  # noisy per-request warnings are useless in a background service
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass
    return session


def _exporter(cls, endpoint: str, config: Config):
    kwargs = {
        "endpoint": endpoint,
        "headers": config.headers(),
        "timeout": config.export_timeout_seconds,
    }
    if config.ca_bundle:
        kwargs["certificate_file"] = config.ca_bundle
    session = _session(config)
    if session is not None:
        try:
            return cls(session=session, **kwargs)
        except TypeError:
            # Older exporters have no 'session' argument; fall back and warn.
            LOG.warning("Installed OTLP exporter ignores custom TLS settings.")
    return cls(**kwargs)


class Telemetry:
    """Owns the SDK providers and shuts them down cleanly."""

    def __init__(self, config: Config):
        self.config = config
        self.resource = build_resource(config)
        self.meter_provider: Optional[MeterProvider] = None
        self.logger_provider: Optional[LoggerProvider] = None
        self._otel_handler: Optional[LoggingHandler] = None

    def start(self) -> Tuple[MeterProvider, LoggerProvider]:
        metric_exporter = _exporter(
            OTLPMetricExporter, self.config.signal_endpoint("metrics"), self.config
        )
        reader = PeriodicExportingMetricReader(
            metric_exporter,
            export_interval_millis=self.config.metrics_interval_seconds * 1000,
            export_timeout_millis=self.config.export_timeout_seconds * 1000,
        )
        self.meter_provider = MeterProvider(resource=self.resource, metric_readers=[reader])

        log_exporter = _exporter(
            OTLPLogExporter, self.config.signal_endpoint("logs"), self.config
        )
        self.logger_provider = LoggerProvider(resource=self.resource)
        self.logger_provider.add_log_record_processor(BatchLogRecordProcessor(log_exporter))

        # Only the agent's own loggers are exported, so exporter errors can never
        # feed back into the export pipeline.
        self._otel_handler = LoggingHandler(
            level=logging.INFO, logger_provider=self.logger_provider
        )
        logging.getLogger("sysmon").addHandler(self._otel_handler)
        return self.meter_provider, self.logger_provider

    def meter(self, name: str = "sysmon-agent"):
        assert self.meter_provider is not None, "Telemetry.start() was not called"
        return self.meter_provider.get_meter(name, __version__)

    def flush(self) -> None:
        for provider in (self.meter_provider, self.logger_provider):
            try:
                if provider is not None:
                    provider.force_flush(timeout_millis=self.config.export_timeout_seconds * 1000)
            except Exception as exc:
                LOG.warning("Flush failed: %s", exc)

    def shutdown(self) -> None:
        if self._otel_handler is not None:
            try:
                logging.getLogger("sysmon").removeHandler(self._otel_handler)
            except Exception:
                pass
        for provider in (self.meter_provider, self.logger_provider):
            try:
                if provider is not None:
                    provider.shutdown()
            except Exception as exc:
                LOG.warning("Shutdown failed: %s", exc)


def check_endpoint(config: Config) -> Tuple[bool, str]:
    """POST an empty OTLP metrics payload to prove the collector is reachable."""
    url = config.signal_endpoint("metrics")
    headers = {"Content-Type": "application/x-protobuf"}
    headers.update(config.headers())
    try:
        response = requests.post(
            url,
            data=b"",
            headers=headers,
            timeout=config.export_timeout_seconds,
            verify=config.tls_verify(),
        )
    except requests.exceptions.SSLError as exc:
        return False, "TLS error talking to %s: %s" % (url, exc)
    except requests.exceptions.RequestException as exc:
        return False, "Cannot reach %s: %s" % (url, exc)
    if response.status_code in (200, 202, 204, 400, 415):
        # 400/415 mean the collector answered and rejected the empty body: reachable.
        return True, "Collector answered at %s (HTTP %d)." % (url, response.status_code)
    if response.status_code in (401, 403):
        return False, "Collector rejected the credentials at %s (HTTP %d)." % (
            url, response.status_code)
    if response.status_code == 404:
        return False, "No OTLP receiver at %s (HTTP 404). Check the endpoint path." % url
    return False, "Unexpected reply from %s: HTTP %d %s" % (
        url, response.status_code, response.text[:200])
