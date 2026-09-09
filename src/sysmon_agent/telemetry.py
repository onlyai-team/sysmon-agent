"""OpenTelemetry wiring: resource, metric provider, logger provider, OTLP/HTTP export."""

from __future__ import annotations

import logging
import platform
import socket
from typing import Optional, Tuple

import requests
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

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
        self.tracer_provider: Optional[TracerProvider] = None
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
        # LoggingHandler renders the body through its formatter when one is set,
        # so in json mode the exported body is the same object the log file has.
        from .logsetup import build_formatter

        self._otel_handler.setFormatter(build_formatter(self.config))
        logging.getLogger("sysmon").addHandler(self._otel_handler)

        if self.config.traces_enabled:
            span_exporter = _exporter(
                OTLPSpanExporter, self.config.signal_endpoint("traces"), self.config
            )
            self.tracer_provider = TracerProvider(resource=self.resource)
            self.tracer_provider.add_span_processor(BatchSpanProcessor(span_exporter))
            # Deliberately not set as the global provider: nothing else in this
            # process should pick up tracing by accident.

        return self.meter_provider, self.logger_provider

    def meter(self, name: str = "sysmon-agent"):
        assert self.meter_provider is not None, "Telemetry.start() was not called"
        return self.meter_provider.get_meter(name, __version__)

    def tracer(self, name: str = "sysmon-agent"):
        """None when tracing is switched off, so callers guard on it."""
        if self.tracer_provider is None:
            return None
        return self.tracer_provider.get_tracer(name, __version__)

    def flush(self) -> None:
        for provider in (self.tracer_provider, self.meter_provider, self.logger_provider):
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
        for provider in (self.tracer_provider, self.meter_provider, self.logger_provider):
            try:
                if provider is not None:
                    provider.shutdown()
            except Exception as exc:
                LOG.warning("Shutdown failed: %s", exc)


def check_endpoint(config: Config) -> Tuple[bool, str]:
    """Probe every signal the agent will send, so a collector that only accepts
    some of them is found now rather than after the service is running."""
    signals = ["metrics", "logs"]
    if config.traces_enabled:
        signals.append("traces")
    lines = []
    ok = True
    for signal in signals:
        reachable, message = _check_signal(config, signal)
        ok = ok and reachable
        lines.append("%-8s %s" % (signal + ":", message))
    return ok, "\n  ".join(lines)


def _check_signal(config: Config, signal: str) -> Tuple[bool, str]:
    url = config.signal_endpoint(signal)
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
        return False, "cannot reach %s: %s" % (url, exc)
    if response.status_code in (200, 202, 204, 400, 415):
        # 400/415 mean the collector answered and rejected the empty body: reachable.
        return True, "%s answered (HTTP %d)" % (url, response.status_code)
    if response.status_code in (401, 403):
        return False, "%s rejected the credentials (HTTP %d)" % (url, response.status_code)
    if response.status_code == 404:
        return False, "no OTLP receiver at %s (HTTP 404)" % url
    return False, "unexpected reply from %s: HTTP %d %s" % (
        url, response.status_code, response.text[:200])


class _RecordingExporter:
    """Wraps an exporter so a one-off send can report what the collector said."""

    def __init__(self, inner):
        self.inner = inner
        self.results = []

    def export(self, batch):
        result = self.inner.export(batch)
        self.results.append(result)
        return result

    def shutdown(self):
        return self.inner.shutdown()

    def force_flush(self, timeout_millis: int = 30000):
        return True

    def ok(self) -> bool:
        return bool(self.results) and all(
            str(result).endswith("SUCCESS") for result in self.results)


def send_test_telemetry(config: Config):
    """Send one span and one log record for real. Returns [(signal, ok, detail)].

    An empty POST proves the route exists; this proves the exporters, the
    credentials and the payload encoding all work end to end.
    """
    from opentelemetry.sdk._logs.export import SimpleLogRecordProcessor
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor

    resource = build_resource(config)
    results = []

    if config.traces_enabled:
        exporter = _RecordingExporter(
            _exporter(OTLPSpanExporter, config.signal_endpoint("traces"), config))
        provider = TracerProvider(resource=resource)
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        with provider.get_tracer("sysmon.test").start_as_current_span(
                "agent.test") as span:
            span.set_attribute("agent.version", __version__)
            span.set_attribute("test", True)
        provider.shutdown()
        results.append(("traces", exporter.ok(),
                        "one span named 'agent.test' -> %s"
                        % config.signal_endpoint("traces")))
    else:
        results.append(("traces", True, "disabled in the configuration"))

    log_exporter = _RecordingExporter(
        _exporter(OTLPLogExporter, config.signal_endpoint("logs"), config))
    log_provider = LoggerProvider(resource=resource)
    log_provider.add_log_record_processor(SimpleLogRecordProcessor(log_exporter))
    handler = LoggingHandler(level=logging.INFO, logger_provider=log_provider)
    from .logsetup import build_formatter

    handler.setFormatter(build_formatter(config))
    logger = logging.getLogger("sysmon.test")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(handler)
    try:
        logger.info("sysmon-agent connectivity test",
                    extra={"event.name": "agent.test", "test": True})
    finally:
        logger.removeHandler(handler)
    log_provider.shutdown()
    results.append(("logs", log_exporter.ok(),
                    "one log record -> %s" % config.signal_endpoint("logs")))

    return results
