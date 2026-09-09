"""POST session enter/exit events to a webhook.

Only two things happen in a session's life as far as a notifier is concerned:
somebody comes in, somebody goes out. An RDP reconnect is somebody coming in
again, and a disconnect is them leaving, even though the session itself lives on.

The payload is the JSON log record the collector receives, plus an `action`
field and the resource attributes, so a consumer can treat webhook deliveries
and OTLP log records identically.
"""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
from typing import Any, Dict, List, Optional

import requests

from . import __version__
from .config import Config

LOG = logging.getLogger("sysmon.webhook")

ACTION_ENTER = "enter"
ACTION_EXIT = "exit"

# An agent restart re-observes sessions that were already open; nobody entered
# anything, so those must not reach the webhook.
ENTER_EVENTS = ("session.start", "rdp.reconnected")
EXIT_EVENTS = ("session.end", "rdp.disconnected")

_QUEUE_LIMIT = 1000
_ATTEMPTS = 3
_BACKOFF_SECONDS = (1, 3)


def action_for(event_name: str) -> Optional[str]:
    """enter, exit, or None for an event the webhook does not care about."""
    if event_name in ENTER_EVENTS:
        return ACTION_ENTER
    if event_name in EXIT_EVENTS:
        return ACTION_EXIT
    return None


def build_payload(action: str, attributes: Dict[str, Any], message: str,
                  resource: Dict[str, Any]) -> Dict[str, Any]:
    """Same field names as the JSON log body, plus action and resource."""
    payload: Dict[str, Any] = {
        "time": _now_iso(),
        "action": action,
        "message": message,
        "logger": "sysmon.events",
        "level": "INFO",
    }
    for key, value in attributes.items():
        payload[key] = value if isinstance(value, (str, int, float, bool)) else str(value)
    payload["resource"] = resource
    return payload


def _now_iso() -> str:
    now = time.time()
    base = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now))
    return "%s.%03dZ" % (base, int((now % 1) * 1000))


class WebhookNotifier:
    """Delivers on a worker thread; a slow endpoint never stalls session polling."""

    def __init__(self, config: Config, resource: Optional[Dict[str, Any]] = None):
        self.config = config
        self.resource = resource or {}
        self._queue: "queue.Queue" = queue.Queue(maxsize=_QUEUE_LIMIT)
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._session: Optional[requests.Session] = None
        self.delivered = 0
        self.failed = 0
        self.dropped = 0

    # ------------------------------------------------------------- lifecycle

    def start(self) -> None:
        if not self.config.webhook_enabled():
            return
        self._session = requests.Session()
        self._session.verify = self.config.webhook_tls_verify()
        self._thread = threading.Thread(target=self._run, name="webhook", daemon=True)
        self._thread.start()
        LOG.info("Webhook enabled: session enter/exit -> %s", self.config.webhook_url)

    def stop(self, timeout: float = 10.0) -> None:
        if self._thread is None:
            return
        self._stop.set()
        self._queue.put(None)  # wake the worker
        self._thread.join(timeout=timeout)
        if self._session is not None:
            self._session.close()
        LOG.info("Webhook stopped: %d delivered, %d failed, %d dropped",
                 self.delivered, self.failed, self.dropped)

    # ---------------------------------------------------------------- input

    def notify(self, event_name: str, message: str,
               attributes: Dict[str, Any]) -> bool:
        """Queue an event if it is an enter or an exit. Never blocks, never raises."""
        if self._thread is None:
            return False
        action = action_for(event_name)
        if action is None:
            return False
        payload = build_payload(action, attributes, message, self.resource)
        try:
            self._queue.put_nowait(payload)
            return True
        except queue.Full:
            self.dropped += 1
            LOG.warning("Webhook queue is full (%d pending); dropped a %s event.",
                        _QUEUE_LIMIT, event_name)
            return False

    # --------------------------------------------------------------- worker

    def _run(self) -> None:
        while True:
            try:
                payload = self._queue.get()
            except Exception:
                return
            if payload is None:
                # Drain whatever is still queued before shutting down.
                self._drain()
                return
            self._deliver(payload)

    def _drain(self) -> None:
        while True:
            try:
                payload = self._queue.get_nowait()
            except queue.Empty:
                return
            if payload is not None:
                self._deliver(payload)

    def _deliver(self, payload: Dict[str, Any]) -> bool:
        headers = {"Content-Type": "application/json",
                   "User-Agent": "sysmon-agent/%s" % __version__}
        headers.update(self.config.webhook_headers())
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")

        for attempt in range(_ATTEMPTS):
            try:
                response = self._session.post(
                    self.config.webhook_url,
                    data=body,
                    headers=headers,
                    timeout=self.config.webhook_timeout_seconds,
                )
                if 200 <= response.status_code < 300:
                    self.delivered += 1
                    return True
                if 400 <= response.status_code < 500 and response.status_code != 429:
                    # The endpoint rejected the payload; retrying sends the same one.
                    self.failed += 1
                    LOG.error("Webhook rejected a session %s event: HTTP %d %s",
                              payload.get("action"), response.status_code,
                              response.text[:200])
                    return False
                LOG.warning("Webhook returned HTTP %d (attempt %d/%d)",
                            response.status_code, attempt + 1, _ATTEMPTS)
            except requests.exceptions.RequestException as exc:
                LOG.warning("Webhook POST failed (attempt %d/%d): %s",
                            attempt + 1, _ATTEMPTS, exc)
            if attempt < len(_BACKOFF_SECONDS):
                if self._stop.wait(_BACKOFF_SECONDS[attempt]):
                    break  # shutting down: do not keep retrying
        self.failed += 1
        LOG.error("Giving up on a session %s webhook event after %d attempts",
                  payload.get("action"), _ATTEMPTS)
        return False


def send_test_webhook(config: Config, resource: Optional[Dict[str, Any]] = None):
    """One synthetic enter event, for 'sysmon-agent test --send'."""
    notifier = WebhookNotifier(config, resource)
    notifier._session = requests.Session()
    notifier._session.verify = config.webhook_tls_verify()
    payload = build_payload(
        ACTION_ENTER,
        {"event.name": "session.start", "session.id": "test", "session.kind": "ssh",
         "session.source": "connectivity-test", "user.name": "sysmon-agent-test",
         "enduser.id": "sysmon-agent-test", "client.address": "192.0.2.1",
         "test": True},
        "Connectivity test from sysmon-agent",
        resource or {},
    )
    try:
        return notifier._deliver(payload)
    finally:
        notifier._session.close()
