"""Command line interface: install, remove, logs, status, run."""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import List, Optional

from . import SERVICE_NAME, __version__
from .config import (AUTH_BASIC, AUTH_BEARER, AUTH_HEADER, AUTH_NONE, AUTH_TYPES,
                     LOG_FORMATS, Config)
from .paths import IS_WINDOWS, config_file, ensure_dirs, log_dir, log_file, state_dir
from .util import AgentError, human_bytes, is_admin, require_admin

LOG = logging.getLogger("sysmon.cli")


# --------------------------------------------------------------------- prompts


def ask(question: str, default: Optional[str] = None, secret: bool = False) -> str:
    suffix = " [%s]" % default if default else ""
    while True:
        prompt = "%s%s: " % (question, suffix)
        answer = (getpass.getpass(prompt) if secret else input(prompt)).strip()
        if answer:
            return answer
        if default is not None:
            return default
        print("  A value is required.")


def ask_choice(question: str, choices: List[str], default: str) -> str:
    print("\n%s" % question)
    for index, choice in enumerate(choices, 1):
        marker = " (default)" if choice == default else ""
        print("  %d) %s%s" % (index, choice, marker))
    while True:
        answer = input("Choice [%s]: " % default).strip().lower()
        if not answer:
            return default
        if answer in choices:
            return answer
        if answer.isdigit() and 1 <= int(answer) <= len(choices):
            return choices[int(answer) - 1]
        print("  Pick a number between 1 and %d." % len(choices))


def ask_bool(question: str, default: bool = True) -> bool:
    suffix = "Y/n" if default else "y/N"
    while True:
        answer = input("%s [%s]: " % (question, suffix)).strip().lower()
        if not answer:
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False


def ask_int(question: str, default: int, minimum: int = 1) -> int:
    while True:
        answer = input("%s [%d]: " % (question, default)).strip()
        if not answer:
            return default
        try:
            value = int(answer)
        except ValueError:
            print("  Enter a whole number.")
            continue
        if value < minimum:
            print("  Must be at least %d." % minimum)
            continue
        return value


# --------------------------------------------------------------------- install


def build_config(args, existing: Optional[Config]) -> Config:
    """Merge flags, existing config and interactive answers into one Config."""
    config = existing or Config()

    if args.non_interactive:
        if args.endpoint:
            config.endpoint = args.endpoint
        if args.machine_name:
            config.machine_name = args.machine_name
        _apply_auth_flags(config, args)
        _apply_common_flags(config, args)
        return config

    print("\n=== %s %s installer ===" % (SERVICE_NAME, __version__))
    print("Answer the prompts; press Enter to accept the value in brackets.\n")

    config.endpoint = args.endpoint or ask(
        "OTLP/HTTP collector endpoint (e.g. https://otel.example.com:4318)",
        config.endpoint or None,
    )

    auth_type = args.auth_type or ask_choice(
        "How does the collector authenticate this agent?",
        list(AUTH_TYPES),
        config.auth_type or AUTH_NONE,
    )
    config.auth_type = auth_type
    if auth_type == AUTH_BEARER:
        config.token = args.token or ask("Bearer token", secret=True)
    elif auth_type == AUTH_BASIC:
        config.username = args.username or ask("Username", config.username or None)
        config.password = args.password or ask("Password", secret=True)
    elif auth_type == AUTH_HEADER:
        config.header_name = args.header_name or ask(
            "Header name", config.header_name or "X-API-Key")
        config.header_value = args.header_value or ask("Header value", secret=True)
    else:
        config.token = config.password = config.header_value = ""

    config.machine_name = args.machine_name or ask(
        "Machine name reported as host.name",
        config.machine_name or socket.gethostname(),
    )
    config.environment = args.environment if args.environment is not None else ask(
        "Environment label (blank for none)", config.environment or "")

    print("")
    config.metrics_interval_seconds = args.interval or ask_int(
        "Metric export interval, seconds", config.metrics_interval_seconds)
    config.session_poll_seconds = args.session_poll or ask_int(
        "Session poll interval, seconds", config.session_poll_seconds)

    if config.endpoint.startswith("https://"):
        config.verify_tls = ask_bool("Verify the collector's TLS certificate?",
                                     config.verify_tls)
        if config.verify_tls:
            bundle = ask("Custom CA bundle path (blank to use the system store)",
                         config.ca_bundle or "")
            config.ca_bundle = bundle if bundle and bundle != "" else ""
    _apply_common_flags(config, args)
    return config


def _apply_auth_flags(config: Config, args) -> None:
    if args.auth_type:
        config.auth_type = args.auth_type
    if args.token:
        config.token = args.token
    if args.username:
        config.username = args.username
    if args.password:
        config.password = args.password
    if args.header_name:
        config.header_name = args.header_name
    if args.header_value:
        config.header_value = args.header_value


def _apply_common_flags(config: Config, args) -> None:
    if args.interval:
        config.metrics_interval_seconds = args.interval
    if args.session_poll:
        config.session_poll_seconds = args.session_poll
    if getattr(args, "heartbeat", None):
        config.heartbeat_seconds = args.heartbeat
    if args.environment is not None:
        config.environment = args.environment
    if args.ca_bundle:
        config.ca_bundle = args.ca_bundle
    if args.no_verify_tls:
        config.verify_tls = False
    if getattr(args, "no_per_cpu", False):
        config.per_cpu_metrics = False
    if getattr(args, "log_format", None):
        config.log_format = args.log_format
    if getattr(args, "no_traces", False):
        config.traces_enabled = False
    if getattr(args, "trace_polls", False):
        config.trace_polls = True
    if args.attribute:
        for pair in args.attribute:
            key, _, value = pair.partition("=")
            if key and value:
                config.extra_attributes[key.strip()] = value.strip()


def cmd_install(args) -> int:
    from . import service
    from .telemetry import check_endpoint

    require_admin("install")
    service.require_available()
    ensure_dirs()

    existing = Config.load() if Config.exists() else None
    if existing and not args.non_interactive:
        print("An existing configuration was found at %s; its values are the defaults."
              % config_file())

    config = build_config(args, existing)
    config.validate()

    if not args.skip_check:
        print("\nChecking the collector...")
        ok, message = check_endpoint(config)
        print("  %s\n  %s" % ("OK" if ok else "FAILED", message))
        if not ok:
            if args.non_interactive:
                raise AgentError(
                    "Collector check failed. Fix the endpoint or pass --skip-check.")
            if not ask_bool("Install anyway?", False):
                return 1

    path = config.save()
    print("\nWrote configuration to %s" % path)

    service.install()
    print("Installed and started the %s service." % SERVICE_NAME)
    print("  status:  sysmon-agent status")
    print("  logs:    sysmon-agent logs -f")
    print("  remove:  sysmon-agent remove")
    return 0


# ---------------------------------------------------------------------- remove


def cmd_remove(args) -> int:
    from . import service

    require_admin("remove")
    if not args.yes and not args.non_interactive:
        target = "service, configuration and logs" if args.purge else "service"
        if not ask_bool("Remove the %s %s?" % (SERVICE_NAME, target), True):
            print("Cancelled.")
            return 1

    steps = service.remove()
    for step in steps:
        print("  %s" % step)
    if not steps:
        print("  no service was installed")

    if args.purge:
        for directory in (state_dir(), log_dir()):
            if directory.exists():
                shutil.rmtree(str(directory), ignore_errors=True)
                print("  removed %s" % directory)
        if config_file().exists():
            config_file().unlink()
            print("  removed %s" % config_file())
            parent = config_file().parent
            try:
                parent.rmdir()
                print("  removed %s" % parent)
            except OSError:
                pass
    else:
        print("  kept %s (use --purge to delete it)" % config_file())
    print("Done.")
    return 0


# ------------------------------------------------------------------------ logs


def cmd_logs(args) -> int:
    source = args.source
    if source == "journal" or (source == "auto" and not IS_WINDOWS
                               and args.journal_available()):
        return _journal_logs(args)
    return _file_logs(args)


def _journal_logs(args) -> int:
    from .service import systemd

    cmd = systemd.journal_command(args.lines, args.follow)
    try:
        return subprocess.call(cmd)
    except KeyboardInterrupt:
        return 0
    except FileNotFoundError:
        return _file_logs(args)


def _file_logs(args) -> int:
    path = log_file()
    if not path.exists():
        print("No log file at %s yet." % path, file=sys.stderr)
        print("The agent writes it once the service starts.", file=sys.stderr)
        return 1
    _tail(path, args.lines, args.follow)
    return 0


def _tail(path: Path, lines: int, follow: bool) -> None:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        block = handle.readlines()
        for line in block[-lines:]:
            sys.stdout.write(line)
        sys.stdout.flush()
        if not follow:
            return
        position = handle.tell()
        try:
            while True:
                time.sleep(0.5)
                # Follow the file across rotation.
                if path.stat().st_size < position:
                    handle.seek(0)
                    position = 0
                handle.seek(position)
                for line in handle:
                    sys.stdout.write(line)
                sys.stdout.flush()
                position = handle.tell()
        except KeyboardInterrupt:
            return
        except FileNotFoundError:
            return


# ---------------------------------------------------------------------- status


def cmd_status(args) -> int:
    from . import service
    from .metrics import snapshot

    print("%s %s" % (SERVICE_NAME, __version__))
    print("  service:  %s" % service.status())
    print("  config:   %s" % (config_file() if Config.exists() else "not configured"))
    print("  log file: %s" % (log_file() if log_file().exists() else "not created yet"))

    if Config.exists():
        config = Config.load()
        print("  endpoint: %s" % config.endpoint)
        print("  machine:  %s" % config.machine_name)
        print("  auth:     %s" % config.auth_type)
        print("  interval: %ds metrics / %ds sessions"
              % (config.metrics_interval_seconds, config.session_poll_seconds))

    data = snapshot()
    print("\nSystem right now")
    print("  cpu:       %.1f%%" % data["cpu_percent"])
    print("  memory:    %.1f%% of %s" % (data["memory_percent"],
                                         human_bytes(data["memory_total"])))
    for mount, percent in data["disks"][:6]:
        print("  disk %-10s %.1f%%" % (mount, percent))
    print("  network:   %s in / %s out since boot"
          % (human_bytes(data["net_recv"]), human_bytes(data["net_sent"])))
    print("  uptime:    %.1f hours" % (data["uptime_seconds"] / 3600.0))
    print("  processes: %d" % data["processes"])

    if args.sessions:
        _print_sessions()
    if args.verbose and service.installed():
        print("\n%s" % service.detail())
    return 0


def cmd_sessions(args) -> int:
    _print_sessions()
    return 0


def _print_sessions() -> None:
    from .sessions import build_tracker

    tracker = build_tracker(5)
    print("\nLogin sessions (source: %s)" % tracker.source_name)
    if not tracker.supported():
        print("  session tracking is unavailable on this system")
        return
    try:
        sessions = tracker.poll()
    except Exception as exc:
        print("  could not read sessions: %s" % exc)
        if not is_admin():
            print("  (this usually needs root / Administrator)")
        return
    if not sessions:
        print("  none")
        return
    for session in sessions:
        print("  %-8s %-20s %-18s %s"
              % (session.kind, session.user or "?",
                 session.remote_host or session.terminal or "local", session.id))


# ------------------------------------------------------------------------- run


def cmd_run(args) -> int:
    from .agent import Agent
    from .logsetup import configure

    config = Config.load()
    configure(config, console=args.console)
    stop = threading.Event()

    def handle(signum, frame):
        LOG.info("Received signal %s", signum)
        stop.set()

    for name in ("SIGTERM", "SIGINT", "SIGBREAK"):
        signum = getattr(signal, name, None)
        if signum is not None:
            try:
                signal.signal(signum, handle)
            except (ValueError, OSError):
                pass

    return Agent(config).run(stop_event=stop)


# ------------------------------------------------------------------ misc verbs


def cmd_test(args) -> int:
    from .telemetry import check_endpoint, send_test_telemetry

    config = Config.load()
    config.validate()
    ok, message = check_endpoint(config)
    print("%s\n  %s" % ("OK" if ok else "FAILED", message))
    if not args.send:
        return 0 if ok else 1

    print("\nSending one real span and one real log record...")
    failures = 0
    for signal, sent, detail in send_test_telemetry(config):
        print("  %-8s %-7s %s" % (signal + ":", "OK" if sent else "FAILED", detail))
        failures += 0 if sent else 1
    if failures:
        print("\nThe collector refused the payload. The exporter logs the reason; "
              "run with a reachable endpoint or check the credentials.")
    else:
        print("\nLook for a span named 'agent.test' in your trace backend.")
    return 0 if ok and failures == 0 else 1


def cmd_config(args) -> int:
    config = Config.load()
    if args.json:
        print(json.dumps(config.redacted(), indent=2, sort_keys=True))
        return 0
    for key, value in sorted(config.redacted().items()):
        print("%-26s %s" % (key, value))
    return 0


def cmd_restart(args) -> int:
    from . import service

    require_admin("restart")
    service.restart()
    print("Restarted. Status: %s" % service.status())
    return 0


# ---------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=SERVICE_NAME,
        description="System and login-session monitoring agent with OTLP/HTTP export.",
    )
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    sub = parser.add_subparsers(dest="command", required=True)

    install = sub.add_parser("install", help="configure and install the background service")
    install.add_argument("--endpoint", help="OTLP/HTTP collector base URL")
    install.add_argument("--machine-name", help="value reported as host.name")
    install.add_argument("--auth-type", choices=list(AUTH_TYPES),
                         help="collector authentication scheme")
    install.add_argument("--token", help="bearer token")
    install.add_argument("--username", help="basic auth username")
    install.add_argument("--password", help="basic auth password")
    install.add_argument("--header-name", help="custom auth header name")
    install.add_argument("--header-value", help="custom auth header value")
    install.add_argument("--interval", type=int, help="metric export interval in seconds")
    install.add_argument("--session-poll", type=int,
                         help="session poll interval in seconds")
    install.add_argument("--heartbeat", type=int,
                         help="heartbeat interval in seconds; also paces the "
                              "agent.heartbeat span (default 300)")
    install.add_argument("--environment", help="deployment.environment attribute")
    install.add_argument("--attribute", action="append", metavar="KEY=VALUE",
                         help="extra resource attribute, repeatable")
    install.add_argument("--log-format", choices=LOG_FORMATS,
                         help="json (default) writes one JSON object per event, "
                              "in the log file and in the exported log body")
    install.add_argument("--no-traces", action="store_true",
                         help="do not export spans, only metrics and logs")
    install.add_argument("--trace-polls", action="store_true",
                         help="also span every session poll and the commands it "
                              "runs; useful for debugging, noisy otherwise")
    install.add_argument("--no-per-cpu", action="store_true",
                         help="report CPU metrics for the host only, not per core")
    install.add_argument("--ca-bundle", help="path to a custom CA bundle")
    install.add_argument("--no-verify-tls", action="store_true",
                         help="do not verify the collector's TLS certificate")
    install.add_argument("--skip-check", action="store_true",
                         help="do not probe the collector before installing")
    install.add_argument("--non-interactive", action="store_true",
                         help="never prompt; take every value from flags")
    install.set_defaults(func=cmd_install)

    remove = sub.add_parser("remove", help="stop and uninstall the background service")
    remove.add_argument("--purge", action="store_true",
                        help="also delete the configuration, state and logs")
    remove.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
    remove.add_argument("--non-interactive", action="store_true", help=argparse.SUPPRESS)
    remove.set_defaults(func=cmd_remove)

    logs = sub.add_parser("logs", help="show the agent log")
    logs.add_argument("-n", "--lines", type=int, default=100,
                      help="number of lines to show (default 100)")
    logs.add_argument("-f", "--follow", action="store_true", help="stream new lines")
    logs.add_argument("--source", choices=("auto", "file", "journal"), default="auto",
                      help="where to read from (journal is systemd only)")
    logs.set_defaults(func=cmd_logs)

    status = sub.add_parser("status", help="show service state and a system snapshot")
    status.add_argument("-v", "--verbose", action="store_true",
                        help="include the service manager's own output")
    status.add_argument("--sessions", action="store_true",
                        help="also list the login sessions detected right now")
    status.set_defaults(func=cmd_status)

    sessions = sub.add_parser("sessions", help="list the login sessions detected right now")
    sessions.set_defaults(func=cmd_sessions)

    run = sub.add_parser("run", help="run the agent in the foreground (used by the service)")
    run.add_argument("--console", action="store_true", default=True,
                     help=argparse.SUPPRESS)
    run.set_defaults(func=cmd_run)

    test = sub.add_parser("test", help="check that the collector is reachable")
    test.add_argument("--send", action="store_true",
                      help="also send one real span and log record, then report "
                           "whether the collector accepted them")
    test.set_defaults(func=cmd_test)

    config = sub.add_parser("config", help="print the stored configuration, secrets redacted")
    config.add_argument("--json", action="store_true", help="print JSON")
    config.set_defaults(func=cmd_config)

    restart = sub.add_parser("restart", help="restart the background service")
    restart.set_defaults(func=cmd_restart)

    return parser


def _journal_available() -> bool:
    from .service import systemd

    return systemd.available() and systemd.installed() and shutil.which("journalctl") is not None


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.journal_available = _journal_available

    if args.command != "run":
        logging.getLogger("sysmon").setLevel(logging.WARNING)
        logging.getLogger("sysmon").addHandler(logging.StreamHandler(sys.stderr))
        logging.getLogger("sysmon").propagate = False

    try:
        return args.func(args)
    except AgentError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
