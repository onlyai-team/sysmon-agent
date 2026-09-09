"""Cross-platform system and login-session monitoring agent."""

__version__ = "1.3.0"

SERVICE_NAME = "sysmon-agent"
SERVICE_DISPLAY_NAME = "System & Session Monitor Agent"
SERVICE_DESCRIPTION = (
    "Collects CPU, memory, disk and network metrics plus login/logout session "
    "events and exports them to an OTLP/HTTP collector."
)
