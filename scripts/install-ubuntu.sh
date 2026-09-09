#!/usr/bin/env bash
# Install or update sysmon-agent: a dedicated venv under /opt plus the systemd unit.
#
#   sudo ./scripts/install-ubuntu.sh                       # first install, prompts
#   sudo ./scripts/install-ubuntu.sh --update              # upgrade, keeps the config
#   sudo ./scripts/install-ubuntu.sh --endpoint ... --non-interactive
#
# Any other argument is passed straight through to 'sysmon-agent install'.
set -euo pipefail

PREFIX="${SYSMON_PREFIX:-/opt/sysmon-agent}"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="/etc/sysmon-agent/config.json"
UPDATE=0
ARGS=()

for arg in "$@"; do
    if [ "$arg" = "--update" ]; then
        UPDATE=1
    else
        ARGS+=("$arg")
    fi
done

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must run as root: sudo $0 $*" >&2
    exit 1
fi

if [ "$UPDATE" -eq 1 ] && [ ! -f "$CONFIG" ]; then
    echo "No configuration at $CONFIG. Run without --update to install." >&2
    exit 1
fi

find_uv() {
    for candidate in "$(command -v uv || true)" /usr/local/bin/uv /root/.local/bin/uv \
                     "${SUDO_USER:+/home/$SUDO_USER/.local/bin/uv}"; do
        [ -n "$candidate" ] && [ -x "$candidate" ] && { echo "$candidate"; return 0; }
    done
    return 1
}

if ! UV="$(find_uv)"; then
    cat >&2 <<'EOF'
uv was not found.

Install it first, then re-run this script:

    curl -LsSf https://astral.sh/uv/install.sh | sh
    sudo install -m 0755 ~/.local/bin/uv /usr/local/bin/uv

EOF
    exit 1
fi
echo "Using uv at $UV"

systemctl stop sysmon-agent 2>/dev/null || true

if [ -x "$PREFIX/venv/bin/python" ]; then
    echo "Reusing the virtual environment at $PREFIX/venv"
else
    echo "Creating the virtual environment at $PREFIX/venv"
    "$UV" venv --python 3.11 "$PREFIX/venv"
fi
"$UV" pip install --python "$PREFIX/venv/bin/python" \
    --reinstall-package sysmon-agent "$SOURCE_DIR"

ln -sf "$PREFIX/venv/bin/sysmon-agent" /usr/local/bin/sysmon-agent
echo "Linked /usr/local/bin/sysmon-agent"

# Call the venv binary directly so the unit's ExecStart points at a stable path.
if [ "$UPDATE" -eq 1 ]; then
    echo "Re-registering the service with the existing configuration"
    "$PREFIX/venv/bin/sysmon-agent" install --non-interactive --skip-check
else
    "$PREFIX/venv/bin/sysmon-agent" install "${ARGS[@]+"${ARGS[@]}"}"
fi

"$PREFIX/venv/bin/sysmon-agent" --version
exec "$PREFIX/venv/bin/sysmon-agent" status
