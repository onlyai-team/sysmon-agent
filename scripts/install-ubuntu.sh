#!/usr/bin/env bash
# Install sysmon-agent into a dedicated venv under /opt and register the systemd unit.
#
#   sudo ./scripts/install-ubuntu.sh                       # interactive prompts
#   sudo ./scripts/install-ubuntu.sh --endpoint ... --non-interactive
#
# Every argument is passed straight through to 'sysmon-agent install'.
set -euo pipefail

PREFIX="${SYSMON_PREFIX:-/opt/sysmon-agent}"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must run as root: sudo $0 $*" >&2
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

echo "Creating the virtual environment at $PREFIX/venv"
"$UV" venv --python 3.11 "$PREFIX/venv"
"$UV" pip install --python "$PREFIX/venv/bin/python" "$SOURCE_DIR"

ln -sf "$PREFIX/venv/bin/sysmon-agent" /usr/local/bin/sysmon-agent
echo "Linked /usr/local/bin/sysmon-agent"

# Call the venv binary directly so the unit's ExecStart points at a stable path.
exec "$PREFIX/venv/bin/sysmon-agent" install "$@"
