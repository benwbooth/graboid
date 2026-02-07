#!/usr/bin/env bash
# Development entrypoint using a user systemd service.

set -euo pipefail

PORT="${GRABOID_PORT:-6749}"
HOST="${GRABOID_HOST:-127.0.0.1}"
BIND_ADDR="${HOST}:${PORT}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
RUST_DIR="$PROJECT_DIR/graboid-rs"

UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
SERVICE_NAME="graboid-dev.service"
SERVICE_PATH="$UNIT_DIR/$SERVICE_NAME"
NIX_BIN="/nix/var/nix/profiles/system/sw/bin/nix"

if [[ ! -x "$NIX_BIN" ]]; then
  NIX_BIN="$(command -v nix || true)"
fi
if [[ -z "$NIX_BIN" ]]; then
  echo "nix not found in PATH and /nix/var/nix/profiles/system/sw/bin/nix is missing"
  exit 1
fi

install_unit() {
  mkdir -p "$UNIT_DIR"
  cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=Graboid Rust Dev Server
After=network.target

[Service]
Type=simple
WorkingDirectory=$PROJECT_DIR
ExecStart=$NIX_BIN develop --command watchexec -r -w $RUST_DIR/src -w $RUST_DIR/Cargo.toml -w $RUST_DIR/build.rs -w $RUST_DIR/frontend/src -w $RUST_DIR/frontend/Cargo.toml -w $RUST_DIR/frontend/index.html -w $RUST_DIR/frontend/Trunk.toml -w $PROJECT_DIR/config.toml -- /run/current-system/sw/bin/bash -lc 'set -euo pipefail; cd "$RUST_DIR/frontend"; NO_COLOR=false trunk build --config Trunk.toml; cd "$PROJECT_DIR"; env GRABOID_RS_BIND_ADDR=$BIND_ADDR cargo run --manifest-path "$RUST_DIR/Cargo.toml"'
Restart=on-failure
RestartSec=1

[Install]
WantedBy=default.target
EOF

  systemctl --user daemon-reload
}

stop_service() {
  systemctl --user stop "$SERVICE_NAME" 2>/dev/null || true
}

echo "Installing user unit: $SERVICE_PATH"
install_unit

# Ensure stale direct runs don't hold the bind address.
pkill -f '[g]raboid-rs/target/debug/graboid-rs' 2>/dev/null || true

stop_service
systemctl --user start "$SERVICE_NAME"

echo ""
echo "Graboid dev service started: $SERVICE_NAME"
echo "URL: http://${BIND_ADDR}"
echo ""

(sleep 2 && xdg-open "http://${BIND_ADDR}" >/dev/null 2>&1 || true) &

exec journalctl --user -f -u "$SERVICE_NAME"
