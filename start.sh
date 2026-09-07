#!/usr/bin/env bash
set -u

printf '%s\n' "[system-config-inspector] Starting read-only runtime inspection..."
if [[ -n "${PORT:-}" ]]; then
  printf '%s\n' "[system-config-inspector] PORT=${PORT} detected; plain-text report will be served on 0.0.0.0:${PORT}."
else
  printf '%s\n' "[system-config-inspector] PORT is not set; plain-text report will use fallback port 10000."
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
if [[ "${INSPECTOR_MODE:-serve}" == "once" ]]; then
  exec python3 "$SCRIPT_DIR/network_details.py" --once
else
  exec python3 "$SCRIPT_DIR/network_details.py" --serve
fi
