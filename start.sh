#!/usr/bin/env bash
set -u

printf '%s\n' "[system-config-inspector] Starting read-only runtime inspection..."
if [[ -n "${PORT:-}" ]]; then
  printf '%s\n' "[system-config-inspector] PORT=${PORT} detected; no web server will be started."
else
  printf '%s\n' "[system-config-inspector] PORT is not set; running without a network listener."
fi

exec python3 "$(dirname "$0")/system_info.py"
