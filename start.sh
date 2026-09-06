#!/usr/bin/env bash
set -u

printf '%s\n' "[system-config-inspector] Starting read-only runtime inspection..."
if [[ -n "${PORT:-}" ]]; then
  printf '%s\n' "[system-config-inspector] PORT=${PORT} detected; the HTTP viewer will bind to 0.0.0.0."
else
  printf '%s\n' "[system-config-inspector] PORT is not set; the HTTP viewer will use fallback port 10000."
fi

if [[ "${INSPECTOR_MODE:-serve}" == "once" ]]; then
  exec python3 "$(dirname "$0")/system_info.py" --once
else
  exec python3 "$(dirname "$0")/system_info.py" --serve
fi
