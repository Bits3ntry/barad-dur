#!/bin/sh
# The runtime's only job: keep the lanes alive. A dead lane is restarted by fieldd;
# a dead fieldd is restarted by compose (`restart: unless-stopped`).
set -eu
: "${BARAD_PLATFORM:?BARAD_PLATFORM is required}"
if [ -z "${BARAD_KEY:-${SHAURON_BARAD_KEY:-}}" ]; then
  echo "field-runtime: BARAD_KEY or SHAURON_BARAD_KEY is required" >&2
  exit 2
fi
mkdir -p "${FIELD_WORK_ROOT:-/work}" /tmp
exec python3 /opt/fieldd/fieldd.py "$@"
