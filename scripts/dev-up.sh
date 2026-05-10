#!/usr/bin/env bash
# Start the local supplycheck dev server.
# Idempotent: if a server is already running on the port, this is a no-op.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${SUPPLYCHECK_PORT:-3004}"
HOST="${SUPPLYCHECK_HOST:-127.0.0.1}"
PID_FILE="$ROOT/.server.pid"
LOG_FILE="$ROOT/.server.log"

# Already-running check: trust PID file if the process is alive.
if [[ -f "$PID_FILE" ]]; then
  pid="$(cat "$PID_FILE")"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    echo "supplycheck dev server already running (PID $pid) on http://$HOST:$PORT"
    exit 0
  fi
  # Stale PID file → remove and continue.
  rm -f "$PID_FILE"
fi

# Port-in-use check: don't trample another process.
if lsof -i ":$PORT" -P -n -sTCP:LISTEN >/dev/null 2>&1; then
  pid="$(lsof -i ":$PORT" -P -n -sTCP:LISTEN -t 2>/dev/null | head -1)"
  echo "Port $PORT is already in use by PID $pid (not us). Stop it first or set SUPPLYCHECK_PORT." >&2
  exit 1
fi

# Start, detached, with a small wait + healthcheck.
( cd "$ROOT" && exec python3 -m http.server "$PORT" --bind "$HOST" --directory "$ROOT" ) >"$LOG_FILE" 2>&1 &
pid=$!
echo "$pid" > "$PID_FILE"

# Wait briefly for the server to start serving (max ~2s).
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl -sf "http://$HOST:$PORT/" -o /dev/null --max-time 1; then
    echo "supplycheck dev server up at http://$HOST:$PORT (PID $pid)"
    echo "Logs: $LOG_FILE"
    exit 0
  fi
  sleep 0.2
done

echo "Server started (PID $pid) but didn't respond within 2s. Check $LOG_FILE." >&2
exit 1
