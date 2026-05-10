#!/usr/bin/env bash
# Stop the local supplycheck dev server started by dev-up.sh.
# Falls back to killing whatever is on the port if the PID file is stale.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${SUPPLYCHECK_PORT:-3004}"
PID_FILE="$ROOT/.server.pid"

stopped=0

if [[ -f "$PID_FILE" ]]; then
  pid="$(cat "$PID_FILE")"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    # Wait briefly for the process to exit; SIGKILL if it hangs.
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      if ! kill -0 "$pid" 2>/dev/null; then break; fi
      sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null || true
    fi
    echo "Stopped supplycheck dev server (PID $pid)"
    stopped=1
  fi
  rm -f "$PID_FILE"
fi

# Belt-and-suspenders: if the port is still occupied by a process matching our
# command line (python http.server), kill it too. Don't touch unrelated processes.
if lsof -i ":$PORT" -P -n -sTCP:LISTEN >/dev/null 2>&1; then
  for pid in $(lsof -i ":$PORT" -P -n -sTCP:LISTEN -t 2>/dev/null); do
    cmd="$(ps -p "$pid" -o command= 2>/dev/null || true)"
    if [[ "$cmd" == *"http.server"* ]]; then
      kill "$pid" 2>/dev/null || true
      echo "Stopped stray python http.server (PID $pid)"
      stopped=1
    fi
  done
fi

if [[ "$stopped" -eq 0 ]]; then
  echo "No supplycheck dev server running on port $PORT"
fi
