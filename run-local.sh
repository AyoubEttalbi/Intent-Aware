#!/usr/bin/env bash
# Start the Intent-Aware stack locally: demo target app + API + web UI.
# One command, all env gotchas baked in. Ctrl-C stops everything.
#
#   ./run-local.sh              # target(8080) + API(8473) + web(6173)
#   ./run-local.sh --no-target  # skip the demo target app AND leave :8080 alone
#
# NOTE on .env: it is sourced by bash, so values need quoting when they contain
# spaces (DESCRIPTION="My CRM app"). python-dotenv is more forgiving than bash.
#
set -euo pipefail
cd "$(dirname "$0")"

export PLAYWRIGHT_BROWSERS_PATH="$(pwd)/.browsers"   # project-local chromium/firefox
if [ -f .env ]; then
  # Don't let one unquoted value in .env abort the whole stack under `set -e`.
  set -a; . ./.env || echo "warning: .env did not source cleanly — check quoting"; set +a
fi
# Without this a missing .env silently selects the API provider, and every brain
# call then dies with "ANTHROPIC_API_KEY not found" *after* the scan has started.
export LLM_PROVIDER="${LLM_PROVIDER:-claude_code}"
# Blank the key ONLY for the CLI provider, which authenticates from the ~/.claude
# OAuth session and breaks on a stray/placeholder key. Blanking unconditionally
# would wipe a real key that an `LLM_PROVIDER=claude` run actually needs.
if [ "$LLM_PROVIDER" = "claude_code" ]; then
  export ANTHROPIC_API_KEY=""
fi

# Ports we own. With --no-target the user is almost certainly testing their OWN
# app on :8080 — killing it would take down the very thing under test.
# Written as explicit `if` blocks, not `[ … ] && …` one-liners: a false test in
# an && list returns non-zero, which is a trap to leave lying around under `set -e`.
NO_TARGET=0
if [ "${1:-}" = "--no-target" ]; then NO_TARGET=1; fi
PORTS=(8473 6173)
if [ "$NO_TARGET" -eq 0 ]; then PORTS+=(8080); fi

# Kill by PORT, never by `pkill -f <pattern>` — the pattern matches this very
# shell's command line and takes the script down with it (exit 144).
free_port() { for p in $(ss -ltnp 2>/dev/null | grep ":$1 " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$p" 2>/dev/null || true; done; }
PIDS=()
cleanup() {
  echo; echo "stopping..."
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  for port in "${PORTS[@]}"; do free_port "$port"; done
}
trap cleanup INT TERM EXIT

for port in "${PORTS[@]}"; do free_port "$port"; done

if [ "$NO_TARGET" -eq 0 ]; then
  .venv/bin/python -m uvicorn target_app.main:app --host 127.0.0.1 --port 8080 >/tmp/ia_target.log 2>&1 &
  PIDS+=($!); echo "demo target app  -> http://127.0.0.1:8080   (log: /tmp/ia_target.log)"
else
  echo "demo target app  -> skipped (--no-target); :8080 left untouched"
fi

.venv/bin/python -m uvicorn api.main:app --host 127.0.0.1 --port 8473 >/tmp/ia_api.log 2>&1 &
PIDS+=($!); echo "backend API      -> http://127.0.0.1:8473   (log: /tmp/ia_api.log)"

( cd web && VITE_API_TARGET=http://127.0.0.1:8473 exec npm run dev >/tmp/ia_web.log 2>&1 ) &
PIDS+=($!); echo "web UI (Vite)    -> http://127.0.0.1:6173   (log: /tmp/ia_web.log)"

echo
echo "Open http://127.0.0.1:6173  —  Ctrl-C here stops all of them."
wait
