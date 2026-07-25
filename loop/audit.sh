#!/usr/bin/env bash
# Recurring integrity + posture audit.
#
# Runs the two checks that matter on a schedule and only speaks up when
# something changed. Silence is the expected output; noise trains people to
# ignore the tool.
#
# Install:  ./loop/install-cron.sh
# Manual:   ./loop/audit.sh ~/traccion ~/agentbazaar

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="${WORMHOLE_LOG_DIR:-$HOME/.wormhole/logs}"
mkdir -p "$LOG_DIR"
STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LOG="$LOG_DIR/audit-$(date -u +%Y%m%d).log"

TARGETS=("$@")
if [ ${#TARGETS[@]} -eq 0 ]; then
  # Default: every directory under $HOME holding an agent config.
  while IFS= read -r d; do TARGETS+=("$d"); done < <(
    find "$HOME" -maxdepth 3 \( -name AGENTS.md -o -name CLAUDE.md -o -name claude.md \) \
      -not -path '*/node_modules/*' -not -path '*/.git/*' 2>/dev/null \
      | xargs -n1 dirname | sort -u
  )
fi

alerts=0
report=""

for t in "${TARGETS[@]}"; do
  [ -d "$t" ] || continue

  # 1. Integrity: did a tracked file change since we last looked?
  vout="$(cd "$ROOT" && python3 -m wormhole verify "$t" --no-color --json 2>/dev/null)"
  vhits="$(printf '%s' "$vout" | python3 -c \
    'import json,sys
try: d=json.load(sys.stdin)
except Exception: d=[]
print(sum(1 for f in d if f["severity"] in ("critical","high")))' 2>/dev/null || echo 0)"

  # 2. Content + posture: is there a payload or an overreaching grant?
  sout="$(cd "$ROOT" && python3 -m wormhole scan "$t" --no-color --local-only \
    --fail-on never --json 2>/dev/null)"
  shits="$(printf '%s' "$sout" | python3 -c \
    'import json,sys
try: d=json.load(sys.stdin)
except Exception: d=[]
print(sum(1 for f in d if f["rule_id"].startswith("WORM")))' 2>/dev/null || echo 0)"

  if [ "${vhits:-0}" -gt 0 ] || [ "${shits:-0}" -gt 0 ]; then
    alerts=$((alerts + 1))
    report+=$'\n'"[$t] integrity=$vhits injection=$shits"
    report+=$'\n'"$(printf '%s' "$sout" | python3 -c \
      'import json,sys
try: d=json.load(sys.stdin)
except Exception: d=[]
for f in d:
    if f["rule_id"].startswith("WORM"):
        print("   ", f["rule_id"], f["path"] or "", f.get("line") or "")' 2>/dev/null)"
  fi
done

if [ "$alerts" -gt 0 ]; then
  echo "$STAMP ALERT ($alerts target(s))$report" | tee -a "$LOG"
  # Surface it where a human will actually see it.
  if command -v osascript >/dev/null 2>&1; then
    osascript -e "display notification \"$alerts target(s) flagged\" with title \"Agent Wormhole: config alert\"" 2>/dev/null
  fi
  exit 1
fi

echo "$STAMP ok (${#TARGETS[@]} targets, no change)" >> "$LOG"
exit 0
