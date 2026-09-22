#!/usr/bin/env bash
# Recurring integrity + posture audit.
#
# Runs the two checks that matter on a schedule and only speaks up when
# something changed. Silence is the expected output; noise trains people to
# ignore the tool.
#
# Install:  ./loop/install-cron.sh
# Manual:   ./loop/audit.sh ~/project-a ~/project-b

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="${WORMHOLE_LOG_DIR:-$HOME/.wormhole/logs}"
mkdir -p "$LOG_DIR"
STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LOG="$LOG_DIR/audit-$(date -u +%Y%m%d).log"

TARGETS=("$@")
DISCOVERY_FAILED=0
if [ ${#TARGETS[@]} -eq 0 ]; then
  # Default: every directory under $HOME holding an agent config.
  #
  # AW-62. This piped `find` into `xargs -n1 dirname` with no -print0, and
  # xargs parses quotes: one apostrophe anywhere under $HOME — "~/Bob's
  # projects/app/AGENTS.md" — aborts the ENTIRE pipeline with "xargs:
  # unterminated quote" and discards every target. The cron audit then logged
  # "ok (1 targets, no change)" and exited 0 while scanning nothing.
  # Reproduced against a synthetic HOME: a WORM-001 payload under "Bob's
  # projects" gave exit 0 and "ok"; the identical payload elsewhere gave ALERT
  # and exit 1. Attacker cost: one mkdir, or nothing at all.
  #
  # NUL-delimited, no xargs, dedupe in bash.
  # Associative arrays need bash 4 and macOS ships 3.2, so dedupe by scanning
  # what is already collected. Target counts here are small.
  while IFS= read -r -d '' f; do
    d=$(dirname "$f")
    dup=0
    for seen in ${TARGETS[@]+"${TARGETS[@]}"}; do
      if [ "$seen" = "$d" ]; then dup=1; break; fi
    done
    if [ "$dup" -eq 0 ]; then TARGETS+=("$d"); fi
  done < <(
    find "$HOME" -maxdepth 3 \( -name AGENTS.md -o -name CLAUDE.md -o -name claude.md \) \
      -not -path '*/node_modules/*' -not -path '*/.git/*' -print0 2>/dev/null
  )
  # A discovery that found nothing is not a clean audit. Saying "ok" here is
  # how the failure above stayed invisible: silence and success looked the
  # same.
  if [ ${#TARGETS[@]} -eq 0 ]; then
    DISCOVERY_FAILED=1
  fi
fi

if [ "$DISCOVERY_FAILED" -eq 1 ]; then
  echo "ALERT: target discovery found no agent configuration under \$HOME." >&2
  echo "  Either there is genuinely none, or discovery failed. Either way this" >&2
  echo "  run audited nothing, and reporting that as 'ok' would be a lie." >&2
  exit 1
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
