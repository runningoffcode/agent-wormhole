#!/usr/bin/env bash
# Corpus replay: the regression gate for detection rules.
#
# Contract:
#   every corpus/malicious/* must produce >=1 WORM finding  (no false negatives)
#   every corpus/benign/*    must produce  0 WORM findings  (no false positives)
#
# A new rule that breaks either half does not ship.

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

hits() {  # count WORM findings for a single file
  mkdir -p "$WORK/case"
  rm -f "$WORK/case/"*
  cp "$1" "$WORK/case/AGENTS.md"
  # --no-suppress: the corpus includes a fixture that carries its own
  # `wormhole:ignore` directive. Honouring it here would let the payload
  # exempt itself from the regression suite that exists to catch it.
  python3 -m wormhole scan "$WORK/case" --no-color --local-only \
    --no-suppress --fail-on never --json 2>/dev/null | python3 -c \
    'import json,sys
try: d=json.load(sys.stdin)
except Exception: d=[]
print(sum(1 for f in d if f["rule_id"].startswith("WORM")))'
}

fn=0; fp=0; tp=0; tn=0

echo "malicious (expect >=1 hit each)"
for f in corpus/malicious/*.md; do
  [ -e "$f" ] || continue
  n="$(hits "$f")"
  if [ "${n:-0}" -ge 1 ]; then echo "  pass  $(basename "$f")  ($n)"; tp=$((tp+1))
  else echo "  MISS  $(basename "$f")  (0)  <- false negative"; fn=$((fn+1)); fi
done

echo
echo "benign (expect 0 hits each)"
for f in corpus/benign/*.md; do
  [ -e "$f" ] || continue
  n="$(hits "$f")"
  if [ "${n:-0}" -eq 0 ]; then echo "  pass  $(basename "$f")"; tn=$((tn+1))
  else echo "  FIRE  $(basename "$f")  ($n)  <- false positive"; fp=$((fp+1)); fi
done

echo
echo "detected $tp/$((tp+fn))   clean $tn/$((tn+fp))   FN=$fn FP=$fp"
[ "$fn" -eq 0 ] && [ "$fp" -eq 0 ] || exit 1
