#!/usr/bin/env bash
# Install the recurring audit. Idempotent — re-running replaces the entry.
#
#   ./loop/install-cron.sh            # every 6 hours
#   ./loop/install-cron.sh "0 * * * *"  # custom schedule
#   ./loop/install-cron.sh --remove

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MARK="# agent-wormhole-audit"
SCHED="${1:-0 */6 * * *}"

if [ "${1:-}" = "--remove" ]; then
  crontab -l 2>/dev/null | grep -vF "$MARK" | crontab -
  echo "removed"
  exit 0
fi

LINE="$SCHED $ROOT/loop/audit.sh >/dev/null 2>&1 $MARK"
{ crontab -l 2>/dev/null | grep -vF "$MARK"; echo "$LINE"; } | crontab -

echo "installed: $SCHED"
echo "  logs:   ~/.wormhole/logs/"
echo "  remove: ./loop/install-cron.sh --remove"
echo
echo "Take a baseline first if you have not:"
echo "  python3 -m wormhole baseline ~/your-project"
