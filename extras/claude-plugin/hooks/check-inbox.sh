#!/bin/bash
# team-mail: PostToolUse hook — check for new messages.
# Silent when there's nothing new, plugin is inactive, or no token is set.

# Check if plugin is active and token is set
if [ -z "$TEAM_MAIL_DIR" ]; then
  exit 0
fi

if [ -z "$TEAM_MAIL_TOKEN" ]; then
  exit 0
fi

CLI="${TEAM_MAIL_CLI:-$(cd "$(dirname "$0")/.." && pwd)/cli/team_mail.py}"

# Read unread messages (silent if none)
OUTPUT=$(uv run "$CLI" inbox read 2>/dev/null)

if [ -n "$OUTPUT" ]; then
  echo "=== TEAM-MAIL: New messages ==="
  # Parse all JSONL lines and format in a single Python invocation
  echo "$OUTPUT" | uv run python -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        m = json.loads(line)
        print(f\"[{m.get('ts', '')}] {m.get('from', '')} ({m.get('type', '')}): {m.get('body', '')}\")
    except json.JSONDecodeError:
        pass
"
  echo "=== Messages marked as read. ==="
fi

exit 0
