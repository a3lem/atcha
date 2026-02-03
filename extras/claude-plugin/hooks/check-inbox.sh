#!/bin/bash
# team-mail: Check for new messages after tool use

[ -z "$TEAM_MAIL_DIR" ] && exit 0
[ -z "$TEAM_MAIL_TOKEN" ] && exit 0

OUTPUT=$(team-mail inbox read 2>/dev/null)

if [ -n "$OUTPUT" ]; then
  echo "=== New mail ==="
  echo "$OUTPUT" | python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        m = json.loads(line)
        print(f\"From {m.get('from','?')}: {m.get('body','')}\")
    except: pass
"
  echo "================"
fi

exit 0
