#!/bin/bash
# atcha: Check for new messages after tool use

[ -z "$ATCHA_DIR" ] && exit 0
[ -z "$ATCHA_TOKEN" ] && exit 0

OUTPUT=$(atcha messages read 2>/dev/null)

if [ -n "$OUTPUT" ]; then
  echo "=== New messages ==="
  echo "$OUTPUT" | python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        m = json.loads(line)
        content = m.get('content') or m.get('body', '')
        print(f\"From {m.get('from','?')}: {content}\")
    except: pass
"
  echo "================"
fi

exit 0
