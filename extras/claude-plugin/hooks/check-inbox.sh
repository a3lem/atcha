#!/bin/bash
# atcha: Check for new messages after tool use
#
# Uses 'messages check --json' to see if there are unread messages,
# then lists and reads specific IDs (messages read now requires IDs).

[ -z "$ATCHA_DIR" ] && exit 0
[ -z "$ATCHA_TOKEN" ] && exit 0

COUNT=$(atcha messages check --json 2>/dev/null | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('count',0))" 2>/dev/null)
if [ "$COUNT" != "0" ] && [ -n "$COUNT" ]; then
    # Get unread message IDs, then read them
    IDS=$(atcha messages --json 2>/dev/null | python3 -c "
import sys,json
msgs = json.loads(sys.stdin.read())
print(' '.join(m['id'] for m in msgs))
" 2>/dev/null)
    if [ -n "$IDS" ]; then
        OUTPUT=$(atcha messages read $IDS 2>/dev/null)
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
    fi
fi

exit 0
