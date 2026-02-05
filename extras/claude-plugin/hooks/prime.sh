#!/bin/bash
# atcha: Show identity at session start

# Show identity if token is set
if [ -n "$ATCHA_TOKEN" ]; then
  IDENTITY=$(atcha whoami 2>/dev/null)

  echo "You are logged into atcha"

  if [ -n "$IDENTITY" ]; then
    echo "$IDENTITY"
    echo ""
    echo "Use the /atcha skill to message teammates."
  fi
fi

exit 0
