#!/bin/bash
# team-mail: Show identity at session start

# Show identity if token is set
if [ -n "$TEAM_MAIL_TOKEN" ]; then
  IDENTITY=$(team-mail whoami 2>/dev/null)

  echo "You are logged into team-mail"
  
  if [ -n "$IDENTITY" ]; then
    echo "$IDENTITY"
    echo ""
    echo "Use the /team-mail skill to message teammates."
  fi
fi

exit 0
