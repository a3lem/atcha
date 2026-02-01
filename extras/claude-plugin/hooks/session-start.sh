#!/bin/bash
# team-mail: Auto-discover .team-mail directory and persist env vars.

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CLI="$SCRIPT_DIR/cli/team_mail.py"

if [ -n "$CLAUDE_ENV_FILE" ]; then
  # Always export the CLI path so commands can find it
  echo "export TEAM_MAIL_CLI=\"$CLI\"" >> "$CLAUDE_ENV_FILE"

  # Auto-discover .team-mail directory and set env vars
  # The Python CLI handles all discovery logic
  ENV_OUTPUT=$(uv run "$CLI" env 2>/dev/null)
  if [ -n "$ENV_OUTPUT" ]; then
    echo "$ENV_OUTPUT" >> "$CLAUDE_ENV_FILE"
  fi
fi

# If token is set, show identity on session start
if [ -n "$TEAM_MAIL_TOKEN" ] && [ -n "$TEAM_MAIL_DIR" ]; then
  IDENTITY=$(uv run "$CLI" profile show 2>/dev/null)
  if [ -n "$IDENTITY" ]; then
    echo "$IDENTITY"
  fi
fi

exit 0
