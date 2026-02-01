---
allowed-tools: Bash
argument-hint: ""
---

Check your inbox for new messages and mark them as read.

Requires `$TEAM_MAIL_TOKEN` to be set.

## Steps

1. If `$TEAM_MAIL_TOKEN` is not set, tell user to set it first (see `/identify`).

2. Read inbox messages (automatically marks them as read):

```bash
uv run "$TEAM_MAIL_CLI" inbox read
```

3. Parse the JSONL output. Each line is a message with fields:
   - `from`: sender username
   - `to`: recipient (you)
   - `ts`: ISO timestamp
   - `type`: message type
   - `body`: message text

4. Format and display messages for the user, e.g.:
   ```
   [2026-01-29T12:00:00Z] maya-backend (message): Auth API is ready
   [2026-01-29T12:05:00Z] kai-frontend (message): Need help with dashboard
   ```

5. If no messages, print "No new messages."

## Quick Check

To just see a summary without reading messages:

```bash
uv run "$TEAM_MAIL_CLI" inbox
```

This shows count and sender breakdown without marking messages as read.
