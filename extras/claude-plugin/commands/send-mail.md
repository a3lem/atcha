---
allowed-tools: Bash
argument-hint: "<to> <message>"
---

Send a message to another user.

## Arguments

Parse `$ARGUMENTS` to extract:
- `to`: recipient username (required)
- `message`: message body (required)

## Steps

1. If `$TEAM_MAIL_TOKEN` is not set, tell user to set it first (see `/identify`).

2. Send the message:

```bash
uv run "$TEAM_MAIL_CLI" send "<to>" "<message>"
```

The CLI automatically:
- Uses your identity from the token
- Generates a timestamp
- Writes to recipient inbox and your sent log

3. Print confirmation from CLI output.

## Example

```bash
uv run "$TEAM_MAIL_CLI" send alex-frontend "Auth API is ready for integration"
```

Output:
```json
{"status": "delivered", "to": "alex-frontend", "ts": "2026-01-30T12:00:00Z"}
```
