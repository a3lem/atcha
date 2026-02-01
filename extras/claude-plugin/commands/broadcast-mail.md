---
allowed-tools: Bash
argument-hint: "[--tag=<tag>] <message>"
---

Broadcast a message to all users, optionally filtered by tag.

Requires `$TEAM_MAIL_TOKEN` to be set.

## Arguments

Parse `$ARGUMENTS` to extract:
- `tag` (optional): only send to users with this tag
- `message`: message body (required)

## Steps

1. If `$TEAM_MAIL_TOKEN` is not set, tell user to set it first (see `/identify`).

2. Get list of all users:

```bash
uv run "$TEAM_MAIL_CLI" team
```

3. Get your own identity to exclude yourself:

```bash
uv run "$TEAM_MAIL_CLI" profile
```

4. If filtering by tag, for each user check their profile:

```bash
uv run "$TEAM_MAIL_CLI" profile "<username>"
```

Skip users whose `tags` array doesn't include the filter tag.

5. For each recipient (excluding yourself), send the message:

```bash
uv run "$TEAM_MAIL_CLI" send "<recipient>" "<message>"
```

6. Print summary: "Broadcast to N users: <message>"

## Example

If you run `/broadcast-mail --tag=backend "API breaking change in v2"`:
1. List users
2. Filter to those with "backend" tag
3. Exclude yourself
4. Send to each matching user
