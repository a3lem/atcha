# Atcha Advanced Examples

Edge cases, advanced patterns, and less common workflows.

## Threading and replies

`--reply-to` sends to all participants in the thread — you don't choose recipients:

```bash
atcha send --reply-to msg-abc123 "Got it, thanks!"
```

- `--reply-to` is **exclusive** with `--to` (can't combine them)
- `--reply-to` is **exclusive** with `--broadcast`
- The reply inherits the thread ID from the original message
- All users who participated in the thread receive the reply

## Filtering messages

Filters can be combined:

```bash
# Everything from maya since yesterday, limit 5
atcha messages --from maya@ --since "2026-01-30T12:00:00Z" --limit 5

# Include already-read messages (default: unread only)
atcha messages --include-read

# Full content instead of truncated preview
atcha messages --no-preview

# Filter by thread
atcha messages --thread thread-abc123

# Filter by specific message ID (repeatable)
atcha messages --id msg-abc --id msg-def
```

## Read modes

```bash
# Read all unread messages at once
atcha messages read --all

# Read without marking as read (peek)
atcha messages read msg-abc123 --no-mark

# Mark as read without printing output (silent acknowledge)
atcha messages read msg-abc123 -q

# Combine: silently mark everything as read
atcha messages read --all -q
```

## Cross-space messaging

Address users in other spaces with `name@space`:

```bash
# Send to maya in the "engineering" space
atcha send --to maya@engineering "Hello from here"

# View a cross-space contact
atcha contacts show maya@engineering
```

Local users use `name@` (trailing @) or just `name`.

## Admin: acting as a user

Admins can impersonate users with `--as-user <user-id>` on any user command.
Requires `--password` or `$ATCHA_ADMIN_PASS`.

```bash
# Check a user's inbox
atcha messages --password=secret --as-user maya-backend-engineer check

# Send on behalf of a user
atcha send --password=secret --as-user maya-backend-engineer --to alex@ "Hello"

# Update a user's profile
atcha profile update --password=secret --as-user maya-backend-engineer --status "On vacation"
```

Note: `--as-user` takes a **user ID** (e.g. `maya-backend-engineer`), not a bare name.

## Multiple recipients

```bash
# Send to specific people
atcha send --to maya@ --to alex@ "Changes deployed"

# Or broadcast to all contacts
atcha send --broadcast "Standup at 10am"
```

`--broadcast` and `--to` are exclusive — you can't combine them.

## Error recovery

Errors follow a structured format:

```
ERROR: <what went wrong>
AVAILABLE: <options if applicable>
FIX: <how to recover>
```

Common errors:

| Error | Cause | Fix |
|-------|-------|-----|
| "No token provided" | Missing `$ATCHA_TOKEN` | Set token or use `--token` |
| "User not found" | Bad name/address | Run `atcha contacts` to see available users |
| "Invalid token" | Token mismatch | Ask admin to regenerate with `atcha admin create-token` |
| "--password authenticates as admin" | Used `--password` on a user command | Add `--as-user <id>` or switch to `--token` |

## JSON output

Most text-output commands support `--json` for machine-parsable output:

```bash
atcha messages check --json    # {"count": 2, "senders": {"maya": 2}}
atcha whoami --json            # {"address": "maya@"}
atcha admin status --json      # {"initialized": true}
```

Commands that already output JSON (`contacts`, `messages`, `send`, `profile`) are unaffected by `--json`.
