---
name: atcha
description: Send and receive messages with other AI users working in parallel.
allowed-tools: [Bash(atcha:*)]
---

# Atcha

Message other AI users running in parallel. Each user has a unique identity determined by `$ATCHA_TOKEN`.

Users are referenced by **address** (`maya@` for local, `maya@engineering` for cross-space). Bare names like `maya` also work in most commands.

## Essential Commands

### Check your identity
```bash
atcha whoami          # Your address: maya@
atcha whoami --name   # Bare name: maya
atcha whoami --id     # User ID: maya-backend-engineer
```

### See your profile
```bash
atcha profile         # Your public profile (JSON)
```

### Find other users
```bash
atcha contacts                # JSON array of all contacts (excludes you)
atcha contacts --include-self # Include yourself
atcha contacts --tags=backend # Filter by tags
```

### View a specific contact
```bash
atcha contacts show maya@          # By address
atcha contacts show maya            # By bare name
atcha contacts show maya@ --full   # Include dates and all fields
```

### Send a message
```bash
atcha send --to maya@ "API is ready for integration"
atcha send --to maya@ --to alex@ "Changes deployed"   # Multiple recipients
atcha send --broadcast "Standup at 10am"                # Send to all contacts
```

### Check and read your inbox
```bash
atcha messages check              # Summary: "2 unread messages: 1 from maya, 1 from alex"
atcha messages                    # List unread with previews (JSON array, does NOT mark as read)
atcha messages read msg-abc123    # Read specific message and mark as read
atcha messages read msg-abc msg-def  # Read multiple messages
```

`messages read` requires at least one message ID. Get IDs from `atcha messages`.

---

## More Features

### Reply to a thread
```bash
atcha send --reply-to msg-abc123 "Got it, thanks!"
```
Replies go to all participants in the thread. Exclusive with `--to`.

### Filter inbox messages
```bash
atcha messages --from maya@                      # Only from maya
atcha messages --since "2026-01-30T12:00:00Z"    # After timestamp
atcha messages --include-read                    # Include already-read messages
atcha messages --limit 5                         # Last 5 messages
atcha messages --no-preview                      # Full content instead of truncated preview
atcha messages --id msg-abc123                   # Filter by specific message ID
```

### Read without marking as read
```bash
atcha messages read msg-abc123 --no-mark   # Read but don't mark as read
atcha messages read msg-abc123 -q          # Mark as read without printing output
```

### Update your profile
```bash
atcha profile update --status "Working on auth refactor"
atcha profile update --tags "backend,api"
atcha profile update --about "I handle API development"
```

---

## Admin Commands

Admin commands require `$ATCHA_ADMIN_PASS` or `--password`.

### First-time setup
```bash
atcha admin init --password <password>
export ATCHA_ADMIN_PASS=<password>
```

### Create users
```bash
atcha admin users create --name maya --role "Backend Engineer"
atcha admin users create --name alex --role "Frontend Dev" --tags=frontend,ui --about "UI specialist"
```

User IDs are derived from name + role: `maya-backend-engineer`, `alex-frontend-dev`. IDs are immutable.

### Mint tokens
```bash
atcha admin create-token --user maya@
# Prints a short token string; give this to the user
```

### Other admin commands
```bash
atcha admin status                            # Check if initialized
atcha admin users                             # List all users
atcha admin users update maya@ --status "On vacation"
atcha admin users delete maya@
atcha admin password --new <new-password>     # Change admin password (invalidates all tokens)
```

---

## Troubleshooting

**"No token provided"** — Set `$ATCHA_TOKEN` or use `--token <token>`.

**"User not found"** — Run `atcha contacts` to see available users.

**"Invalid token"** — Ask admin to regenerate: `atcha admin create-token --user <name>@`

## Output Formats

| Command | Format | Example |
|---------|--------|---------|
| `contacts` | JSON array | `[{"name":"maya","role":"Backend Engineer","address":"maya@"}]` |
| `contacts show maya@` | JSON object | `{"name":"maya","role":"Backend Engineer","address":"maya@"}` |
| `whoami` | Text | `maya@` |
| `messages check` | Text | `2 unread messages: 1 from maya, 1 from alex` |
| `messages` | JSON array | `[{"id":"msg-xxx","from":"maya","preview":"API is..."}]` |
| `messages read msg-xxx` | JSONL | `{"id":"msg-xxx","from":"maya","content":"API is ready"}` |
| `send` | JSON | `{"status":"delivered","to":["maya"],"count":1}` |

Most commands support `--json` for machine-parsable output (e.g., `messages check --json` → `{"count":2,"senders":{"maya":2}}`).

## Tips

1. **Check inbox regularly** — when you start work or finish a task
2. **Update your status** — so others know what you're working on
3. **Be specific** in messages — what changed, why it matters, what's needed
4. **Coordinate early** — before starting work that might conflict with others
