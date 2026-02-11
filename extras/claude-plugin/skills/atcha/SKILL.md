---
name: atcha
description: Send and receive messages with other AI users working in parallel.
allowed-tools: [Bash(atcha:*)]
---

# Atcha

Message other AI users running in parallel. Each user has a unique identity determined by `$ATCHA_TOKEN`.

## Essential Commands

### Check your identity
```bash
atcha whoami               # Prints just your username
atcha contacts $(atcha whoami)  # View your full profile
```
Output: `maya-backend` (just the username)

### Find other users
```bash
atcha contacts                # JSON array of profiles (excludes you by default)
atcha contacts --names-only   # Just names, one per line
atcha contacts --include-self # Include yourself in the list
```

Note: `contacts` has no `list` subcommand - just use `atcha contacts` to list all.

### Send a message
```bash
atcha send --to <recipient> "<message>"
atcha send --to <recipient1> --to <recipient2> "<message>"  # Multiple recipients
atcha send --broadcast "<message>"                            # Broadcast to all
```
Example: `atcha send --to alex-frontend "API is ready for integration"`

### Read your inbox
```bash
atcha messages check     # Summary: "2 unread messages: 1 from alice, 1 from bob"
atcha messages list      # JSON array with previews (does NOT mark as read)
atcha messages read      # Full messages as JSONL (marks as read)
```

---

## Filters & Profile Updates

### Filter users by tag
```bash
atcha contacts --tags=backend,auth
```

### Update your profile
```bash
atcha profile update --status "Working on auth refactor"
atcha profile update --tags "backend,api"
atcha profile update --about "I handle API development"
```

### Filter inbox messages
```bash
atcha messages read --from alice                    # Only from alice
atcha messages read --since "2026-01-30T12:00:00Z"  # After timestamp
atcha messages read --include-read                  # Include already-read
atcha messages read --no-mark                       # Read without marking as read
atcha messages list --limit 5                       # Last 5 messages
atcha messages list --no-preview                    # Full content instead of preview
```

### View another user's profile
```bash
atcha contacts alex-frontend
atcha contacts alex-frontend --full  # Include dates
```

---

## Admin Setup & Troubleshooting

### First-time setup (admin only)
```bash
# Initialize
atcha init --password <password>
export ATCHA_ADMIN_PASS=<password>

# Create users
atcha admin users add --name anna --role "CLI Specialist"
# Auto-generates id: usr-XXXXX (random)

atcha admin users add --name maya --role "Backend Engineer"
# Auto-generates id: usr-XXXXX (random)

# Generate tokens for users
atcha admin create-token --user anna
atcha admin create-token --user maya
```

### Admin commands reference

```bash
# List all users
atcha contacts --include-self  # Uses admin auth (--password or $ATCHA_ADMIN_PASS)

# Add a new user
atcha admin users add --name <short-name> --role "<Role>" [--tags=tag1,tag2] [--about="..."]

# Create user token
atcha admin create-token --user <name-or-id>

# Change admin password
atcha admin password --password <old> --new <new>
```

### Check initialization status
```bash
# Check if atcha is initialized (useful in hooks)
atcha admin status
# Exits with 0 if initialized, 1 if not. Prints "Atcha initialized" on success.
# Use -q/--quiet to suppress output (exit code only)
atcha admin status -q
```

### User ID format
User IDs are randomly generated with the `usr-` prefix:
- `usr-a3k9m`, `usr-7x2pq`, `usr-3n8qr`
- IDs are immutable and auto-assigned on user creation
- Users are referenced by name in commands (e.g., `anna`, `maya`)

### Troubleshooting

**"No token provided"**
```
FIX: Set $ATCHA_TOKEN or use --token <token>
```

**"User not found"**
```bash
atcha contacts --names-only  # See available users
```

**"Invalid token"**
Ask admin to regenerate: `atcha admin create-token --user <name>`

---

## Output Formats

| Command | Format | Example |
|---------|--------|---------|
| `contacts` | JSON array | `[{"name":"alice","role":"Engineer"}]` |
| `contacts <name>` | JSON object | `{"name":"alice","role":"Engineer"}` |
| `whoami` | Text | `alice` |
| `messages check` | Text | `2 unread messages: 1 from bob` |
| `messages list` | JSON array | `[{"from":"bob","ts":"...","preview":"Hello..."}]` |
| `messages read` | JSONL | `{"from":"bob","ts":"...","content":"..."}` |
| `send` | JSON | `{"status":"delivered","to":["bob"]}` |

Most commands support `--json` for machine-parsable output (e.g., `whoami --json` → `{"name":"alice"}`, `messages check --json` → `{"count":2,"senders":{"bob":2}}`).

## Tips

1. **Check inbox regularly** when you start work or finish a task
2. **Update your status** so others know what you're working on
3. **Use tags** to indicate your expertise areas
4. **Be specific** in messages: what changed, why it matters, what's needed
5. **Coordinate early** before starting work that might conflict with others
