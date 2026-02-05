# atcha

File-based messaging between parallel Claude Code sessions. No MCP servers, no daemons, no databases — just JSONL files, a Python CLI, and token-based authentication.

## How it works

Each user has a directory with `profile.json` and a `mail/` subdirectory containing their inbox and sent messages. When a user sends a message, the CLI writes directly to the recipient's inbox. A PostToolUse hook checks for new messages after each tool call.

Authentication uses short random tokens stored as hashes. Set `$ATCHA_TOKEN` to authenticate as a user.

## Quick Start

### 1. Initialize the system

```bash
cd your-project

# Initialize (will prompt for password)
atcha init

# Or with password directly
atcha init --password secret123
```

This creates `.atcha/` with the admin config, tokens directory, and users directory.

### 2. Set admin password

```bash
# Set admin password for subsequent commands
export ATCHA_ADMIN_PASS=secret123
```

### 3. Create users

```bash
# Create a user (requires admin password)
atcha admin users add --name maya-backend --role "Backend Engineer" --tags=backend,auth

# Create another user
atcha admin users add --name alex-frontend --role "Frontend Dev" --tags=frontend,ui
```

### 4. Get user tokens

```bash
# Get tokens for your users
USER_MAYA_TOKEN=$(atcha create-token --user maya-backend)
USER_ALEX_TOKEN=$(atcha create-token --user alex-frontend)
```

### 5. Start collaborating

```bash
# As Maya, send a message to Alex
export ATCHA_TOKEN=$USER_MAYA_TOKEN
python cli/atcha.py send --to alex-frontend "Auth API is ready for integration"

# As Alex, check inbox
export ATCHA_TOKEN=$USER_ALEX_TOKEN
atcha messages check
# → 1 unread message from maya-backend

# Read messages (marks as read)
atcha messages read
# → {"from":"maya-backend","to":["alex-frontend"],"ts":"...","type":"message","content":"Auth API is ready for integration"}
```

## Using with Claude Code

With the plugin installed, use slash commands instead of the CLI directly:

| Command | Description |
|---------|-------------|
| `/init-workspace` | Initialize atcha (sets admin password) |
| `/register <description>` | Create new user from natural language description |
| `/identify` | Show your identity (from token) |
| `/signin --status="..." --tags=t1,t2` | Update your profile |
| `/whoami` | Show your profile |
| `/profile <user-name>` | View another user's profile |
| `/send-mail <to> <message>` | Send a message to one user |
| `/broadcast-mail [--tag=X] <message>` | Broadcast to all or tagged users |
| `/team` | List all users with profiles |
| `/tags` | List all tags with counts |
| `/check-mail` | Read inbox and mark as read |

## CLI Reference

### Setup commands (require admin password)

```bash
# Initialize system (prompts for password if not provided)
atcha init
atcha init --password <password>

# Check if initialized (useful in hooks)
atcha init --check  # exits 0 if initialized, 1 if not

# Change password
atcha admin password --old <old> --new <new>

# Create user token
atcha create-token --user <user-name>

# Create user (requires ATCHA_ADMIN_PASS or --password)
atcha admin users add --name <name> --role <role> [--status=...] [--tags=...] [--about=...]
```

### User commands (require token in $ATCHA_TOKEN)

```bash
# List all users
atcha contacts

# View profiles
atcha whoami               # Print your username
atcha contacts $(atcha whoami)  # Your full profile
atcha contacts <user-name> # Someone else's profile

# Update profile
atcha profile update --status="Working on auth" --tags=backend,api

# Check inbox
atcha messages check          # Summary (count + senders)
atcha messages list           # JSON array with previews (no side effects)
atcha messages read           # Full messages as JSONL, marks as read

# Send message
atcha send --to <recipient> "<message>"
```

## Directory structure

```
.atcha/
├── admin.json              # {"password_hash": "...", "salt": "..."}
├── tokens/
│   ├── _admin              # Hash of admin token
│   └── maya-backend        # Hash of user token
└── users/
    ├── maya-backend/
    │   ├── profile.json
    │   └── mail/
    │       ├── inbox.jsonl
    │       ├── sent.jsonl
    │       └── state.json
    └── alex-frontend/
        └── ...
```

## User name format

Names follow the pattern `{firstname}-{role-slug}`:
- `maya-backend-engineer`
- `alex-frontend-specialist`
- `kai-auth-expert`

Validation rules:
- Lowercase letters, numbers, and dashes only
- 3-40 characters
- No consecutive dashes
- No leading/trailing dashes

## Multi-worktree setup

Each git worktree can have its own `.atcha/` directory, or they can share one. Set `$ATCHA_DIR` to point to a shared directory:

```bash
# Worktree A - Backend engineer
export ATCHA_DIR=/path/to/shared/.atcha
export ATCHA_TOKEN=$USER_MAYA_TOKEN

# Worktree B - Frontend engineer
export ATCHA_DIR=/path/to/shared/.atcha
export ATCHA_TOKEN=$USER_ALEX_TOKEN
```

## Environment variables

| Variable | Description |
|----------|-------------|
| `ATCHA_DIR` | Path to `.atcha/` directory (auto-discovered if not set) |
| `ATCHA_TOKEN` | Authentication token for the current user |
| `ATCHA_ADMIN_PASS` | Admin password (alternative to `--password` for admin operations) |
| `ATCHA_CLI` | Path to CLI script (set by SessionStart hook for plugin) |

## Message format

```json
{"id":"msg-abc12345","thread_id":"msg-abc12345","from":"maya-backend","to":["alex-frontend"],"ts":"2026-01-27T10:00:00Z","type":"message","content":"Changed auth exports"}
```

Note: Old messages with `body` field are still readable for backward compatibility.

## Development

```bash
cd plugins/atcha
uv sync
uv run pytest tests/ -v
```

## Requirements

- Python 3.11+
- uv (for running tests and CLI)
