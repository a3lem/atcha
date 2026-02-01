# team-mail

File-based messaging between parallel Claude Code sessions. No MCP servers, no daemons, no databases — just JSONL files, a Python CLI, and token-based authentication.

## How it works

Each user has a directory with `profile.json` and a `mail/` subdirectory containing their inbox and sent messages. When a user sends a message, the CLI writes directly to the recipient's inbox. A PostToolUse hook checks for new messages after each tool call.

Authentication uses short random tokens stored as hashes. Set `$TEAM_MAIL_TOKEN` to authenticate as a user.

## Quick Start

### 1. Initialize the system

```bash
cd your-project

# Initialize with an admin password
python cli/team_mail.py admin init --password secret123
```

This creates `.team-mail/` with the admin config, tokens directory, and users directory.

### 2. Get an admin token

```bash
# Mint an admin token (needed to create users)
ADMIN_TOKEN=$(python cli/team_mail.py admin auth --admin --password secret123)
export TEAM_MAIL_TOKEN=$ADMIN_TOKEN
```

### 3. Create users

```bash
# Create a user (requires admin token)
python cli/team_mail.py admin create maya-backend "Backend Engineer" --tags=backend,auth

# Create another user
python cli/team_mail.py admin create alex-frontend "Frontend Dev" --tags=frontend,ui
```

### 4. Get user tokens

```bash
# Get tokens for your users
MAYA_TOKEN=$(python cli/team_mail.py admin auth --user maya-backend --password secret123)
ALEX_TOKEN=$(python cli/team_mail.py admin auth --user alex-frontend --password secret123)
```

### 5. Start collaborating

```bash
# As Maya, send a message to Alex
export TEAM_MAIL_TOKEN=$MAYA_TOKEN
python cli/team_mail.py send alex-frontend "Auth API is ready for integration"

# As Alex, check inbox
export TEAM_MAIL_TOKEN=$ALEX_TOKEN
python cli/team_mail.py inbox
# → 1 unread message from maya-backend

# Read messages (marks as read)
python cli/team_mail.py inbox read
# → {"from":"maya-backend","to":"alex-frontend","ts":"...","type":"message","body":"Auth API is ready for integration"}
```

## Using with Claude Code

With the plugin installed, use slash commands instead of the CLI directly:

| Command | Description |
|---------|-------------|
| `/init-workspace` | Initialize team-mail (sets admin password) |
| `/register <description>` | Create new user from natural language description |
| `/identify` | Show your identity (from token) |
| `/signin --status="..." --tags=t1,t2` | Update your profile |
| `/whoami` | Show your profile |
| `/profile <username>` | View another user's profile |
| `/send-mail <to> <message>` | Send a message to one user |
| `/broadcast-mail [--tag=X] <message>` | Broadcast to all or tagged users |
| `/team` | List all users with profiles |
| `/tags` | List all tags with counts |
| `/check-mail` | Read inbox and mark as read |

## CLI Reference

### Admin commands (require password)

```bash
# Initialize system
python cli/team_mail.py admin init --password <password>

# Change password
python cli/team_mail.py admin password --old <old> --new <new>

# Mint tokens
python cli/team_mail.py admin auth --admin --password <password>
python cli/team_mail.py admin auth --user <username> --password <password>

# Create user (requires admin token in $TEAM_MAIL_TOKEN)
python cli/team_mail.py admin create <username> <title> [--status=...] [--tags=...] [--about=...]
```

### User commands (require token in $TEAM_MAIL_TOKEN)

```bash
# List all users
python cli/team_mail.py users list

# View profiles
python cli/team_mail.py profile show         # Your profile
python cli/team_mail.py users get <username> # Someone else's (no token needed)

# Update profile
python cli/team_mail.py profile update --status="Working on auth" --tags=backend,api

# Check inbox
python cli/team_mail.py inbox                # Summary
python cli/team_mail.py inbox read           # Full messages, marks as read

# Send message
python cli/team_mail.py send <recipient> "<message>"
```

## Directory structure

```
.team-mail/
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

## Username format

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

Each git worktree can have its own `.team-mail/` directory, or they can share one. Set `$TEAM_MAIL_DIR` to point to a shared directory:

```bash
# Worktree A - Backend engineer
export TEAM_MAIL_DIR=/path/to/shared/.team-mail
export TEAM_MAIL_TOKEN=$MAYA_TOKEN

# Worktree B - Frontend engineer
export TEAM_MAIL_DIR=/path/to/shared/.team-mail
export TEAM_MAIL_TOKEN=$ALEX_TOKEN
```

## Environment variables

| Variable | Description |
|----------|-------------|
| `TEAM_MAIL_DIR` | Path to `.team-mail/` directory (auto-discovered if not set) |
| `TEAM_MAIL_TOKEN` | Authentication token for the current user |
| `TEAM_MAIL_CLI` | Path to `cli/team_mail.py` (set by SessionStart hook) |

## Message format

```json
{"from":"maya-backend","to":"alex-frontend","ts":"2026-01-27T10:00:00Z","type":"message","body":"Changed auth exports"}
```

## Development

```bash
cd plugins/team-mail
uv sync
uv run pytest tests/ -v
```

## Requirements

- Python 3.11+
- uv (for running tests and CLI)
