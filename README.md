# team-mail

File-based messaging between parallel Claude Code sessions. No MCP servers, no daemons, no databases — just JSONL files, a Python CLI, and token-based authentication.

## How it works

Each agent has a directory with `profile.json` and a `mail/` subdirectory containing their inbox and sent messages. When an agent sends a message, the CLI writes directly to the recipient's inbox. A PostToolUse hook checks for new messages after each tool call.

Authentication uses short random tokens stored as hashes. Set `$TEAM_MAIL_TOKEN` to authenticate as an agent.

## Quick Start

### 1. Initialize the system

```bash
cd your-project

# Initialize (will prompt for password)
team-mail init

# Or with password directly
team-mail init --password secret123
```

This creates `.team-mail/` with the admin config, tokens directory, and agents directory.

### 2. Set admin password

```bash
# Set admin password for subsequent commands
export TEAM_MAIL_ADMIN_PASS=secret123
```

### 3. Create agents

```bash
# Create an agent (requires admin password)
team-mail agents add --name maya-backend --role "Backend Engineer" --tags=backend,auth

# Create another agent
team-mail agents add --name alex-frontend --role "Frontend Dev" --tags=frontend,ui
```

### 4. Get agent tokens

```bash
# Get tokens for your agents
MAYA_TOKEN=$(team-mail create-token --agent maya-backend)
ALEX_TOKEN=$(team-mail create-token --agent alex-frontend)
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
| `/register <description>` | Create new agent from natural language description |
| `/identify` | Show your identity (from token) |
| `/signin --status="..." --tags=t1,t2` | Update your profile |
| `/whoami` | Show your profile |
| `/profile <agent-name>` | View another agent's profile |
| `/send-mail <to> <message>` | Send a message to one agent |
| `/broadcast-mail [--tag=X] <message>` | Broadcast to all or tagged agents |
| `/team` | List all agents with profiles |
| `/tags` | List all tags with counts |
| `/check-mail` | Read inbox and mark as read |

## CLI Reference

### Setup commands (require admin password)

```bash
# Initialize system (prompts for password if not provided)
team-mail init
team-mail init --password <password>

# Check if initialized (useful in hooks)
team-mail init --check  # exits 0 if initialized, 1 if not

# Change password
team-mail admin password --old <old> --new <new>

# Create agent token
team-mail create-token --agent <agent-name>

# Create agent (requires TEAM_MAIL_ADMIN_PASS or --password)
team-mail agents add --name <name> --role <role> [--status=...] [--tags=...] [--about=...]
```

### Agent commands (require token in $TEAM_MAIL_TOKEN)

```bash
# List all agents
team-mail agents list

# View profiles
team-mail profile show         # Your profile
team-mail whoami               # Alias for profile show
team-mail agents get <agent-name> # Someone else's (no token needed)

# Update profile
team-mail profile update --status="Working on auth" --tags=backend,api

# Check inbox
team-mail inbox                # Summary
team-mail inbox read           # Full messages, marks as read

# Send message
team-mail send <recipient> "<message>"
```

## Directory structure

```
.team-mail/
├── admin.json              # {"password_hash": "...", "salt": "..."}
├── tokens/
│   ├── _admin              # Hash of admin token
│   └── maya-backend        # Hash of agent token
└── agents/
    ├── maya-backend/
    │   ├── profile.json
    │   └── mail/
    │       ├── inbox.jsonl
    │       ├── sent.jsonl
    │       └── state.json
    └── alex-frontend/
        └── ...
```

## Agent name format

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
| `TEAM_MAIL_TOKEN` | Authentication token for the current agent |
| `TEAM_MAIL_ADMIN_PASS` | Admin password (alternative to `--password` for admin operations) |
| `TEAM_MAIL_CLI` | Path to CLI script (set by SessionStart hook for plugin) |

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
