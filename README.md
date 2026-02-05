# atcha

File-based messaging between parallel AI agent sessions. No MCP servers, no daemons, no databases — just JSONL files, a Python CLI, and token-based authentication.

## How it works

Each user has a directory with `profile.json` and a `mail/` subdirectory containing their inbox and sent messages. When a user sends a message, the CLI writes directly to the recipient's inbox. A PostToolUse hook checks for new messages after each tool call.

Authentication uses short random tokens stored as hashes. Set `$ATCHA_TOKEN` to authenticate as a user.

## Quick Start

### 1. Install

```bash
git clone <repo-url>
cd agent-team-mail
uv tool install -e .
```

This installs the `atcha` command in your local bin.

### 2. Initialize the system

```bash
# Initialize (will prompt for admin password)
atcha init

# Or with password directly
atcha init --password secret123
```

This creates `.atcha/` with the admin config, tokens directory, and users directory.

### 3. Set admin password

```bash
# Set admin password for subsequent commands
export ATCHA_ADMIN_PASS=secret123
```

### 4. Create users

```bash
# Create a user (requires admin password)
atcha admin users add --name maya --role "Backend Engineer" --tags=backend,auth

# Create another user
atcha admin users add --name alex --role "Frontend Dev" --tags=frontend,ui
```

### 5. Get user token and start using atcha

```bash
# Get token for a specific user (give this token only to that user)
atcha create-token --user maya
# → a3k9m

# Use the token to authenticate as that user
export ATCHA_TOKEN=a3k9m

# Send a message
atcha send --to alex "Auth API is ready for integration"

# Check inbox
atcha messages check
# → 1 unread message from alex

# Read messages (marks as read)
atcha messages read
# → {"from":"alex","ts":"...","type":"message","content":"Thanks, will integrate today"}
```

**Security note:** Each user should only have access to their own token. Never store multiple user tokens in the same environment.

## Using with Claude Code

Install the Claude Code skill from `extras/claude-plugin/skills/atcha/` to use atcha with Claude Code. The skill provides a simplified interface to the CLI commands for common operations like sending messages and checking your inbox.

### Running as a user

Launch Claude Code with a user token to give the agent a specific identity. The agent can send and receive messages but cannot create users or impersonate others.

```bash
ATCHA_TOKEN=$(atcha create-token --user bashir --password test) claude
```

The agent never knows the admin password and cannot impersonate other users.

### Running as an admin

Launch Claude Code with the admin password to enable user management. This is useful for setting up the system and creating users.

```bash
ATCHA_ADMIN_PASS=test claude
```

Example prompt to an agent with admin powers:

```
Create two new atcha users:

  - Anna. Specialized in CLI design for AI agents. Agent Anna takes into account the needs of LLMs.
  - Bashir. New agent on the team. Will ask questions. Fresh pair of eyes.
```

The agent will create the users with appropriate names, roles, and descriptions.

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
atcha admin users add --name <short-name> --role <role> [--status=...] [--tags=...] [--about=...]
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
│   └── usr-a3k9m           # Hash of user token
└── users/
    ├── usr-a3k9m/
    │   ├── profile.json
    │   └── mail/
    │       ├── inbox.jsonl
    │       ├── sent.jsonl
    │       └── state.json
    └── usr-7x2pq/
        └── ...
```

## User identifiers

Each user has a **name** (short, unique identifier like `maya`) and an **id** (random alphanumeric sequence). The id is auto-generated when the user is created.

Both name and id can be used in commands:
```bash
atcha contacts maya        # by name (preferred)
atcha contacts usr-7x3km   # by id
atcha send --to maya "Hello"
```

Examples:
- Name: `maya`, ID: `a3k9m`
- Name: `alex`, ID: `7x2pq`

The name must be unique across all users. The id is randomly generated and immutable.

## Multi-worktree setup

Each git worktree can have its own `.atcha/` directory, or they can share one. Set `$ATCHA_DIR` to point to a shared directory:

```bash
# Worktree A - Maya's session
export ATCHA_DIR=/path/to/shared/.atcha
export ATCHA_TOKEN=a3k9m  # Maya's token

# Worktree B - Alex's session
export ATCHA_DIR=/path/to/shared/.atcha
export ATCHA_TOKEN=7x2pq  # Alex's token
```

Each worktree should only have access to one user's token.

## Environment variables

| Variable | Description |
|----------|-------------|
| `ATCHA_DIR` | Path to `.atcha/` directory (auto-discovered if not set) |
| `ATCHA_TOKEN` | Authentication token for the current user |
| `ATCHA_ADMIN_PASS` | Admin password (alternative to `--password` for admin operations) |

## Message format

Messages use the `content` field for message body:

```json
{"id":"msg-abc12345","thread_id":"msg-abc12345","from":"maya","to":["alex"],"ts":"2026-01-27T10:00:00Z","type":"message","content":"Changed auth exports"}
```

## Development

```bash
uv sync
uv run pytest tests/ -v
```

## Requirements

- Python 3.11+
- uv
