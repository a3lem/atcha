# team-mail

## What this is

A file-based messaging system for parallel Claude Code sessions. Users running in separate git worktrees can send each other messages through JSONL files on the filesystem. No MCP servers, no daemons, no databases.

The Python CLI (`team-mail`) provides a hierarchical command structure with token-based authentication. Claude Code commands handle higher-level logic like name generation and message formatting.

## Architecture

A `.team-mail/` directory lives at the project root and contains admin config, tokens, and user data. Users authenticate via tokens stored in `$TEAM_MAIL_TOKEN`.

Each user gets a directory under `.team-mail/users/` with their profile and mail. Sending a message means appending a JSON line directly to the recipient's `inbox.jsonl`. A PostToolUse hook checks for new messages after every tool call.

### Directory structure

```
.team-mail/
├── admin.json              # {"password_hash": "...", "salt": "..."}
├── tokens/
│   ├── _admin              # hash of admin token
│   └── <username>          # hash of user token
└── users/
    └── <username>/
        ├── profile.json
        └── mail/
            ├── inbox.jsonl
            ├── sent.jsonl
            └── state.json
```

### profile.json

```json
{
  "name": "maya-backend-engineer",
  "role": "Backend Engineer",
  "status": "Refactoring auth module",
  "about": "I handle backend services and API development.",
  "tags": ["auth", "backend"],
  "joined": "2026-01-27T10:00:00Z",
  "updated": "2026-01-29T14:30:00Z"
}
```

The filesystem is the registry — a user exists if their directory exists.

### Username format

Names follow the pattern `{random-name}-{role-slug}`:
- `maya-backend-engineer`
- `alex-frontend-specialist`
- `kai-auth-expert`

Validation rules:
- Lowercase letters, numbers, and dashes only
- 3-40 characters
- No consecutive dashes
- No leading/trailing dashes

### Authentication model

- Password stored as hash in `.team-mail/admin.json`
- Tokens are 5-char random strings, stored in plain text in `.team-mail/tokens/`
- `$TEAM_MAIL_TOKEN` env var required for all non-admin operations
- Admin token (`_admin`) grants elevated privileges (create users)
- User token grants access to own profile + mail operations

### Message flow

1. User A (authenticated via token) runs `/send-mail alex-frontend "Changed auth exports"`
2. The CLI uses the token to identify the sender and appends to `alex-frontend/mail/inbox.jsonl`
3. A copy goes to sender's `mail/sent.jsonl` atomically
4. On user B's next tool call, the `check-inbox.sh` hook fires, sees the new message, and prints it to stdout
5. User B runs `/check-mail` (which uses `inbox read`) to read and mark messages as read

### Env vars

- `TEAM_MAIL_DIR` — absolute path to `.team-mail/` directory. Auto-discovered by SessionStart hook.
- `TEAM_MAIL_TOKEN` — authentication token for the current user.
- `TEAM_MAIL_CLI` — (plugin only) absolute path to CLI script. Set by SessionStart hook.

When the package is installed (`uv sync` or `pip install -e .`), use `team-mail` directly.

## CLI Commands

The CLI provides a hierarchical structure with token-based authentication.

### Authentication options

All commands requiring authentication support these options (priority order):

1. `--password <pw>` — Admin password (requires `--user` for user operations)
2. `--token <token>` — Auth token (user or admin)
3. `$TEAM_MAIL_TOKEN` — Env var fallback

Admin commands can use `--password` directly. User commands require `--token` or `$TEAM_MAIL_TOKEN`.

### Admin impersonation

Commands that self-identify (profile, inbox, send) accept `--user <name>` with admin auth:

```bash
# Check alice's inbox as admin
team-mail inbox --password=secret --user=alice

# Send from alice to bob as admin
team-mail send --password=secret --user=alice bob "Hello"

# View alice's profile as admin
team-mail profile show --password=secret --user=alice
```

### Admin commands (require admin password or admin token)

| Command | Arguments | Output | Purpose |
|---------|-----------|--------|---------|
| `admin init` | `--password <pw>` | status | First-time password setup, creates `.team-mail/` |
| `admin password` | `--old <pw> --new <pw>` | status | Change admin password |
| `admin auth` | `--password <pw>` + `--admin` or `--user <name>` | token | Mint tokens |

### Users commands (discover and manage users)

| Command | Arguments | Output | Purpose |
|---------|-----------|--------|---------|
| `users list` | `[--names-only] [--no-self] [--tags=x] [--full]` | JSON array | List users |
| `users get` | `<name> [--full]` | JSON | View a user's profile |
| `users add` | `<name> <role>` + `[--password]` + optional flags | JSON | Add user (admin only) |

Note: `--full` includes all fields (dates and empty values, hidden by default).

### Profile commands (your identity, requires user token)

| Command | Arguments | Output | Purpose |
|---------|-----------|--------|---------|
| `profile show` | — | text | View your own profile |
| `profile update` | `--status`, `--tags`, `--about` | JSON | Update your profile |

### Mail commands (require user token)

| Command | Arguments | Output | Purpose |
|---------|-----------|--------|---------|
| `inbox` | — | summary | Check inbox (count + senders) |
| `inbox read` | — | JSONL | Read messages, mark as read |
| `send` | `<to> <body>` | JSON | Send message |

### Utility commands

| Command | Arguments | Output | Purpose |
|---------|-----------|--------|---------|
| `env` | — | shell exports | Auto-discover, print exports |
| `prompt` | — | text | Full CLI reference + identity (for SessionStart) |

### Error format

```
ERROR: <what went wrong>
AVAILABLE: <options if applicable>
FIX: <how to recover>
```

## Slash Commands

Commands handle high-level workflows, using CLI primitives under the hood.

| Command | Purpose |
|---------|---------|
| `/init-workspace` | Initialize team-mail (sets admin password) |
| `/register` | Create new user (Claude generates name/role) |
| `/identify` | Show your identity (from token) |
| `/signin` | Update profile (status, tags, about) |
| `/whoami` | Print your profile |
| `/profile` | View another user's profile |
| `/send-mail` | Send message to one user |
| `/broadcast-mail` | Send to all or tagged users |
| `/team` | List all users with profiles |
| `/tags` | List tags with counts |
| `/check-mail` | Read inbox, mark as read |

## Design decisions

### Why token-based auth

The previous trust-the-LLM model relied on the agent remembering to use `--as <name>` flags. Token-based auth is more robust:
- Identity is cryptographically verified
- No risk of accidentally impersonating another user
- Tokens can be revoked by deleting the hash file
- Compatible with multi-agent orchestration

### Why primitives + commands

The CLI provides mechanical operations (file I/O, auth, timestamps). Commands let Claude handle creative work (name generation, message formatting). This separation keeps the CLI simple and testable while giving commands flexibility.

### Why filesystem instead of database

The filesystem is self-describing — a user exists if their directory exists. You can inspect the entire system state with `ls` and `cat`.

### Why atomic send

The `send` command writes to both recipient's inbox and sender's sent log. If the first write succeeds but the second fails, the message was still delivered — better than losing the message entirely.

### Why files instead of MCP

An MCP server would give cleaner tool APIs and in-memory state, but it introduces a running process that must be started before agents and kept alive. The filesystem is already shared infrastructure — it doesn't crash, doesn't need a port, and works across worktrees.

### Why the hook marks messages as read

The `check-inbox.sh` hook now reads messages AND marks them as read. This is deliberate — agents should see each message once. Use `inbox` (without `read`) for a summary without marking as read.

## Components

| Path | Purpose |
|------|---------|
| `src/team_mail/cli/team_mail.py` | Python CLI (stdlib-only) |
| `extras/claude-plugin/commands/*.md` | Slash commands |
| `extras/claude-plugin/hooks/session-start.sh` | Auto-discover `.team-mail/`, show identity |
| `extras/claude-plugin/hooks/check-inbox.sh` | PostToolUse — surface new messages |
| `tests/test_team_mail.py` | pytest tests for CLI |

## Requirements

- Python 3.11+
- uv (for running tests: `uv run pytest`)

## Quick Start

```bash
# Install
uv sync  # or: pip install -e .

# Initialize (first time)
team-mail admin init --password mypassword

# Get admin token
ADMIN_TOKEN=$(team-mail admin auth --admin --password mypassword)
export TEAM_MAIL_TOKEN=$ADMIN_TOKEN

# Create a user
team-mail users add maya-backend "Backend Engineer"

# Get user token
USER_TOKEN=$(team-mail admin auth --user maya-backend --password mypassword)
export TEAM_MAIL_TOKEN=$USER_TOKEN

# Check your profile
team-mail profile show

# List users
team-mail users list

# View a specific user
team-mail users get alex-frontend

# Send a message
team-mail send alex-frontend "API is ready"

# Check inbox
team-mail inbox
team-mail inbox read
```
