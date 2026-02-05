# atcha

## What this is

A file-based messaging system for parallel Claude Code sessions. Agents running in separate git worktrees can send each other messages through JSONL files on the filesystem. No MCP servers, no daemons, no databases.

The Python CLI (`atcha`) provides a hierarchical command structure with token-based authentication. Claude Code commands handle higher-level logic like name generation and message formatting.

## Architecture

A `.atcha/` directory lives at the project root and contains admin config, tokens, and agent data. Agents authenticate via tokens stored in `$ATCHA_TOKEN`.

Each user gets a directory under `.atcha/users/` with their profile and mail. Sending a message means appending a JSON line directly to the recipient's `inbox.jsonl`. A PostToolUse hook checks for new messages after every tool call.

### Directory structure

```
.atcha/
├── admin.json              # {"password_hash": "...", "salt": "..."}
├── tokens/
│   ├── _admin              # hash of admin token
│   └── <user-name>         # hash of user token
└── users/
    └── <user-name>/
        ├── profile.json
        └── mail/
            ├── inbox.jsonl
            ├── sent.jsonl
            └── state.json
```

### profile.json

```json
{
  "id": "maya-backend-engineer",
  "name": "maya",
  "role": "Backend Engineer",
  "status": "Refactoring auth module",
  "about": "I handle backend services and API development.",
  "tags": ["auth", "backend"],
  "joined": "2026-01-27T10:00:00Z",
  "updated": "2026-01-29T14:30:00Z"
}
```

The filesystem is the registry — a user exists if their directory exists.

### User identifiers

Each user has two identifiers:
- **name**: The user's unique name (e.g., `maya`), always unique across all users
- **id**: Full identifier `{name}-{role-slug}` (e.g., `maya-backend-engineer`), used as directory name

The name is the primary identifier. The id adds role context to help understand what the user does.

Both can be used interchangeably in CLI commands:
```bash
atcha contacts maya                   # by name (preferred)
atcha contacts maya-backend-engineer  # by id (more descriptive)
atcha send --to maya "Hello"          # by name
```

Examples:
- `maya-backend-engineer` (name: `maya`, role: Backend Engineer)
- `alex-frontend-specialist` (name: `alex`, role: Frontend Specialist)
- `kai-auth-expert` (name: `kai`, role: Auth Expert)

Validation rules for id:
- Lowercase letters, numbers, and dashes only
- 3-40 characters
- No consecutive dashes
- No leading/trailing dashes
- The name (first component) must be unique across all users

### Authentication model

- Admin authenticates with password (`--password` or `$ATCHA_ADMIN_PASS`)
- Users authenticate with tokens (`--token` or `$ATCHA_TOKEN`)
- Password stored as hash in `.atcha/admin.json`
- User tokens are deterministically derived from `HMAC(password, user_id, salt)`
- Token files store SHA-256 hashes, not plaintext tokens
- Same password + user always produces the same token (idempotent)
- Users cannot read each other's tokens (only hashes are stored)

### Message flow

1. Agent A (authenticated via token) runs `/send-mail alex-frontend "Changed auth exports"`
2. The CLI uses the token to identify the sender and appends to `alex-frontend/mail/inbox.jsonl`
3. A copy goes to sender's `mail/sent.jsonl` atomically
4. On agent B's next tool call, the `check-inbox.sh` hook fires, sees the new message, and prints it to stdout
5. Agent B runs `/check-mail` (which uses `messages read`) to read and mark messages as read

### Env vars

- `ATCHA_DIR` — absolute path to `.atcha/` directory. Auto-discovered by SessionStart hook.
- `ATCHA_TOKEN` — authentication token for the current agent.
- `ATCHA_ADMIN_PASS` — admin password (for admin operations without `--password`).
- `ATCHA_CLI` — (plugin only) absolute path to CLI script. Set by SessionStart hook.

When the package is installed (`uv sync` or `pip install -e .`), use `atcha` directly.

## CLI Commands

The CLI provides a hierarchical structure with token-based authentication.

### Authentication options

**Admin operations** (create agents, mint tokens):
- `--password <pw>` or `$ATCHA_ADMIN_PASS`

**Agent operations** (profile, inbox, send):
- `--token <token>` or `$ATCHA_TOKEN`

Priority: password/ATCHA_ADMIN_PASS > token/ATCHA_TOKEN

### Admin impersonation

Commands that self-identify (messages, send) accept `--user <name>` with admin auth:

```bash
# Check alice's inbox as admin
atcha messages --password=secret --user=alice check

# Send from alice to bob as admin
atcha send --password=secret --user=alice --to bob "Hello"

# Update alice's profile as admin
atcha profile update --password=secret --name=alice --status="On vacation"
```

### Setup commands (require admin password)

| Command | Arguments | Output | Purpose |
|---------|-----------|--------|---------|
| `init` | `[--password <pw>]` | status | First-time setup, creates `.atcha/`. Prompts if no password |
| `init` | `--check` | status | Check if initialized (exit 0 if yes, 1 if no). Useful in hooks |
| `create-token` | `--user <name>` | token | Create user token |
| `admin password` | `--old <pw> --new <pw>` | status | Change admin password |

### Contact and profile commands

| Command | Arguments | Output | Purpose |
|---------|-----------|--------|---------|
| `contacts` | `[--names-only] [--include-self] [--tags=x] [--full]` | JSON array | List all contacts (excludes self by default) |
| `contacts` | `<name> [--full]` | JSON | View a contact's profile |
| `admin users add` | `--name <name> --role <role>` + optional flags | JSON | Add new user (admin only) |
| `profile update` | `[--name <name>] --status/--role/--tags/--about` | JSON | Update profile |

Notes:
- `contacts` with no arguments lists all users, excluding self by default. Use `--include-self` to include yourself.
- `contacts <name>` shows a specific user's profile.
- `--full` includes all fields (dates and empty values, hidden by default).
- `profile update` without `--name` updates your own profile (requires token). With `--name`, requires admin auth.

### Mail commands (require agent token)

| Command | Arguments | Output | Purpose |
|---------|-----------|--------|---------|
| `messages check` | — | summary | Check inbox (count + senders) |
| `messages list` | `[--from=user] [--thread=id] [--limit=N] [--all] [--no-preview]` | JSON array | List messages with previews (no side effects) |
| `messages read` | `[IDs...] [--since=TS] [--from=user] [--include-read] [--no-mark]` | JSONL | Read messages, mark as read |
| `send` | `--to <name> <content>` | JSON | Send message |

Notes:
- `messages list` returns JSON array with `preview` field (50 chars + "..."). Use `--no-preview` for full `content`.
- `messages list` does NOT mark messages as read (no side effects).
- `messages read` marks messages as read. Use `--no-mark` to prevent this.
- `messages read [IDs]` reads only specific messages by ID.
- `messages read` excludes the `to` field by default (it's redundant). When admin impersonates, `to` is included.
- Filters: `--since` (ISO timestamp), `--from` (sender agent name), `--include-read` (include already-read messages).
- Message field: `content` (old `body` field is still readable for backward compatibility).

### Utility commands

| Command | Arguments | Output | Purpose |
|---------|-----------|--------|---------|
| `whoami` | — | text | Print your username (requires token) |
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
| `/init-workspace` | Initialize atcha (sets admin password) |
| `/register` | Create new user (Claude generates name/role) |
| `/identify` | Show your identity (from token) |
| `/signin` | Update profile (status, tags, about) |
| `/send-mail` | Send message to one user |
| `/broadcast-mail` | Send to all or tagged users |
| `/team` | List all users with profiles |
| `/tags` | List tags with counts |
| `/check-mail` | Read inbox, mark as read |

## Design decisions

### Why token-based auth

The previous trust-the-LLM model relied on the agent remembering to use `--as <name>` flags. Token-based auth is more robust:
- Identity is cryptographically verified
- No risk of accidentally impersonating another agent
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

The `check-inbox.sh` hook uses `messages read` which marks messages as read. This is deliberate — agents should see each message once. Use `messages check` for a summary without marking as read, or `messages list` for full details without marking as read.

## Components

| Path | Purpose |
|------|---------|
| `src/atcha/cli/atcha.py` | Python CLI (stdlib-only) |
| `extras/claude-plugin/commands/*.md` | Slash commands |
| `extras/claude-plugin/hooks/session-start.sh` | Auto-discover `.atcha/`, show identity |
| `extras/claude-plugin/hooks/check-inbox.sh` | PostToolUse — surface new messages |
| `tests/test_atcha.py` | pytest tests for CLI |

## Requirements

- Python 3.11+
- uv (for running tests: `uv run pytest`)

## Quick Start

```bash
# Install
uv sync  # or: pip install -e .

# Initialize (first time, will prompt for password)
atcha init
# Or with password directly:
atcha init --password mypassword

# Set admin password for subsequent commands
export ATCHA_ADMIN_PASS=mypassword

# Create a user
atcha admin users add --name maya-backend --role "Backend Engineer"

# Get user token
USER_TOKEN=$(atcha create-token --user maya-backend)
export ATCHA_TOKEN=$USER_TOKEN

# Check your identity
atcha whoami
atcha contacts $(atcha whoami)

# List users
atcha contacts

# View a specific user
atcha contacts alex-frontend

# Send a message
atcha send --to alex-frontend "API is ready"

# Check inbox
atcha messages check
atcha messages read
```
