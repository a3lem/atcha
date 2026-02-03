# team-mail

## What this is

A file-based messaging system for parallel Claude Code sessions. Agents running in separate git worktrees can send each other messages through JSONL files on the filesystem. No MCP servers, no daemons, no databases.

The Python CLI (`team-mail`) provides a hierarchical command structure with token-based authentication. Claude Code commands handle higher-level logic like name generation and message formatting.

## Architecture

A `.team-mail/` directory lives at the project root and contains admin config, tokens, and agent data. Agents authenticate via tokens stored in `$TEAM_MAIL_TOKEN`.

Each agent gets a directory under `.team-mail/agents/` with their profile and mail. Sending a message means appending a JSON line directly to the recipient's `inbox.jsonl`. A PostToolUse hook checks for new messages after every tool call.

### Directory structure

```
.team-mail/
├── admin.json              # {"password_hash": "...", "salt": "..."}
├── tokens/
│   ├── _admin              # hash of admin token
│   └── <agent-name>        # hash of agent token
└── agents/
    └── <agent-name>/
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

The filesystem is the registry — an agent exists if their directory exists.

### Agent identifiers

Each agent has two identifiers:
- **name**: The agent's unique name (e.g., `maya`), always unique across all agents
- **id**: Full identifier `{name}-{role-slug}` (e.g., `maya-backend-engineer`), used as directory name

The name is the primary identifier. The id adds role context to help understand what the agent does.

Both can be used interchangeably in CLI commands:
```bash
team-mail agents get maya                   # by name (preferred)
team-mail agents get maya-backend-engineer  # by id (more descriptive)
team-mail send maya "Hello"                 # by name
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
- The name (first component) must be unique across all agents

### Authentication model

- Admin authenticates with password (`--password` or `$TEAM_MAIL_ADMIN_PASS`)
- Agents authenticate with tokens (`--token` or `$TEAM_MAIL_TOKEN`)
- Password stored as hash in `.team-mail/admin.json`
- Agent tokens are deterministically derived from `HMAC(password, agent_id, salt)`
- Token files store SHA-256 hashes, not plaintext tokens
- Same password + agent always produces the same token (idempotent)
- Agents cannot read each other's tokens (only hashes are stored)

### Message flow

1. Agent A (authenticated via token) runs `/send-mail alex-frontend "Changed auth exports"`
2. The CLI uses the token to identify the sender and appends to `alex-frontend/mail/inbox.jsonl`
3. A copy goes to sender's `mail/sent.jsonl` atomically
4. On agent B's next tool call, the `check-inbox.sh` hook fires, sees the new message, and prints it to stdout
5. Agent B runs `/check-mail` (which uses `inbox read`) to read and mark messages as read

### Env vars

- `TEAM_MAIL_DIR` — absolute path to `.team-mail/` directory. Auto-discovered by SessionStart hook.
- `TEAM_MAIL_TOKEN` — authentication token for the current agent.
- `TEAM_MAIL_ADMIN_PASS` — admin password (for admin operations without `--password`).
- `TEAM_MAIL_CLI` — (plugin only) absolute path to CLI script. Set by SessionStart hook.

When the package is installed (`uv sync` or `pip install -e .`), use `team-mail` directly.

## CLI Commands

The CLI provides a hierarchical structure with token-based authentication.

### Authentication options

**Admin operations** (create agents, mint tokens):
- `--password <pw>` or `$TEAM_MAIL_ADMIN_PASS`

**Agent operations** (profile, inbox, send):
- `--token <token>` or `$TEAM_MAIL_TOKEN`

Priority: password/TEAM_MAIL_ADMIN_PASS > token/TEAM_MAIL_TOKEN

### Admin impersonation

Commands that self-identify (inbox, send) accept `--user <name>` with admin auth:

```bash
# Check alice's inbox as admin
team-mail inbox --password=secret --user=alice

# Send from alice to bob as admin
team-mail send --password=secret --user=alice bob "Hello"

# Update alice's profile as admin
team-mail agents update --password=secret --name=alice --status="On vacation"
```

### Setup commands (require admin password)

| Command | Arguments | Output | Purpose |
|---------|-----------|--------|---------|
| `init` | `[--password <pw>]` | status | First-time setup, creates `.team-mail/`. Prompts if no password |
| `init` | `--check` | status | Check if initialized (exit 0 if yes, 1 if no). Useful in hooks |
| `create-token` | `--agent <name>` | token | Create agent token |
| `admin password` | `--old <pw> --new <pw>` | status | Change admin password |

### Agents commands (discover and manage agents)

| Command | Arguments | Output | Purpose |
|---------|-----------|--------|---------|
| `agents list` | `[--names-only] [--include-self] [--tags=x] [--full]` | JSON array | List agents (excludes self by default) |
| `agents get` | `<name> [--full]` | JSON | View an agent's profile |
| `agents add` | `--name <name> --role <role>` + optional flags | JSON | Add agent (admin only) |
| `agents update` | `[--name <name>] --status/--role/--tags/--about` | JSON | Update agent profile |

Notes:
- `agents list` excludes the current agent by default. Use `--include-self` to include yourself. Admin sees all.
- `--full` includes all fields (dates and empty values, hidden by default).
- `agents update` without `--name` updates your own profile (requires token). With `--name`, requires admin auth.

### Mail commands (require agent token)

| Command | Arguments | Output | Purpose |
|---------|-----------|--------|---------|
| `inbox` | — | summary | Check inbox (count + senders) |
| `inbox read` | `[--since=TS] [--from=agent] [--include-read]` | JSONL | Read messages, mark as read |
| `send` | `<to> <body>` | JSON | Send message |

Notes:
- `inbox read` excludes the `to` field by default (it's redundant). When admin impersonates, `to` is included.
- Filters: `--since` (ISO timestamp), `--from` (sender agent name), `--include-read` (include already-read messages).

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
| `/init-workspace` | Initialize team-mail (sets admin password) |
| `/register` | Create new agent (Claude generates name/role) |
| `/identify` | Show your identity (from token) |
| `/signin` | Update profile (status, tags, about) |
| `/send-mail` | Send message to one agent |
| `/broadcast-mail` | Send to all or tagged agents |
| `/team` | List all agents with profiles |
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

The filesystem is self-describing — an agent exists if their directory exists. You can inspect the entire system state with `ls` and `cat`.

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

# Initialize (first time, will prompt for password)
team-mail init
# Or with password directly:
team-mail init --password mypassword

# Set admin password for subsequent commands
export TEAM_MAIL_ADMIN_PASS=mypassword

# Create an agent
team-mail agents add --name maya-backend --role "Backend Engineer"

# Get agent token
AGENT_TOKEN=$(team-mail create-token --agent maya-backend)
export TEAM_MAIL_TOKEN=$AGENT_TOKEN

# Check your identity
team-mail whoami
team-mail agents get $(team-mail whoami)

# List agents
team-mail agents list

# View a specific agent
team-mail agents get alex-frontend

# Send a message
team-mail send alex-frontend "API is ready"

# Check inbox
team-mail inbox
team-mail inbox read
```
