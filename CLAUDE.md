# atcha

## What this is

A file-based messaging system for parallel Claude Code sessions. Users running in separate git worktrees can send each other messages through JSONL files on the filesystem. No MCP servers, no daemons, no databases.

The Python CLI (`atcha`) provides a hierarchical command structure with token-based authentication. Claude Code commands handle higher-level logic like name generation and message formatting.

## Architecture

A `.atcha/` directory lives at the project root and contains admin config, tokens, and user data. Users authenticate via tokens stored in `$ATCHA_TOKEN`.

Each user gets a directory under `.atcha/users/` with their profile and messages. Sending a message means appending a JSON line directly to the recipient's `inbox.jsonl`. A PostToolUse hook checks for new messages after every tool call.

### Directory structure

```
.atcha/
├── admin.json              # {"password_hash": "...", "salt": "..."}
├── space.json              # {"id": "spc-xxxxx", "name": "project-name", ...}
├── federation.local.json   # {"spaces": [...]} (federated space registry)
├── tokens/
│   ├── _admin              # hash of admin token
│   └── <user-id>           # hash of user token (e.g., maya-backend-engineer)
└── users/
    └── <user-id>/          # directory named by user id (e.g., maya-backend-engineer)
        ├── profile.json
        └── messages/
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

### User identifiers and addresses

Each user has two identifiers:
- **name**: The user's display name (e.g., `maya`), always unique within a space, immutable
- **id**: Deterministic identifier derived from `{name}-{slugify(role)}` (e.g., `maya-backend-engineer`), immutable. The user's directory name = user ID.

Name and role are **immutable** — baked into the user ID. To change identity, create a new user.

The **address** is the canonical way to reference users in CLI commands: `name@space` for cross-space, `name` for local. Behind the scenes, addresses resolve to user IDs.

Address formats:
- `maya@` — explicitly local
- `maya@engineering` — user in the `engineering` space (cross-space)

Bare names (e.g. `maya`) are rejected in admin update/delete commands — must use address form (`maya@`) or user ID. Other commands (`contacts show`, `send --to`) accept bare names for convenience.

```bash
atcha contacts show maya@           # local lookup
atcha contacts show maya@engineering  # cross-space lookup
atcha send --to maya@ "Hello"
atcha send --to maya@engineering "Hello from here"
```

Examples:
- `maya` (name) → `maya-backend-engineer` (id), role: Backend Engineer
- `alex` (name) → `alex-frontend-specialist` (id), role: Frontend Specialist
- `kai` (name) → `kai-auth-expert` (id), role: Auth Expert

### Authentication model

- Admin authenticates with password (`--password` or `$ATCHA_ADMIN_PASS`)
- Users authenticate with tokens (`--token` or `$ATCHA_TOKEN`)
- Password stored as hash in `.atcha/admin.json`
- User tokens are deterministically derived from `HMAC(password, user_id, salt)`
- Token files store SHA-256 hashes, not plaintext tokens
- Same password + user always produces the same token (idempotent)
- Users cannot read each other's tokens (only hashes are stored)

### Message flow

1. User A (authenticated via token) sends a message to alex
2. The CLI uses the token to identify the sender and appends to `alex/messages/inbox.jsonl` (using alex's user directory)
3. A copy goes to sender's `messages/sent.jsonl` atomically
4. On user B's next tool call, the `check-inbox.sh` hook fires, sees the new message, and prints it to stdout
5. User B runs `/check-messages` (which uses `messages read`) to read and mark messages as read

### Env vars

- `ATCHA_DIR` — absolute path to `.atcha/` directory. Auto-discovered by SessionStart hook.
- `ATCHA_TOKEN` — authentication token for the current user.
- `ATCHA_ADMIN_PASS` — admin password (for admin operations without `--password`).

When the package is installed (`uv sync` or `pip install -e .`), use `atcha` directly.

## CLI Commands

The CLI provides a hierarchical structure with token-based authentication.

### Command tree

```
atcha
│
│   Auth flags (on user commands):
│     --token <token>       user auth (or $ATCHA_TOKEN)
│     --password <pw>       admin auth (or $ATCHA_ADMIN_PASS)
│     --as-user <user-id>   act as USER (admin only, user commands only). USER is a user ID (e.g. maya-backend-engineer)
│     --json                machine-readable output
│
├── contacts [--include-self] [--tags=x] [--full]
│   └── show <id-or-address> [--full]
│
├── messages [--from=address] [--since=date] [--limit=N] [--include-read] [--no-preview] [--id=msg-id]
│   ├── check
│   └── read <msg-id> [msg-id...] [--no-mark] [-q/--quiet]
│
├── send --to <address> "content"
├── send --broadcast "content"
├── send --reply-to <msg-id> "content"   # exclusive with --to
│
├── profile
│   └── update [--status <text>] [--about <text>] [--tags <csv>]
│
├── whoami [--id] [--name]
│
├── admin
│   ├── status [-q/--quiet]
│   ├── init [--password <pw>]
│   ├── create-token <user>
│   ├── password --new <pw>
│   ├── envs
│   ├── users
│   │   ├── create --name <n> --role <r> [--status] [--about] [--tags]
│   │   ├── update <address> [--status] [--about] [--tags]
│   │   └── delete <address>
│   └── spaces
│       ├── update [--name] [--description]
│       ├── add <dir>
│       └── drop <id>
```

Design rules:
- Bare plural = list (e.g. `contacts`, `messages`, `admin users`, `admin spaces`)
- Subcommands = other verbs on that collection (e.g. `contacts show`, `messages read`)
- Bare `profile` = show self
- `whoami` defaults to address; `--id` returns user ID; `--name` returns bare name
- `admin status` prints initialization state; `-q`/`--quiet` suppresses output (exit code only)

### Authentication

**Admin operations** (create users, mint tokens):
- `--password <pw>` or `$ATCHA_ADMIN_PASS`

**User operations** (profile, messages, send):
- `--token <token>` or `$ATCHA_TOKEN`

Priority: password/ATCHA_ADMIN_PASS > token/ATCHA_TOKEN

**Acting as a user**: `--as-user <user-id>` with admin auth on user commands. Takes a user ID (e.g. `alice-backend-engineer`).

```bash
# Check alice's inbox as admin
atcha messages --password=secret --as-user=alice-backend-engineer check

# Send from alice to bob as admin
atcha send --password=secret --as-user=alice-backend-engineer --to bob@ "Hello"

# Update alice's profile as admin
atcha profile update --password=secret --as-user=alice-backend-engineer --status="On vacation"
```

### Field permissions

- **Self-service** (`profile update`): status, about, tags
- **Admin-only** (`admin users create`): name, role (set at creation, immutable afterward)
- **Admin-only** (`admin users update`): status, about, tags
- Name and role are **immutable** — they're baked into the user ID

### Messages

- `messages` lists messages (no side effects, no marking as read)
- `messages check` returns a digest/summary (count + senders)
- `messages read <msg-id> [msg-id...]` reads specific messages (at least one ID required) and marks them as read; `--no-mark` prevents this
- Filters: `--since` (ISO timestamp), `--from` (sender address), `--include-read`, `--limit`
- `--no-preview` shows full content instead of truncated preview

### JSON output

Most commands support `--json` for machine-parsable output:

| Command | Default output | `--json` output |
|---------|---------------|-----------------|
| `messages check` | English text | `{"count": N, "senders": {"maya": 2}}` |
| `messages read` | JSONL (one per line) | JSON array |
| `admin init` | "Initialized .atcha/ at ..." | `{"status": "initialized", "path": "..."}` |
| `admin password` | "Password updated" | `{"status": "updated"}` |
| `whoami` | plain text address | `{"address": "maya@"}` |
| `admin status` | "Atcha initialized" / "Not initialized" | `{"initialized": true/false}` |

Commands already outputting JSON (`contacts`, `messages`, `send`, `profile`) are unchanged by `--json`.

### Error format

```
ERROR: <what went wrong>
AVAILABLE: <options if applicable>
FIX: <how to recover>
```

## Claude Code Skill

The Claude Code skill in `extras/claude-plugin/skills/atcha/` provides a simplified interface to the CLI for common operations. See `SKILL.md` and `ADMIN.md` in that directory for detailed documentation on using atcha with Claude Code.

## Design decisions

### Why token-based auth

The previous trust-the-LLM model relied on the agent remembering to use identity flags. Token-based auth is more robust:
- Identity is cryptographically verified
- No risk of accidentally acting as another user
- Tokens can be revoked by deleting the hash file
- Compatible with multi-agent orchestration

### Why primitives + skill

The CLI provides mechanical operations (file I/O, auth, timestamps). The Claude Code skill lets Claude handle higher-level workflows and user interaction. This separation keeps the CLI simple and testable while giving the skill flexibility.

### Why filesystem instead of database

The filesystem is self-describing — a user exists if their directory exists. You can inspect the entire system state with `ls` and `cat`.

### Why atomic send

The `send` command writes to both recipient's inbox and sender's sent log. If the first write succeeds but the second fails, the message was still delivered — better than losing the message entirely.

### Why files instead of MCP

An MCP server would give cleaner tool APIs and in-memory state, but it introduces a running process that must be started before agents and kept alive. The filesystem is already shared infrastructure — it doesn't crash, doesn't need a port, and works across worktrees.

### Why the hook marks messages as read

The `check-inbox.sh` hook uses `messages check` to detect new messages, then `messages` (list) to get IDs, then `messages read` to read and mark them. Users see each message once. Use `messages check` for a summary without marking as read, or bare `messages` for full details without marking as read.

## Components

### CLI modules (`src/atcha/cli/`)

| Module | Purpose |
|--------|---------|
| `_types.py` | Constants, TypedDicts, AuthContext dataclass |
| `errors.py` | Structured error formatting |
| `utils.py` | Pure utilities (timestamps, message IDs) |
| `validation.py` | Username validation, name slugification |
| `store.py` | `.atcha/` data store (directories, profiles, user resolution) |
| `auth.py` | Crypto, token management, authentication |
| `federation.py` | Space identity, federation registry, cross-space resolution |
| `parser.py` | argparse parser construction |
| `main.py` | CLI entry point and dispatch |
| `help.py` | Custom tree-formatted help |
| `atcha.py` | Backward-compat shim (re-exports `main` and `_build_parser`) |
| `commands/admin.py` | Admin commands (init, users, spaces, tokens) |
| `commands/contacts.py` | Contact listing and viewing |
| `commands/profile.py` | Profile and identity commands |
| `commands/messages.py` | Message check, read, list |
| `commands/send.py` | Send message command |
| `commands/env.py` | Env discovery for hooks |

### Other

| Path | Purpose |
|------|---------|
| `extras/claude-plugin/skills/atcha/` | Claude Code skill |
| `extras/claude-plugin/hooks/session-start.sh` | Auto-discover `.atcha/`, show identity |
| `extras/claude-plugin/hooks/check-inbox.sh` | PostToolUse — surface new messages |
| `tests/test_atcha.py` | pytest tests for CLI |
| `tests/test_help.py` | pytest tests for custom help formatting |

## Requirements

- Python 3.11+
- uv (for running tests: `uv run pytest`)

## Quick Start

```bash
# Install
git clone <repo-url>
cd atcha-chat
uv tool install -e .

# Initialize (first time, will prompt for password)
atcha admin init
# Or with password directly:
atcha admin init --password mypassword

# Set admin password for subsequent commands
export ATCHA_ADMIN_PASS=mypassword

# Create a user
atcha admin users create --name maya --role "Backend Engineer"

# Get user token and use it
export ATCHA_TOKEN=$(atcha admin create-token maya@)

# Check your identity
atcha whoami

# List contacts
atcha contacts

# View a specific contact
atcha contacts show maya@

# Send a message
atcha send --to alex@ "API is ready"

# Check inbox
atcha messages check
atcha messages read msg-xxxxx
```
