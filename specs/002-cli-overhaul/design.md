---
locked: false
status: draft
---

# Design: CLI Overhaul

## Approach

Restructure the CLI parser and dispatch logic in `atcha.py` to enforce the "bare plural = list, subcommand = verb" convention uniformly. The implementation is parser-first: change the argparse tree and dispatch, then adapt command handlers to match. No file formats or auth logic changes.

The overhaul touches one file heavily (`atcha.py`) and two files lightly (`check-inbox.sh`, `test_atcha.py`). The command handlers themselves are largely reusable — most changes are in how they're wired, not what they do.

## Decisions

| Decision | Rationale |
|----------|-----------|
| Rewrite `_build_parser()` from scratch | The current parser has accumulated ad-hoc patterns (optional positionals on `contacts`, `messages list` as separate subcommand). A clean rewrite is less error-prone than incremental patching. |
| Keep all code in single `atcha.py` | The file is large (~2900 lines) but follows a clear section pattern. Splitting would add import complexity with no architectural benefit for a stdlib-only CLI. |
| Migration stubs as real subparsers | Removed commands (`init`, `env`, `messages list`, etc.) are registered as parsers that immediately error with `FIX:` guidance. This is more reliable than string-matching in dispatch. |
| `contacts show` as explicit subcommand | Replaces the current `contacts [name]` positional. Cleaner separation of list vs. show. The `cmd_users_get` handler is reused. |
| `messages` bare = current `messages list` | The `cmd_messages_list` handler already does exactly what bare `messages` should do. Just rewire the dispatch. |
| `admin users` bare = list all users | Currently `admin users` with no subcommand prints help. Change to list users (new handler, simple — iterate user dirs and output JSON). |
| `admin spaces` replaces both `admin space` and `admin federated` | Two concepts (local space identity + federation registry) are unified under one collection noun. `update` handles local space config; `add`/`drop` handle federation entries. |
| `profile update` drops `--role`/`--name` from parser | Currently `--role` is parsed then rejected at runtime for non-admins. Removing it from the parser means `argparse` itself rejects it — no confusing "parsed but denied" behavior. |
| `--as` requires user ID, not address | Addresses resolve through name lookup, which requires user auth context. Admin impersonation should use the unambiguous ID directly. |
| `whoami` gains `--id` and `--name` flags | Currently only prints the user name. Address format (`name@`) becomes the default, with `--id` and `--name` as alternatives. |
| `admin envs` replaces `env` | The `env` command prints shell exports for hooks. It's admin-adjacent (reads `.atcha/` structure) and confusing at top level. Renamed and moved. |
| `admin init` replaces top-level `init` | `init` sets the admin password, so it belongs under `admin`. |

## Architecture

### Parser Structure

```
_build_parser()
├── auth_parent (shared: --token, --password, --as, --json)
├── "contacts" → contacts_parser
│   └── "show" → contacts_show_parser
├── "messages" → messages_parser
│   ├── "check" → messages_check_parser
│   └── "read" → messages_read_parser
├── "send" → send_parser
├── "profile" → profile_parser
│   └── "update" → profile_update_parser
├── "whoami" → whoami_parser
├── "status" → status_parser
├── "admin" → admin_parser
│   ├── "init" → admin_init_parser
│   ├── "envs" → admin_envs_parser
│   ├── "password" → admin_password_parser
│   ├── "create-token" → admin_create_token_parser
│   ├── "users" → admin_users_parser
│   │   ├── "create" → admin_users_create_parser
│   │   ├── "update" → admin_users_update_parser
│   │   └── "delete" → admin_users_delete_parser
│   ├── "spaces" → admin_spaces_parser
│   │   ├── "update" → admin_spaces_update_parser
│   │   ├── "add" → admin_spaces_add_parser
│   │   └── "drop" → admin_spaces_drop_parser
│   └── "hints" → admin_hints_parser
└── Migration stubs: "init", "env" (top-level errors)
```

### Dispatch Changes

The `main()` dispatch currently uses a chain of `if/elif` on `args.command`. The new dispatch will follow the same pattern but with updated routing:

- `contacts` (no subcommand) → `cmd_users_list` (existing)
- `contacts show` → `cmd_users_get` (existing)
- `messages` (no subcommand) → `cmd_messages_list` (existing, becomes default)
- `messages check` → `cmd_messages_check` (existing)
- `messages read` → `cmd_messages_read` (existing, but require IDs)
- `admin users` (no subcommand) → `cmd_admin_users_list` (new)
- `admin users create` → `cmd_users_add` (existing, renamed from `add`)
- `admin users update` → `cmd_admin_users_update` (new, wraps `cmd_users_update` with admin-only fields)
- `admin users delete` → `cmd_admin_users_delete` (new)
- `admin spaces` (no subcommand) → `cmd_admin_spaces_list` (new, combines local space + federation list)
- `admin spaces update` → `cmd_admin_space_rename` (existing, extended for `--description`)
- `admin spaces add` → `cmd_admin_federated_add` (existing)
- `admin spaces drop` → `cmd_admin_federated_remove` (existing)
- `admin init` → `cmd_init` (existing, re-routed)
- `admin envs` → `cmd_env` (existing, re-routed)
- `init` (top-level) → migration error
- `env` (top-level) → migration error
- `messages list` → migration error

### Handler Changes

Most existing handlers are reused with minimal modification:

| Handler | Change |
|---------|--------|
| `cmd_init` | None (just re-routed from `admin init`) |
| `cmd_env` | None (re-routed from `admin envs`) |
| `cmd_users_list` | Remove `--names-only` support |
| `cmd_users_get` | None (called from `contacts show` now) |
| `cmd_messages_list` | Add `--since` filter (currently only on `messages read`) |
| `cmd_messages_read` | Error when `args.ids` is empty list |
| `cmd_users_update` | Split into two paths: `profile update` (no `--role`/`--name`) and `admin users update` (all fields) |
| `cmd_whoami` | Add `--id`, `--name` flags; default to address format |
| `cmd_admin_space_rename` | Extend for `--description`; rename to `cmd_admin_spaces_update` |
| `cmd_admin_federated_remove` | Accept `id-or-handle` positional (rename from `identifier`) |

New handlers needed:

| Handler | Purpose |
|---------|---------|
| `cmd_admin_users_list` | List all users as JSON array (simple: iterate dirs, load profiles) |
| `cmd_admin_users_update` | Update user with admin-only fields (`--name`, `--role`) |
| `cmd_admin_users_delete` | Delete user directory + token file |
| `cmd_admin_spaces_list` | Combine local space info + federation list |
| `_migration_error` | Helper for removed commands |

### Address Validation

Add a `_validate_address_format` helper called at parse time for user-reference arguments. This function:
1. Accepts `name@`, `name@space`, `usr-xxxxx`
2. Rejects bare names with the `FIX:` message
3. Called in `_resolve_user` or as a pre-check in handlers that accept addresses

### Impersonation Validation

Add a check in `_require_user` that validates `--as` is a user ID (starts with `usr-`), not an address.

## Error Handling

Migration errors use the existing `_error()` helper with the `fix` parameter:

```python
def _migration_error(old: str, new: str) -> T.NoReturn:
    """Error for removed/relocated commands."""
    _error(f"'{old}' has been removed", fix=f"use '{new}'")
```

## Testing Strategy

- Update all test invocations to new command paths (`init` → `admin init`, `admin users add` → `admin users create`, etc.)
- Add tests for migration errors (each removed command produces the right `FIX:` message)
- Add tests for `messages read` with no IDs (error)
- Add tests for `profile update --role` rejection
- Add tests for bare name rejection in address positions
- Add tests for `--as` with address rejection
- Add tests for new commands: `admin users` (list), `admin users update`, `admin users delete`
- Add tests for `whoami --id`, `whoami --name`, `whoami --id --name` (error)
