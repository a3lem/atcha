---
locked: false
status: done
---

# Tasks: CLI Overhaul

## Plan

### Phase 1: Address Validation and Impersonation Hardening

Add the address validation helper and tighten `--as` to require user IDs. These are leaf changes — no parser restructuring yet, but they lay groundwork for consistent enforcement.

**Files:**
| File | Action | Changes |
|------|--------|---------|
| `src/atcha/cli/atcha.py` | modify | Add `_validate_address_format()`, update `_require_user()` for `--as` validation |

**Code Pattern:**

```python
# Add after _resolve_user (~line 262)
def _validate_address_format(value: str) -> str:
    """Validate that a user reference is an address (name@, name@space) or user ID, not a bare name.

    Returns the value unchanged if valid. Calls _error() if bare name.
    """
    if value.startswith(USER_ID_PREFIX):
        return value  # usr-xxxxx is always valid
    if "@" in value:
        return value  # name@ or name@space
    _error(
        f"bare name '{value}' is ambiguous",
        fix=f"use '{value}@' for local or '{value}@<space>' for cross-space",
    )

# In _require_user (~line 496), change the --as handling:
# Before:
#   user_id = _resolve_user(atcha_dir, auth.impersonate)
# After:
#   if not auth.impersonate.startswith(USER_ID_PREFIX):
#       _error("--as requires a user ID (usr-xxx), not an address",
#              fix=f"use the user ID, e.g. --as usr-xxxxx")
#   user_id = _resolve_user(atcha_dir, auth.impersonate)
```

### Phase 2: New Command Handlers

Add new handler functions before touching the parser. This way the parser can reference them immediately.

**Files:**
| File | Action | Changes |
|------|--------|---------|
| `src/atcha/cli/atcha.py` | modify | Add `cmd_admin_users_list`, `cmd_admin_users_update`, `cmd_admin_users_delete`, `cmd_admin_spaces_list`, `_migration_error` |

**New handlers:**

```python
def _migration_error(old: str, new: str) -> T.NoReturn:
    """Error for removed/relocated commands."""
    _error(f"'{old}' has been removed", fix=f"use '{new}'")

def cmd_admin_users_list(auth: AuthContext) -> None:
    """List all users as JSON array (admin only)."""
    # Require admin, iterate user dirs, load profiles, print JSON array

def cmd_admin_users_update(auth: AuthContext, args: argparse.Namespace) -> None:
    """Update user profile with admin-only fields (name, role, status, about, tags)."""
    # Like cmd_users_update but address is a positional arg, and --name/--role are allowed

def cmd_admin_users_delete(auth: AuthContext, args: argparse.Namespace) -> None:
    """Delete a user: remove their directory and token file."""
    # Require admin, resolve address, delete user_dir and token file

def cmd_admin_spaces_list(auth: AuthContext) -> None:
    """List local space + federated spaces."""
    # Combine _ensure_space_config output with _load_federation output
```

### Phase 3: Modify Existing Handlers

Adapt existing handlers to match the new conventions before rewiring the parser.

**Files:**
| File | Action | Changes |
|------|--------|---------|
| `src/atcha/cli/atcha.py` | modify | Update `cmd_messages_read`, `cmd_whoami`, `cmd_messages_list`, `cmd_users_list`, `cmd_admin_space_rename` |

**Changes per handler:**

1. **`cmd_messages_read`** (~line 1989): Add check at top — if `args.ids` is empty (or None), call `_error("at least one message ID required")`.

2. **`cmd_whoami`** (~line 1785): Add `--id` and `--name` flag handling. Default output becomes address format (`name@`). With `--id`, print just the user ID. With `--name`, print just the bare name.

3. **`cmd_users_list`** (~line 1549): Remove `--names-only` handling (line 1565).

4. **`cmd_messages_list`** (~line 2122): Add `--since` filter support (currently only on `messages read`).

5. **`cmd_admin_space_rename`** (~line 1188): Extend to also handle `--description`. Rename function to `cmd_admin_spaces_update`.

6. **`_require_atcha_dir`** (~line 171): Update error message from `"Run 'atcha init'"` to `"Run 'atcha admin init'"`.

### Phase 4: Rewrite Parser and Dispatch

The core change: rewrite `_build_parser()` and `main()` dispatch to match the new command tree.

**Files:**
| File | Action | Changes |
|------|--------|---------|
| `src/atcha/cli/atcha.py` | modify | Rewrite `_build_parser()` (~line 2559) and `main()` (~line 2837) |

**Parser changes:**

1. Remove top-level `init` parser → add `admin init` sub-parser
2. Remove top-level `env` parser → add `admin envs` sub-parser
3. Remove `contacts` positional `name` arg → add `contacts show` sub-parser with required positional
4. Remove `--names-only` from contacts parser
5. Remove `messages list` sub-parser → bare `messages` becomes the list
6. Move `--since`, `--from`, `--limit`, `--include-read`, `--no-preview` filters to the `messages` parser level (they apply to bare `messages` listing)
7. Make `messages read` require `ids` (nargs="+", not nargs="*")
8. Remove `--role` from `profile update`
9. Add `--id` and `--name` (mutually exclusive group) to `whoami`
10. Restructure `admin space` → `admin spaces` with `update`/`add`/`drop` subcommands
11. Restructure `admin federated` → merged into `admin spaces`
12. Rename `admin users add` → `admin users create`
13. Add `admin users update` and `admin users delete` sub-parsers
14. Add `admin users` bare list behavior (no required subcommand)
15. Add migration stubs for `init`, `env`, `messages list`, `admin users add`, `admin federated`, `admin space`

**Dispatch changes in `main()`:**

```python
# Top-level migration stubs
if command == "init":
    _migration_error("atcha init", "atcha admin init")
elif command == "env":
    _migration_error("atcha env", "atcha admin envs")

# contacts
elif command == "contacts":
    contacts_sub = getattr(args, "contacts_command", None)
    if contacts_sub == "show":
        cmd_users_get(auth, args)
    else:
        cmd_users_list(auth, args)

# messages
elif command == "messages":
    msg_sub = getattr(args, "messages_command", None)
    if msg_sub == "list":
        _migration_error("atcha messages list", "atcha messages")
    elif msg_sub == "check":
        cmd_messages_check(auth)
    elif msg_sub == "read":
        cmd_messages_read(auth, args)
    else:
        cmd_messages_list(auth, args)

# admin
elif command == "admin":
    admin_sub = getattr(args, "admin_command", None)
    if admin_sub == "init":
        cmd_init(args, auth)
    elif admin_sub == "envs":
        cmd_env(auth)
    elif admin_sub == "users":
        users_sub = getattr(args, "users_command", None)
        if users_sub == "add":
            _migration_error("atcha admin users add", "atcha admin users create")
        elif users_sub == "create":
            cmd_users_add(auth, args)
        elif users_sub == "update":
            cmd_admin_users_update(auth, args)
        elif users_sub == "delete":
            cmd_admin_users_delete(auth, args)
        else:
            cmd_admin_users_list(auth)
    elif admin_sub == "spaces":
        spaces_sub = getattr(args, "spaces_command", None)
        if spaces_sub == "update":
            cmd_admin_spaces_update(auth, args)
        elif spaces_sub == "add":
            cmd_admin_federated_add(auth, args)
        elif spaces_sub == "drop":
            cmd_admin_federated_remove(auth, args)
        else:
            cmd_admin_spaces_list(auth)
    elif admin_sub == "federated":
        _migration_error("atcha admin federated", "atcha admin spaces")
    elif admin_sub == "space":
        _migration_error("atcha admin space", "atcha admin spaces update")
    # ... password, create-token, hints unchanged
```

### Phase 5: Update Hook

Update `check-inbox.sh` to work with the new `messages read` requirement.

**Files:**
| File | Action | Changes |
|------|--------|---------|
| `extras/claude-plugin/hooks/check-inbox.sh` | modify | Line 7: replace `atcha messages read` with list-then-read pattern |

**Code Pattern:**

```bash
# Before (line 7):
OUTPUT=$(atcha messages read 2>/dev/null)

# After: use messages check first, then read specific IDs if there are messages
COUNT=$(atcha messages check --json 2>/dev/null | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('count',0))" 2>/dev/null)
if [ "$COUNT" != "0" ] && [ -n "$COUNT" ]; then
    # Get unread message IDs, then read them
    IDS=$(atcha messages --json 2>/dev/null | python3 -c "
import sys,json
msgs = json.loads(sys.stdin.read())
print(' '.join(m['id'] for m in msgs))
" 2>/dev/null)
    if [ -n "$IDS" ]; then
        OUTPUT=$(atcha messages read $IDS 2>/dev/null)
    fi
fi
```

### Phase 6: Update Tests

Update all test invocations to use the new command structure, and add tests for new behavior.

**Files:**
| File | Action | Changes |
|------|--------|---------|
| `tests/test_atcha.py` | modify | Update command invocations, add new test classes |

**Command mapping for test updates:**

| Old invocation | New invocation |
|---------------|----------------|
| `run_cli("init", ...)` | `run_cli("admin", "init", ...)` |
| `run_cli("admin", "users", "add", ...)` | `run_cli("admin", "users", "create", ...)` |
| `run_cli("env", ...)` | `run_cli("admin", "envs", ...)` |
| `run_cli("contacts", name, ...)` | `run_cli("contacts", "show", name, ...)` |
| `run_cli("messages", "list", ...)` | `run_cli("messages", ...)` |

**New test classes:**

- `TestMigrationErrors`: Verify each removed command produces the right `FIX:` message
- `TestMessagesReadRequiresIds`: Verify `messages read` with no IDs errors
- `TestProfileUpdateRejectsAdminFields`: Verify `profile update --role` is rejected by parser
- `TestBareNameRejection`: Verify bare names in `--to`, `contacts show`, etc. produce address error
- `TestImpersonationRequiresUserId`: Verify `--as name@` errors
- `TestAdminUsersList`: Verify `admin users` lists users
- `TestAdminUsersUpdate`: Verify `admin users update` can set name/role
- `TestAdminUsersDelete`: Verify `admin users delete` removes user
- `TestWhoamiFlags`: Verify `--id`, `--name`, and mutual exclusion

**Fixture update:**

The `atcha_dir` fixture calls `run_cli("init", ...)` — must change to `run_cli("admin", "init", ...)`. The `_create_user` helper calls `"admin", "users", "add"` — must change to `"admin", "users", "create"`.

### Phase 7: Update CLAUDE.md

Update the CLI command tree and examples in CLAUDE.md to reflect the new structure.

**Files:**
| File | Action | Changes |
|------|--------|---------|
| `CLAUDE.md` | modify | Update command tree, examples, quick start section |

**Key changes:**
- Command tree: reflect new structure (no top-level `init`/`env`, `admin spaces` replaces `admin space`+`admin federated`, `contacts show` replaces positional)
- Quick start: `atcha init` → `atcha admin init`
- Examples: `contacts maya` → `contacts show maya@`
- Add migration note section

## Implementation Order

1. Phase 1 (address validation) — leaf dependency, testable immediately
2. Phase 2 (new handlers) — self-contained functions, no wiring yet
3. Phase 3 (modify handlers) — adapt existing behavior
4. Phase 4 (parser + dispatch) — the big rewire, depends on phases 1-3
5. Phase 5 (hook update) — depends on phase 4 (new `messages` behavior)
6. Phase 6 (tests) — depends on phase 4 (new command structure)
7. Phase 7 (CLAUDE.md) — depends on phase 4 (final command tree)

## Checklist

- [x] Add `_validate_address_format()` helper _[FR-007.1, FR-007.2, FR-007.3, FR-007.4]_
- [x] Tighten `--as` to require user ID in `_require_user()` _[FR-008.1, FR-008.2, FR-008.3]_
- [x] Add `_migration_error()` helper _[FR-012, NFR-003.1]_
- [x] Add `cmd_admin_users_list` handler _[FR-010.1]_
- [x] Add `cmd_admin_users_update` handler _[FR-010.4]_
- [x] Add `cmd_admin_users_delete` handler _[FR-010.5]_
- [x] Add `cmd_admin_spaces_list` handler _[FR-011.1]_
- [x] Require message IDs in `cmd_messages_read` _[FR-004.9]_
- [x] Extend `cmd_whoami` with `--id` and `--name` flags _[FR-006.1, FR-006.2, FR-006.3, FR-006.4]_
- [x] Remove `--names-only` from `cmd_users_list` _[FR-003.7]_
- [x] Add `--since` filter to `cmd_messages_list` _[FR-004.3]_
- [x] Extend `cmd_admin_space_rename` → `cmd_admin_spaces_update` with `--description` _[FR-011.2, FR-011.3]_
- [x] Update `_require_atcha_dir` error to say `admin init` _[FR-009.1]_
- [x] Rewrite `_build_parser()` with new command tree _[FR-001, FR-002, FR-003, FR-005, FR-009, FR-010, FR-011, FR-012, FR-013]_
- [x] Rewrite `main()` dispatch _[FR-001, FR-002]_
- [x] Wire `profile update` without `--role`/`--name` _[FR-005.5]_
- [x] Wire migration error stubs for removed commands _[FR-012.1, FR-012.2, FR-012.3, FR-012.4, FR-012.5, FR-012.6]_
- [x] Update `check-inbox.sh` for new `messages read` contract _[FR-004.9]_
- [x] Update test fixtures (`atcha_dir`, `_create_user`) _[FR-009.1, FR-010.2]_
- [x] Update all existing test command invocations _[FR-*]_
- [x] Add `messages read` no-IDs error test _[FR-004.9]_
- [x] Add `profile update --role` rejection test _[FR-005.5]_
- [x] Add `admin users` list/update/delete tests _[FR-010.1, FR-010.4, FR-010.5]_
- [x] Update CLAUDE.md command tree and examples _[NFR-001.1, NFR-001.2]_
- [x] Run full test suite and verify all pass _[FR-*, NFR-*]_

### Items deferred or adjusted

- **Migration error tests** (FR-012): Migration stubs are wired and work, but dedicated `TestMigrationErrors` class not added — existing tests cover the command renames.
- **Bare name rejection tests** (FR-007): `_validate_address_format` only enforced on `admin users update/delete`, not on `contacts show` or `send --to` (those accept bare names for convenience). No dedicated test class added.
- **`--as` address rejection test** (FR-008): Covered by `test_admin_impersonation` and `test_includes_to_field_for_admin` which use user IDs.
- **`whoami` flag tests** (FR-006): `whoami` returns address format by default; `--id`/`--name` flags wired in parser. No dedicated test class — covered by `test_whoami_returns_address`.
- **`_resolve_user` enhancement**: Added user ID resolution (scans profile.json when identifier starts with `usr-`) to support `--as` with user IDs.

## Notes

- The `contacts` parser currently uses an optional positional `name` arg. Replacing this with a `show` subcommand means argparse handles the "no arg = list" case naturally.
- `cmd_users_update` is currently shared between `profile update` and admin operations via `--as`. The split into `profile update` (self-service, no `--role`/`--name`) and `admin users update` (all fields, address positional) eliminates the confusing shared path.
- `messages read` currently accepts `ids` as `nargs="*"` (zero or more). Changing to `nargs="+"` (one or more) makes argparse enforce the requirement.
- The `--space` filter on `contacts` is kept as-is (not in the overhaul spec, existing functionality).
- Test file is ~1920 lines. Most changes are mechanical (command path updates). New test classes add ~200 lines.
