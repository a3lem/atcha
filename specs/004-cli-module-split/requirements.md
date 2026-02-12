---
locked: false
status: draft
---

# Requirements: CLI Module Split

## Overview

### Context

The atcha CLI lives in a single 3100-line module (`src/atcha/cli/atcha.py`). It contains type definitions, crypto helpers, filesystem utilities, address resolution, 27 command handlers, argparse construction, and the dispatch loop — all in one file. A second module (`help.py`) already exists for custom help formatting.

### Problem

1. **Navigability**: Finding a function means scrolling through 3000+ lines grouped by comment headers. No IDE outline or import path hints at the domain.
2. **Merge conflicts**: Two people editing different commands (e.g., admin users vs. messages) touch the same file.
3. **Coupling risk**: With everything in one namespace, any function can call any other. Module boundaries would make dependencies explicit.
4. **Test targeting**: Tests currently shell out to `atcha.py` as a script. Unit-testing individual layers (e.g., auth logic, address resolution) without invoking the CLI would be easier with importable modules.

### Goal

Split `atcha.py` into focused modules within the `src/atcha/cli/` package while preserving all behavior, the subprocess-based test suite, and the `atcha` entry point. No functional changes — pure structural refactor.

## Functional Requirements

### FR-001: Module Layout

The `src/atcha/cli/` package SHALL be reorganized into the following modules:

| Module | Responsibility | Source lines (approx) |
|--------|---------------|----------------------|
| `types.py` | TypedDict definitions, constants, `AuthContext` dataclass | 52–144 |
| `errors.py` | `_error()` helper, error formatting | 146–158 |
| `paths.py` | `.atcha/` directory discovery, user directory layout, profile I/O | 161–349, 694–728 |
| `auth.py` | Crypto (salt, password hashing, ID generation, token derivation/hashing/storage), token/password retrieval, `_require_auth`, `_require_admin`, `_require_user` | 353–580 |
| `validation.py` | Username validation, slugification | 581–635 |
| `utils.py` | Timestamps, message ID generation, last-seen updates, time formatting, name iteration | 636–692 |
| `federation.py` | Space config, federation config, address parsing, cross-space resolution | 730–1019 |
| `commands/admin.py` | `cmd_status`, `cmd_init`, `cmd_admin_password`, `cmd_admin_hints`, space commands, user CRUD, token creation | 1020–1689 |
| `commands/contacts.py` | `_compact_profile`, `cmd_users_list`, `cmd_users_get` | 1690–1951 |
| `commands/profile.py` | `cmd_whoami`, `cmd_users_update`, `cmd_profile` | 1952–2080 |
| `commands/messages.py` | `cmd_messages_check`, `cmd_messages_read`, `cmd_messages_list`, `_find_message_by_id`, `_get_thread_participants` | 2058–2505 |
| `commands/send.py` | `cmd_send` | 2506–2695 |
| `commands/env.py` | `cmd_env` | 2696–2710 |
| `parser.py` | `Parsers` NamedTuple, `_build_parser()` | 2710–3003 |
| `main.py` | `main()` dispatch function, `if __name__` guard | 3006–3113 |

**Acceptance Criteria:**

1. Each module listed above SHALL exist and contain only the described responsibility
2. `src/atcha/cli/commands/` SHALL be a package (`__init__.py` present)
3. No module SHALL exceed 700 lines (the largest, `commands/admin.py`, is ~670 lines)

### FR-002: Entry Point Preservation

**Acceptance Criteria:**

1. `pyproject.toml` `[project.scripts]` SHALL point to the new entry point (`atcha.cli.main:main`)
2. `src/atcha/__init__.py` SHALL import `VERSION` from `atcha.cli.types` (or wherever `VERSION` lands)
3. Running `atcha` after `uv sync` SHALL produce identical behavior to before the refactor
4. Running `python src/atcha/cli/atcha.py` as a standalone script is NOT required to keep working — the module is being split

### FR-003: Import Hygiene

**Acceptance Criteria:**

1. All cross-module imports SHALL be absolute (`from atcha.cli.types import ...`), not relative
2. No circular imports SHALL exist — the dependency graph SHALL be acyclic:
   - `types` ← `errors` ← `paths` ← `auth` ← `validation` ← `utils` ← `federation` ← `commands/*` ← `parser` ← `main`
   - `commands/*` may import from any non-command module but NOT from each other
3. `if T.TYPE_CHECKING` blocks SHALL be used where needed to break type-only cycles
4. Each module SHALL import only what it uses — no wildcard re-exports

### FR-004: Backward Compatibility Shim

**Acceptance Criteria:**

1. `src/atcha/cli/atcha.py` SHALL remain as a thin backward-compatibility shim that re-exports `main` and `_build_parser` (used by `test_help.py`)
2. The shim SHALL contain an import of `main` from `atcha.cli.main` and `_build_parser` from `atcha.cli.parser`
3. The shim file SHALL be under 20 lines
4. `test_help.py` SHALL continue to work without modification via the shim

### FR-005: No Behavior Changes

**Acceptance Criteria:**

1. All existing tests in `test_atcha.py` SHALL pass without modification
2. All existing tests in `test_help.py` SHALL pass without modification
3. No CLI output, exit codes, error messages, or file I/O behavior SHALL change
4. The `check-inbox.sh` hook SHALL continue to work

### FR-006: Naming Conventions

**Acceptance Criteria:**

1. Public command functions SHALL keep their `cmd_` prefix
2. Private helpers SHALL keep their `_` prefix
3. Module names SHALL be lowercase, no hyphens (PEP 8)
4. The `commands/` subpackage groups command handlers — nothing else goes there

## Non-Functional Requirements

### NFR-001: Stdlib-Only Preserved

1. No new dependencies SHALL be introduced
2. The refactored code SHALL use only Python standard library modules

### NFR-002: Type Checking

1. The refactored code SHALL pass `basedpyright` with no new errors beyond those already present
2. Type hints SHALL be preserved exactly as-is during the move

### NFR-003: Test Coverage Preserved

1. The subprocess-based test suite SHALL remain the primary test mechanism
2. No tests SHALL be deleted or weakened
3. New unit tests for individual modules are welcome but NOT required by this spec

### NFR-004: Diff Minimization

1. Code within each module SHALL preserve its original structure, ordering, and formatting
2. The only changes SHALL be: import statements, and removing code that moved to another module
3. No renaming, reformatting, or logic changes — this is a pure code-motion refactor

## Constraints

- The `help.py` module stays where it is — it's already separate and correctly placed
- `test_atcha.py` runs the CLI as a subprocess via `python src/atcha/cli/atcha.py` — the shim (FR-004) ensures this keeps working
- `test_help.py` imports `_build_parser` from `atcha.cli.atcha` — the shim (FR-004) ensures this keeps working

## Assumptions

- No other code outside this repo imports from `atcha.cli.atcha` directly
- The Claude Code plugin hooks invoke `atcha` as a CLI command, not as a Python import

## Out of Scope

- Functional changes to any command
- Adding new commands or removing existing ones
- Changing file formats or auth logic
- Refactoring the parser construction (just moving it)
- Refactoring the `main()` dispatch (just moving it)
- Adding new tests (allowed, not required)
- Changes to `help.py`

## Verification

1. `uv run pytest` passes with zero failures
2. `uvx basedpyright src/atcha/cli/` produces no new errors
3. `wc -l src/atcha/cli/atcha.py` is under 20 lines (shim only)
4. No module in `src/atcha/cli/` exceeds 700 lines
5. `uv sync && atcha --help` works
6. The dependency graph has no cycles (verified by successful imports)

## Glossary

- **Shim**: A thin compatibility file that re-exports symbols from their new locations
- **Code motion**: Moving code between files without changing it
- **Acyclic dependency graph**: No module A imports B which imports A (directly or transitively)
