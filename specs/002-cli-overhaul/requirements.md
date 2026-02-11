---
locked: false
status: draft
---

# Requirements: CLI Overhaul

## Overview

### Context

The atcha CLI has grown organically. Some commands use optional positional arguments (`contacts [name]`), others have subcommands (`messages check/read/list`). Some admin-scoped functionality lives at the top level (`init`, `env`). These inconsistencies make the CLI harder to learn and maintain.

### Problem

1. **Inconsistent command patterns**: `contacts` takes an optional positional to show one user; `messages` requires a subcommand. No single discoverable convention.
2. **Misplaced commands**: `init` is top-level despite requiring/setting the admin password. `env` is visible to regular users but only useful for hooks.
3. **Merged list/show semantics**: `contacts [name]` overloads bare invocation (list) and positional argument (show) in one command.
4. **Overly permissive read-all**: `messages read` with no arguments reads and marks *all* unread messages. Users may accidentally mark everything as read.
5. **Field permission confusion**: `profile update --role` exists but role is admin-only. Users hit a permission error after parsing succeeds.
6. **Admin user management gaps**: No `admin users update`, no `admin users delete`, no bare `admin users` listing.

### Goal

Restructure the CLI command tree so every command follows the same conventions, admin-only functionality is scoped under `admin`, and field permissions are enforced at the parser level. The overhaul is backward-compatible at the data layer (no file format changes) while being a clean break at the CLI interface.

## Functional Requirements

### Command Structure Conventions

#### FR-001: Bare Plural Lists the Collection

Bare invocation of a plural noun prints the collection as a list.

**Acceptance Criteria:**

1. WHEN user runs `atcha contacts` (no subcommand), the CLI SHALL list all contacts as a JSON array (excluding self by default)
2. WHEN user runs `atcha messages` (no subcommand), the CLI SHALL list messages with previews (absorbing current `messages list`), without marking any as read
3. WHEN admin runs `atcha admin users` (no subcommand), the CLI SHALL list all users as a JSON array
4. WHEN admin runs `atcha admin spaces` (no subcommand), the CLI SHALL list the local space and all federated spaces

#### FR-002: Subcommands Are Verbs on Collections

Each collection supports verb subcommands for non-list operations.

**Acceptance Criteria:**

1. WHEN user runs `atcha contacts show <id-or-address>`, the CLI SHALL display that contact's profile
2. WHEN user runs `atcha messages check`, the CLI SHALL print a summary (count + senders) without marking messages as read
3. WHEN user runs `atcha messages read <msg-id> [msg-id...]`, the CLI SHALL read and display the specified messages, marking them as read
4. WHEN user runs `atcha messages read` with no message IDs, the CLI SHALL error with guidance to provide at least one message ID
5. WHEN user runs `atcha profile` (no subcommand), the CLI SHALL display the authenticated user's own profile
6. WHEN user runs `atcha profile update [flags]`, the CLI SHALL update the authenticated user's profile fields

### Contacts

#### FR-003: Contacts List and Show

**Acceptance Criteria:**

1. WHEN user runs `atcha contacts`, the CLI SHALL output a JSON array of contact profiles, excluding the authenticated user by default
2. WHEN user runs `atcha contacts --include-self`, the CLI SHALL include the authenticated user in the list
3. WHEN user runs `atcha contacts --tags=x,y`, the CLI SHALL filter to contacts matching any listed tag
4. WHEN user runs `atcha contacts --full`, the CLI SHALL include all fields (dates, empty values)
5. WHEN user runs `atcha contacts show <id-or-address>`, the CLI SHALL display the specified contact's profile
6. WHEN user runs `atcha contacts show <id-or-address> --full`, the CLI SHALL include all fields
7. [CLI] SHALL remove the `--names-only` flag (superseded by `--json` and jq)

### Messages

#### FR-004: Messages List, Check, and Read

**Acceptance Criteria:**

1. WHEN user runs `atcha messages`, the CLI SHALL list messages with previews as a JSON array, without marking any as read
2. WHEN user runs `atcha messages --from=<address>`, the CLI SHALL filter to messages from the specified sender
3. WHEN user runs `atcha messages --since=<ISO-timestamp>`, the CLI SHALL filter to messages after the specified timestamp
4. WHEN user runs `atcha messages --limit=N`, the CLI SHALL return at most N messages
5. WHEN user runs `atcha messages --include-read`, the CLI SHALL include already-read messages
6. WHEN user runs `atcha messages --no-preview`, the CLI SHALL show full content instead of truncated preview
7. WHEN user runs `atcha messages check`, the CLI SHALL display an inbox summary (count + senders) without marking as read
8. WHEN user runs `atcha messages read <msg-id> [msg-id...]`, the CLI SHALL read the specified messages and mark them as read
9. WHEN user runs `atcha messages read` with zero message IDs, the CLI SHALL error: `ERROR: at least one message ID required`
10. WHEN user runs `atcha messages read <msg-id> --no-mark`, the CLI SHALL display the message without marking as read

### Profile

#### FR-005: Profile View and Self-Service Update

**Acceptance Criteria:**

1. WHEN user runs `atcha profile`, the CLI SHALL display the authenticated user's profile
2. WHEN user runs `atcha profile update --status <text>`, the CLI SHALL update the user's status
3. WHEN user runs `atcha profile update --about <text>`, the CLI SHALL update the about field
4. WHEN user runs `atcha profile update --tags <csv>`, the CLI SHALL update the tags field
5. [CLI] SHALL NOT accept `--role` or `--name` on `profile update` (admin-only via `admin users update`)

### Identity

#### FR-006: Whoami and Status

**Acceptance Criteria:**

1. WHEN user runs `atcha whoami`, the CLI SHALL print the user's address (e.g. `maya@`)
2. WHEN user runs `atcha whoami --id`, the CLI SHALL print only the user ID (e.g. `usr-a3k9m`)
3. WHEN user runs `atcha whoami --name`, the CLI SHALL print only the bare name (e.g. `maya`)
4. WHEN user runs `atcha whoami --id --name`, the CLI SHALL error (mutually exclusive)
5. WHEN user runs `atcha status`, the CLI SHALL print "Atcha initialized" (exit 0) or "Not initialized" (exit 1)
6. WHEN user runs `atcha status --quiet`, the CLI SHALL suppress all output (exit code only)

### Address Enforcement

#### FR-007: Address Format Requirement

All commands that accept user references require addresses or user IDs, not bare names.

**Acceptance Criteria:**

1. WHEN a command receives a bare name (e.g. `maya`), the CLI SHALL error: `ERROR: bare name 'maya' is ambiguous` with `FIX: use 'maya@' for local or 'maya@<space>' for cross-space`
2. WHEN a command receives `maya@`, the CLI SHALL resolve it as a local user
3. WHEN a command receives `maya@engineering`, the CLI SHALL resolve it as a cross-space user
4. WHEN a command receives `usr-a3k9m`, the CLI SHALL resolve it by user ID
5. Applies to: `--to`, `--from`, `contacts show`, `admin users update`, `admin users delete`, `admin create-token --user`

### Impersonation

#### FR-008: Admin Impersonation via User ID

**Acceptance Criteria:**

1. WHEN admin uses `--as usr-a3k9m`, the CLI SHALL impersonate that user
2. WHEN admin uses `--as maya@`, the CLI SHALL error: `ERROR: --as requires a user ID (usr-xxx), not an address`
3. WHEN non-admin uses `--as`, the CLI SHALL error: `ERROR: --as requires admin auth`

### Admin Commands

#### FR-009: Admin Init and Utilities

**Acceptance Criteria:**

1. WHEN user runs `atcha admin init [--password <pw>]`, the CLI SHALL initialize `.atcha/` (moved from top-level)
2. WHEN admin runs `atcha admin envs`, the CLI SHALL print shell export statements (moved from top-level `env`)
3. WHEN admin runs `atcha admin create-token --user <address>`, the CLI SHALL generate a token (unchanged)
4. WHEN admin runs `atcha admin password --new <pw>`, the CLI SHALL change the admin password (unchanged)

#### FR-010: Admin Users CRUD

**Acceptance Criteria:**

1. WHEN admin runs `atcha admin users`, the CLI SHALL list all users as a JSON array
2. WHEN admin runs `atcha admin users create --name <n> --role <r> [--status] [--about] [--tags]`, the CLI SHALL create a user
3. WHEN admin runs `atcha admin users create` without `--name` or `--role`, the CLI SHALL error (both required)
4. WHEN admin runs `atcha admin users update <address> [--name] [--role] [--status] [--about] [--tags]`, the CLI SHALL update the user
5. WHEN admin runs `atcha admin users delete <address>`, the CLI SHALL remove the user's directory and token

#### FR-011: Admin Spaces Management

**Acceptance Criteria:**

1. WHEN admin runs `atcha admin spaces`, the CLI SHALL list local space + federated spaces
2. WHEN admin runs `atcha admin spaces update --name <n>`, the CLI SHALL rename the local space
3. WHEN admin runs `atcha admin spaces update --description <text>`, the CLI SHALL set the space description
4. WHEN admin runs `atcha admin spaces add <dir>`, the CLI SHALL register a federated space
5. WHEN admin runs `atcha admin spaces drop <id-or-handle>`, the CLI SHALL unregister a federated space

### Migration Errors

#### FR-012: Removed and Relocated Commands

**Acceptance Criteria:**

1. WHEN user runs `atcha init`, the CLI SHALL error with `FIX: use 'atcha admin init'`
2. WHEN user runs `atcha env`, the CLI SHALL error with `FIX: use 'atcha admin envs'`
3. WHEN user runs `atcha admin users add`, the CLI SHALL error with `FIX: use 'atcha admin users create'`
4. WHEN user runs `atcha admin federated`, the CLI SHALL error with `FIX: use 'atcha admin spaces'`
5. WHEN user runs `atcha admin space`, the CLI SHALL error with `FIX: use 'atcha admin spaces update'`
6. WHEN user runs `atcha messages list`, the CLI SHALL error with `FIX: use bare 'atcha messages'`

### JSON Output

#### FR-013: Consistent JSON Output

**Acceptance Criteria:**

1. WHEN `--json` is passed to `messages check`, output `{"count": N, "senders": {"maya": 2}}`
2. WHEN `--json` is passed to `messages read`, output a JSON array instead of JSONL
3. WHEN `--json` is passed to `admin init`, output `{"status": "initialized", "path": "..."}`
4. WHEN `--json` is passed to `whoami`, output `{"address": "maya@", "id": "usr-a3k9m", "name": "maya"}`
5. WHEN `--json` is passed to `status`, output `{"initialized": true/false}`
6. Commands already outputting JSON (`contacts`, `messages`, `send`, `profile`, `admin users`) are unaffected by `--json`

## Non-Functional Requirements

### NFR-001: Convention Discoverability

1. [CLI] SHALL follow "bare plural = list, subcommand = verb" consistently across all collection commands
2. [CLI help] SHALL show the convention pattern in top-level `--help`

### NFR-002: Data Layer Unchanged

1. [CLI] SHALL NOT change any file formats (profile.json, inbox.jsonl, sent.jsonl, state.json, admin.json, space.json, federation.local.json)
2. [CLI] SHALL NOT change token derivation or verification logic

### NFR-003: Helpful Migration Errors

1. WHEN a user invokes a removed/relocated command, the error SHALL include a `FIX:` line with the replacement command

### NFR-004: Stdlib-Only

1. [CLI] SHALL use only Python standard library modules

## Constraints

- Breaking change at CLI interface level. Scripts calling old commands must update.
- `--as` changing from address to user-ID breaks admin scripts.
- `messages read` requiring explicit IDs breaks `check-inbox.sh` hook (line 7: `atcha messages read` with no args).
- The hook must be updated to use `messages check` or to list-then-read specific IDs.

## Assumptions

- Users accept a CLI breaking change for consistency.
- CLAUDE.md and skill files will be updated alongside the CLI.
- The `check-inbox.sh` hook will be updated.

## Out of Scope

- File format changes
- New features (threading, reactions, attachments)
- Federation protocol changes (spec 001)
- Claude Code skill changes (separate update)
- Shell completions

## Verification

- **Convention consistency**: Every plural noun (`contacts`, `messages`, `admin users`, `admin spaces`) lists when bare, supports verb subcommands
- **No stale commands**: `init`, `env`, `admin users add`, `admin federated`, `admin space`, `messages list` all produce migration errors
- **Address enforcement**: Bare names rejected everywhere a user reference is accepted
- **Field permissions**: `profile update` rejects `--role`/`--name`; `admin users update` accepts them
- **Explicit read**: `messages read` with no IDs errors
- **Data integrity**: Existing test scenarios pass with updated command invocations
- **JSON output**: `--json` produces valid JSON for all documented commands

## Glossary

- **Address**: `name@space` format. `name@` = local. `name@space` = cross-space. Bare names rejected.
- **User ID**: Immutable `usr-{5-char}` format. Accepted anywhere an address is accepted.
- **Collection command**: Plural noun that lists when invoked bare.
- **Self-service field**: Profile field users can update (status, about, tags).
- **Admin-only field**: Profile field only admins can set (name, role).
- **Migration error**: Error from removed/relocated command with `FIX:` line.
