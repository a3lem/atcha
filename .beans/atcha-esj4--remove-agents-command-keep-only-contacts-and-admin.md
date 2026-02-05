---
# atcha-esj4
title: Remove agents command, keep only contacts and admin users
status: completed
type: task
priority: normal
created_at: 2026-02-03T21:44:59Z
updated_at: 2026-02-04T10:13:50Z
---

Remove the 'atcha agents' command from the CLI since it's replaced by 'atcha contacts' for users and 'atcha admin users' for admin.

## Changes needed:
- Remove 'agents' subparser from CLI
- Ensure 'contacts' works independently (not delegating)
- Ensure 'admin users' command exists for listing all users
- Update any remaining references in docs/tests

## Current state:
- contacts delegates to agents commands
- agents add/update are used by admin

## Target state:
- contacts is the primary user command
- admin users for admin to list all
- No 'atcha agents' command exposed to users



## Summary of Changes

Successfully removed the `agents` command and replaced it with `contacts` and `admin users`:

✓ Removed `agents` parser from CLI
✓ Added `admin users` command with `list` and `add` subcommands
✓ Added `profile update` command for user profile updates
✓ Updated Parsers NamedTuple (removed agents)
✓ Updated all 65 tests to use new commands:
  - `agents add` → `admin users add`
  - `agents list` → `contacts --include-self` (or just `contacts` for excluding self)
  - `agents get` → `contacts <name>`
  - `agents update` → `profile update`
✓ Fixed test issues with admin password env var
✓ All 65 tests passing

## Command Structure

**User commands:**
- `atcha contacts` - list contacts (excludes self by default)
- `atcha contacts --include-self` - include self in list  
- `atcha contacts <name>` - view specific contact profile
- `atcha profile update` - update your own profile

**Admin commands:**
- `atcha admin users list` - list all users
- `atcha admin users add` - create new user
- `atcha profile update --name <user> --password <pw>` - admin can update other users
