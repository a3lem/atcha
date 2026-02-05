---
# atcha-9fhm
title: Fix outdated command documentation in CLAUDE.md, README.md, and sync-cli-help-prompt.md
status: completed
type: task
priority: normal
created_at: 2026-02-04T20:47:50Z
updated_at: 2026-02-04T20:50:38Z
---

Update three documentation files to use correct CLI commands: contacts, admin users, profile update, and send --to flags. CLAUDE.md is critical as it's loaded into system prompt.

## Summary of Changes

Fixed outdated command documentation across three files:

### CLAUDE.md (CRITICAL - System Prompt)
- Lines 59-61: Changed atcha agents get → atcha contacts
- Line 61: Changed atcha send maya → atcha send --to maya
- Line 126: Added --to flag to admin send example
- Line 129: Changed atcha agents update → atcha profile update
- Lines 141-153: Renamed "Users commands" section to "Contact and profile commands" and updated all commands:
  - agents list → contacts (no subcommand)
  - agents get <name> → contacts <name>
  - agents add → admin users add
  - agents update → profile update
- Line 161: Changed send <to> → send --to <name>
- Lines 259-276: Updated Quick Start section with correct commands

### README.md (User Documentation)
- Lines 38, 41: Changed atcha users add → atcha admin users add
- Line 57: Added --to flag to send command
- Line 106: Changed atcha users add → atcha admin users add
- Lines 113-128: Updated user commands section:
  - Removed non-existent atcha profile show
  - Changed agents list → contacts
  - Changed agents get → contacts
  - Added --to flag to send command

### .claude/commands/sync-cli-help-prompt.md
- Lines 25-26: Changed agents list and agents get → contacts with proper flags
- Added note about --include-self flag

### Verification Results
All three checks passed:
- ✓ No 'atcha agents' commands remain
- ✓ No standalone 'atcha users' commands (only 'admin users' exists)
- ✓ All send commands use the --to flag

### Impact
This fix is critical because CLAUDE.md is loaded into the system prompt for every agent session. Outdated commands were causing agents to fail when trying to use documented functionality.
