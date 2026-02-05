---
# atcha-pdia
title: Refactor messages interface
status: completed
type: task
priority: normal
created_at: 2026-02-05T07:43:55Z
updated_at: 2026-02-05T08:04:02Z
---

Implement the plan to refactor the messages interface:
1. Rename body to content (with backward compatibility)
2. Remove obsolete inbox subcommand  
3. Add messages list command (JSON array output, previews, no side effects)
4. Update messages read to accept IDs and --no-mark flag
5. Update tests
6. Update documentation (CLAUDE.md, README.md, SKILL.md)

## Summary of Changes

### Phase 1: Renamed body to content
- Changed message field from `body` to `content` in CLI
- Added `_get_message_content()` helper for backward compatibility with old messages
- Updated `check-inbox.sh` hook to handle both field names

### Phase 2: Removed inbox subcommand
- Removed `inbox` and `inbox read` commands from argparse
- Removed dispatch code in `main()`
- Renamed `cmd_inbox()` → `cmd_messages_check()`
- Renamed `cmd_inbox_read()` → `cmd_messages_read()`

### Phase 3: Updated messages read command
- Added positional `ids` argument to filter by specific message IDs
- Added `--no-mark` flag to prevent marking messages as read

### Phase 4: Added messages list command
- New `cmd_messages_list()` function
- Returns JSON array (not JSONL)
- Shows `preview` field (first 50 chars + "...") by default
- `--no-preview` shows full `content` instead
- Filters: `--limit`, `--thread`, `--from`, `--all`
- Does NOT mark messages as read (no side effects)

### Phase 5: Updated tests
- Renamed `TestInbox` → `TestMessagesCheck`
- Renamed `TestInboxRead` → `TestMessagesRead`
- Updated all `inbox` commands to `messages check/read`
- Updated all `body` assertions to `content`
- Added tests for `messages list` command
- Added tests for `--no-mark` and reading by ID
- Fixed test for role updates (now admin-only)
- Fixed `_create_user` helper to use `name` instead of `id` for tokens

### Phase 6: Updated documentation
- CLAUDE.md: Updated command table, examples, and notes
- README.md: Updated command examples and message format
- SKILL.md: Updated command reference and output formats

### Bug fixes discovered during implementation
- Fixed message ID generation to include random salt (preventing duplicate IDs for messages sent in same second)
