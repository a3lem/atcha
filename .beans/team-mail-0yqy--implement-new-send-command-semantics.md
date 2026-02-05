---
# team-mail-0yqy
title: Implement new send command semantics
status: completed
type: feature
priority: normal
created_at: 2026-02-03T20:23:26Z
updated_at: 2026-02-03T21:33:23Z
parent: team-mail-92gi
blocked_by:
    - team-mail-hmug
---

Update send command with new recipient and reply semantics.

## Send Variants
| Command | Recipients |
|---------|------------|
| send --to maya 'msg' | just maya |
| send --to maya --to alex 'msg' | maya and alex |
| send --all 'msg' | broadcast to all contacts |
| send --reply-to X 'msg' | all thread X participants |
| send --to maya --reply-to X 'msg' | just maya (must be in thread) |
| send --all --reply-to X 'msg' | ERROR (ambiguous) |
| send 'msg' | ERROR (no recipients) |

## Tasks
- [ ] Make --to repeatable for multiple recipients
- [ ] Implement --all flag for broadcast
- [ ] Implement --reply-to flag
- [ ] --reply-to without --to = all thread participants
- [ ] --to with --reply-to validates recipient is in thread
- [ ] --all with --reply-to = error with helpful message
- [ ] No recipients = error with helpful message
- [ ] Closed threads: can't add new recipients via reply

## Status

Ready to implement. This is a core part of the atcha design, not a future enhancement.



## Summary of Changes

Implemented all new send command semantics:

✓ Parser updated with --to (repeatable), --all, --reply-to flags
✓ cmd_send rewritten to handle multiple recipients, broadcast, and threading
✓ Added helper functions _find_message_by_id() and _get_thread_participants()
✓ Validates all recipient combinations (--all with --reply-to errors, etc.)
✓ Thread participants validation for closed threads
✓ Updated all 58 existing tests to use new --to syntax
✓ Added 7 new tests covering all new semantics
✓ All 65 tests passing

The send command now supports:
- Single recipient: `--to alice "message"`
- Multiple recipients: `--to alice --to bob "message"`
- Broadcast: `--all "message"`
- Reply to thread: `--reply-to msg-abc123 "message"`
- Reply to specific person: `--to alice --reply-to msg-abc123 "message"`

Error handling for ambiguous cases (--all with --reply-to, no recipients, recipient not in thread) all working correctly.
