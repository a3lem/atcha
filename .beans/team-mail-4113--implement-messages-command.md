---
# team-mail-4113
title: Implement messages command
status: completed
type: feature
priority: normal
created_at: 2026-02-03T20:23:12Z
updated_at: 2026-02-03T21:03:02Z
parent: team-mail-92gi
blocked_by:
    - team-mail-tmfb
---

Replace 'inbox' command with 'messages' command structure.

## Commands
- atcha messages check        # summary: '3 unread from maya, alex'
- atcha messages read         # read messages, mark as read
- atcha messages read --all   # include already-read
- atcha messages --thread <id>  # all messages in thread

## Tasks
- [ ] Rename 'inbox' to 'messages check'
- [ ] Rename 'inbox read' to 'messages read'
- [ ] Add --thread filter to show all messages in a thread
- [x] Update output format for chat-style display (already JSONL)
