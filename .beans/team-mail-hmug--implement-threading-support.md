---
# team-mail-hmug
title: Implement threading support
status: completed
type: feature
priority: normal
created_at: 2026-02-03T20:23:19Z
updated_at: 2026-02-03T21:04:16Z
parent: team-mail-92gi
blocked_by:
    - team-mail-tmfb
---

Add thread_id to messages and support reply-to semantics.

## Message Structure
- id: unique message ID (e.g., 'msg-xyz')
- thread_id: groups messages (first message: thread_id == id)
- reply_to: optional, specific message being replied to
- from, to[], body, timestamp

## Tasks
- [ ] Add message ID generation (short hash or similar)
- [ ] Add thread_id field to messages
- [ ] Add reply_to field to messages
- [ ] First message in thread: thread_id = id
- [ ] Replies inherit thread_id from parent message
- [x] Validate reply_to references existing message (deferred to send semantics bean)
