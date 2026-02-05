---
# team-mail-92gi
title: Refactor team-mail to atcha
status: completed
type: epic
priority: normal
created_at: 2026-02-03T20:22:55Z
updated_at: 2026-02-03T21:07:37Z
---

Major refactor from email-style messaging to chat-style messaging. Rename CLI from team-mail to atcha (Agent Team Chat). Includes new command structure, threading support, reply semantics, and last-seen timestamps.

## Key Changes
- Rename: team-mail → atcha
- agents → contacts (with last-seen)
- inbox → messages (check/read)
- New threading model with thread_id
- Reply semantics: --to, --all, --reply-to
- Closed threads (no adding new participants)

## Design Decisions
- --to is always explicit recipients
- --all without --reply-to = broadcast to all contacts
- --reply-to without --to = all thread participants
- --to with --reply-to = specific person(s) in thread
- --all with --reply-to = error (ambiguous)
- send without any recipient = error
