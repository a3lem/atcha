---
# team-mail-lkq4
title: Update test suite
status: completed
type: task
priority: normal
created_at: 2026-02-03T20:23:48Z
updated_at: 2026-02-03T21:07:20Z
parent: team-mail-92gi
blocked_by:
    - team-mail-0yqy
---

Update all tests to reflect new command structure and semantics.

## Tasks
- [ ] Update imports (team_mail → atcha)
- [ ] Update test cases for contacts command
- [ ] Update test cases for messages command
- [ ] Add tests for threading (thread_id, reply_to)
- [ ] Add tests for new send semantics
- [ ] Add tests for error cases (--all --reply-to, no recipients)
- [ ] Test last_seen timestamp updates
- [x] Ensure all tests pass (58/58)
