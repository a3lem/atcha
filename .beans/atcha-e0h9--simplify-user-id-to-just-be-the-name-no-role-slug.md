---
# atcha-e0h9
title: Simplify user id to just be the name (no role slug)
status: scrapped
type: task
priority: normal
created_at: 2026-02-04T20:09:24Z
updated_at: 2026-02-04T20:11:30Z
---

The current design has a flaw:
- id = name-role-slug
- But role can be updated, making the id stale/misleading

Solution: id should just be the name (which is already unique)

- [ ] Remove role-based id generation
- [ ] Update CLI to use name as id directly
- [ ] Update documentation 
- [ ] Add migration for existing users (rename directories)
- [ ] Update all tests

Since name is always unique, there's no need for the role slug in the id.


## Reasons for Scrapping

User correctly pointed out that the id combining name + role is helpful context for other agents. The real issue is that users shouldn't be able to change their own roles anyway.

Better solution: Make role updates admin-only. This keeps ids stable and meaningful.
