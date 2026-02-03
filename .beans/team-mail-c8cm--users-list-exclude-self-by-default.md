---
# team-mail-c8cm
title: 'users list: exclude self by default'
status: completed
type: task
priority: normal
created_at: 2026-02-01T20:24:11Z
updated_at: 2026-02-01T20:26:23Z
parent: team-mail-88qz
---

Change `team-mail users list` behavior:
- Exclude authenticated user from list by default
- Add `--include-self` flag to include self in the list
- Exception: if token is admin, list all users (no exclusion)
