---
# team-mail-nujy
title: 'users add: use --name and --role options'
status: completed
type: task
priority: normal
created_at: 2026-02-01T20:24:14Z
updated_at: 2026-02-01T20:29:45Z
parent: team-mail-88qz
---

Change `team-mail users add` from positional arguments to required options:
- Before: `team-mail users add maya-backend "Backend Engineer"`
- After: `team-mail users add --name maya-backend --role "Backend Engineer"`

This makes the command more readable and self-documenting.
