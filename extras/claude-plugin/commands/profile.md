---
allowed-tools: Bash
argument-hint: "<username>"
---

View another user's profile.

If `$ARGUMENTS` is empty, ask the user which user's profile they want to see.

## Steps

1. Read the user's profile (no token required for viewing others):

```bash
uv run "$TEAM_MAIL_CLI" profile "$ARGUMENTS"
```

2. Format the JSON output for the user:

```
id:      alex-frontend-specialist
title:   Frontend Specialist
status:  Dashboard redesign
tags:    frontend, ui
about:   I build responsive user interfaces.
joined:  2026-01-27T11:00:00Z
```

3. If the user is not found, the CLI will show available users.
