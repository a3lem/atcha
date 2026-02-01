---
allowed-tools: Bash
argument-hint: ""
---

Print your profile.

## Steps

1. If `$TEAM_MAIL_TOKEN` is not set, tell user to set it first (see `/identify`).

2. Read your profile:

```bash
uv run "$TEAM_MAIL_CLI" profile
```

3. Format the JSON output for the user:

```
id:      maya-backend-engineer
title:   Backend Engineer
status:  Refactoring auth module
tags:    backend, auth
about:   I handle backend services and API development.
joined:  2026-01-27T10:00:00Z
```
