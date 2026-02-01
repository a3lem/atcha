---
allowed-tools: Bash
argument-hint: ""
---

List all users with their profiles.

## Steps

1. Get list of all usernames:

```bash
uv run "$TEAM_MAIL_CLI" team
```

2. For each username, read their profile:

```bash
uv run "$TEAM_MAIL_CLI" profile "<username>"
```

3. If `$TEAM_MAIL_TOKEN` is set, get your own identity to mark "(you)":

```bash
uv run "$TEAM_MAIL_CLI" profile
```

4. Format output for the user. For each user show:
   - Username (mark with "(you)" if it matches your identity)
   - Title
   - Current status/focus
   - Tags

Example output:
```
- maya-backend-engineer (you) [Backend Engineer] — Refactoring auth module  tags: backend, auth
- alex-frontend-specialist [Frontend Specialist] — Dashboard redesign  tags: frontend, ui
- kai-devops-lead [DevOps Lead] — CI/CD pipelines  tags: devops, infra
```

5. If no users found, print "No users registered."
