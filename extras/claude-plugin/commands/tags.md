---
allowed-tools: Bash
argument-hint: ""
---

List all tags with member counts.

## Steps

1. Get list of all usernames:

```bash
uv run "$TEAM_MAIL_CLI" team
```

2. For each username, read their profile:

```bash
uv run "$TEAM_MAIL_CLI" profile "<username>"
```

3. Aggregate tags from all profiles, counting how many users have each tag.

4. Format output:

```
- backend (3 users)
- frontend (2 users)
- auth (2 users)
- devops (1 user)
```

5. If no tags found, print "No tags found."
