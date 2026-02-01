---
allowed-tools: Bash
argument-hint: ""
---

Display your identity in the team-mail system.

This command shows your profile based on the token set in `$TEAM_MAIL_TOKEN`.

## Steps

1. If `$TEAM_MAIL_TOKEN` is not set, explain how to get a token:
   - Ask admin to create you: `team-mail admin create <name> <title>`
   - Get your token: `team-mail admin auth --user <name> --password <admin-password>`
   - Set it: `export TEAM_MAIL_TOKEN=<token>`

2. Display your identity:

```bash
uv run "$TEAM_MAIL_CLI" profile show
```

This returns something like:
```
You are **maya-backend-engineer**.
Role: Backend Engineer
Status: Refactoring auth module
Tags: backend, auth
```

The token-based system means your identity is automatically determined by your token — no need to specify `--as` flags.
