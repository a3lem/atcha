---
allowed-tools: Bash
argument-hint: "--password=<password>"
---

Initialize team-mail system in the current directory.

## Arguments

Parse `$ARGUMENTS` to extract:
- `password`: admin password (required)

If no password is provided, ask the user to provide one.

## Steps

Run the admin init command:

```bash
uv run "$TEAM_MAIL_CLI" admin init --password "<password>"
```

This creates:
- `.team-mail/` directory structure
- `admin.json` with hashed password
- `tokens/` directory for auth tokens
- `users/` directory for user profiles

Print the CLI output and explain next steps:
1. Create users with `team-mail admin create <name> <title>` (requires admin token)
2. Get an admin token first: `team-mail admin auth --admin --password <password>`
