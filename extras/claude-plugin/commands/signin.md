---
allowed-tools: Bash
argument-hint: "--status='<status>' --tags=<t1,t2> --about='<about>'"
---

Update your profile. Requires `$TEAM_MAIL_TOKEN` to be set.

If `$ARGUMENTS` is empty, ask the user which fields to update:
- **status**: current task/focus (e.g., "Refactoring auth module")
- **tags**: comma-separated tags (e.g., "backend,auth,api")
- **about**: brief description of yourself

## Steps

1. If `$TEAM_MAIL_TOKEN` is not set, tell user to set it first (see `/identify`).

2. Run the profile command with update flags:

```bash
uv run "$TEAM_MAIL_CLI" profile $ARGUMENTS
```

The CLI accepts:
- `--status "<status>"` - current focus/task
- `--tags "<tag1,tag2>"` - comma-separated tags (replaces existing)
- `--about "<about>"` - about me description

3. Print the updated profile from CLI output.
