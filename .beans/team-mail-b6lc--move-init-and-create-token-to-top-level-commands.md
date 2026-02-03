---
# team-mail-b6lc
title: Move init and create-token to top-level commands
status: completed
type: task
priority: normal
created_at: 2026-02-01T21:01:42Z
updated_at: 2026-02-01T21:07:38Z
---

CLI improvements:

1. Move `admin init` to `team-mail init`:
   - If --password not provided, prompt interactively
   - Creates .team-mail/ directory
   - Mention in help

2. Move `admin auth` to `team-mail create-token`:
   - More explicit name
   - Doesn't need to be shown in `prompt` output (agents won't need it)
   - Still requires admin password

## Summary of Changes

- Moved `admin init` to top-level `team-mail init`
  - Now prompts interactively for password if `--password` not provided
  - Uses getpass for secure password entry with confirmation
  
- Moved `admin auth` to top-level `team-mail create-token`
  - More explicit name that describes what it does
  - Not shown in `prompt` output (agents don't need it)

- Updated all documentation:
  - CLAUDE.md
  - README.md
  - Plugin commands (init-workspace.md, register.md, identify.md)

- Updated all tests to use new command names

- All 52 tests passing
