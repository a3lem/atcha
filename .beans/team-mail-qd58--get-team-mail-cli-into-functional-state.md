---
# team-mail-qd58
title: Get team-mail CLI into functional state
status: completed
type: task
priority: normal
created_at: 2026-02-01T19:44:47Z
updated_at: 2026-02-01T19:53:16Z
---

Make the CLI installable via pip install -e . and expose a team-mail command

## Acceptance Criteria
- [ ] Locally installing (-e) the project exposes a cli command team-mail
- [ ] The CLI runs

## Tasks
- [ ] Reorganize src/team-mail to src/team_mail (valid Python module name)
- [ ] Add __init__.py files for proper packaging
- [ ] Add entry point in pyproject.toml
- [ ] Test installation and CLI execution

## Summary of Changes

- Renamed `src/team-mail` to `src/team_mail` (valid Python module name)
- Updated `pyproject.toml` to use uv build backend (`uv_build`)
- Added `[project.scripts]` entry point: `team-mail = team_mail.cli.team_mail:main`
- Verified installation with `uv sync` and tested CLI with `team-mail --help`

The package now installs correctly with `uv sync` or `pip install -e .` and exposes the `team-mail` command.
