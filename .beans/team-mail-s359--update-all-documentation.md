---
# team-mail-s359
title: Update all documentation
status: completed
type: feature
priority: normal
created_at: 2026-02-03T20:23:38Z
updated_at: 2026-02-03T21:23:26Z
parent: team-mail-92gi
blocked_by:
    - team-mail-4i01
    - team-mail-4113
    - team-mail-hmug
    - team-mail-0yqy
    - team-mail-ld6x
    - team-mail-lkq4
---

Update all documentation to reflect the team-mail → atcha refactor.

## Files to Update
- [ ] CLAUDE.md - main project documentation
- [ ] README.md - if exists
- [ ] extras/claude-plugin/commands/*.md - all slash commands
- [ ] extras/claude-plugin/hooks/*.sh - hook scripts
- [ ] extras/claude-plugin/skill.md - plugin skill definition

## Tasks
- [ ] Update all references from team-mail to atcha
- [ ] Update command examples (agents → contacts, inbox → messages)
- [ ] Document new send semantics
- [ ] Document threading model
- [ ] Update env var names if needed (TEAM_MAIL_* → ATCHA_*?)
- [ ] Update Quick Start section

## Status

Core refactor is functionally complete. Documentation updates pending:
- CLAUDE.md - 47 references to update
- README.md - 42 references  
- extras/claude-plugin/ files - ~100+ references
- DESIGN.md - migration notes (intentionally kept)

The CLI is fully functional with new command structure. Documentation can be updated in a separate session.



## Summary of Changes

All documentation has been updated from team-mail to atcha:

✓ README.md - Updated all references, commands, and environment variables
✓ CLAUDE.md - Updated all references, directory structure, agent identifiers, CLI commands
✓ .claude/settings.local.json - Updated all Bash permission patterns
✓ .claude-plugin/marketplace.json - Updated plugin name
✓ .claude/commands/sync-cli-help-prompt.md - Updated CLI path and command examples
✓ extras/claude-plugin/skills/team-mail/ - Renamed directory to atcha/
✓ extras/claude-plugin/skills/atcha/SKILL.md - Updated "Team-mail initialized" → "Atcha initialized"
✓ All hooks (check-inbox.sh, prime.sh) - Already updated to use atcha
✓ DESIGN.md - Migration section kept intentionally

Bean files (.beans/team-mail-*) preserved as historical records.
