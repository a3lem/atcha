---
# team-mail-z7qr
title: Progressive disclosure restructure for team-mail plugin
status: completed
type: feature
priority: normal
created_at: 2026-02-02T20:57:12Z
updated_at: 2026-02-02T21:10:11Z
---

Restructure team-mail Claude plugin with progressive disclosure:
- [x] CLI --help improvements (add examples)
- [x] SKILL.md restructure (3 tiers)
- [x] Restore hooks (session-start.sh, check-inbox.sh, hooks.json)
- [x] Create sync mechanism (scripts/sync-skill.sh)
- [x] Deprecate team-mail prompt command

## Summary of Changes

Restructured team-mail Claude plugin with progressive disclosure:

1. **CLI --help improvements**: Added epilog examples to key commands (agents, send, inbox)

2. **SKILL.md restructure** (237 → 124 lines):
   - Tier 1: Essential commands (whoami, agents list, send, inbox)
   - Tier 2: Filters & profile updates
   - Tier 3: Admin setup & troubleshooting

3. **Restored hooks**:
   - session-start.sh: Lightweight identity + skill pointer
   - check-inbox.sh: Message notifications on PostToolUse
   - hooks.json: Configuration for both hooks

4. **Created sync mechanism**: scripts/sync-skill.sh extracts CLI help for comparison

5. **Deprecated team-mail prompt**: Marked as deprecated in help text
