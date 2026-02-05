---
# atcha-l4yx
title: Update outdated README.md and CLAUDE.md
status: completed
type: task
priority: normal
created_at: 2026-02-05T08:50:50Z
updated_at: 2026-02-05T09:02:32Z
---

Fix outdated quickstart instructions, remove incorrect backward compatibility notes, remove references to non-existent slash commands, and correct CLI usage examples.

## Issues to fix:
- [x] README: Wrong quickstart - should use 'uv tool install -e .' not 'uv sync'
- [x] README: Remove backward compatibility note about 'body' field (line 193)
- [x] README: Fix 'python cli/atcha.py send' to 'atcha send' (line 57)
- [x] README: Remove outdated slash commands table (lines 74-85)
- [x] CLAUDE.md: Remove backward compatibility note about 'body' field (line 172)
- [x] CLAUDE.md: Update 'Slash Commands' section - they're now Claude Code skills (lines 190-204)
- [x] CLAUDE.md: Fix components path reference (line 241) - commands/*.md doesn't exist


## Summary of Changes

### README.md
- Added correct quickstart instructions: git clone, then `uv tool install -e .`
- Removed incorrect backward compatibility note about 'body' field
- Fixed command example from `python cli/atcha.py send` to `atcha send`
- Replaced outdated slash commands table with brief reference to Claude Code skill
- Improved user identifier section to explain name vs id distinction
- Updated all example user names to use short names (maya, alex) consistently
- Fixed Development section path and simplified Requirements section

### CLAUDE.md
- Removed backward compatibility note about 'body' field
- Replaced 'Slash Commands' section with brief 'Claude Code Skill' section
- Updated Components table to reference skills directory instead of non-existent commands directory
- Renamed design decision section from 'Why primitives + commands' to 'Why primitives + skill'
- Updated Quick Start to use correct installation command and short user names



## Additional Update

Added practical guide for using atcha with Claude Code:
- Running as a user: Shows how to launch Claude with ATCHA_TOKEN (agent cannot impersonate others)
- Running as an admin: Shows how to launch Claude with ATCHA_ADMIN_PASS for user management
- Includes example prompt for creating users with natural language descriptions



## Security and ID Format Updates

- **Removed dangerous multi-token examples**: Quick Start no longer shows storing multiple tokens in variables (USER_MAYA_TOKEN, USER_ALEX_TOKEN), which could give an agent access to multiple identities
- **Added security warning**: Emphasized that each user should only have access to their own token
- **Updated ID format throughout**: Changed from human-readable `maya-backend-engineer` format to random alphanumeric `usr-a3k9m` format
- **Updated all examples**: Directory structure, user identifiers section, multi-worktree setup now show correct random ID format
- **Clarified message format**: Added note about `content` field usage



## CLAUDE.md Updates

- Updated profile.json example to show random ID format (`usr-a3k9m`)
- Rewrote User identifiers section to explain random alphanumeric IDs instead of name-role-slug format
- Updated directory structure to show user-id instead of user-name
- Fixed Message flow example to reference correct directory path
- Simplified Quick Start token handling (no intermediate variable)
