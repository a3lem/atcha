---
# atcha-zrk0
title: Standardize terminology from 'agents' to 'users'
status: completed
type: task
priority: normal
created_at: 2026-02-04T10:26:05Z
updated_at: 2026-02-04T11:11:36Z
---

Replace all references to 'agents' with 'users' throughout the codebase for consistency. This includes:

- [x] CLI implementation (src/atcha/cli/atcha.py)
- [x] CLI help messages (part of CLI implementation)
- [x] CLAUDE.md documentation
- [x] README.md documentation
- [x] Skills in extras/claude-plugin/commands/ (SKILL.md)
- [x] Directory structure (.atcha/agents/ → .atcha/users/) - with auto-migration
- [x] Profile JSON structure and field names (no changes needed)
- [x] Command groups (agents commands still work for compatibility)
- [x] Flags (--agent → --user)
- [x] Tests (tests/test_atcha.py)

The goal is to use 'users' consistently, allowing us to later distinguish between human and AI agent users in the profile.

## Summary of Changes

Successfully standardized all terminology from 'agents' to 'users' throughout the codebase:

### Code Changes
- **CLI Implementation**: Updated all function names, variable names, type definitions, and docstrings
  - Changed AgentProfile to UserProfile
  - Changed function names (e.g., _get_agents_dir to _get_users_dir)
  - Changed resolve_agent to resolve_user
  - Updated all variable names (agent_id to user_id, etc.)
  - Changed CLI flag from --agent to --user

- **Directory Structure**: Added automatic migration from .atcha/agents/ to .atcha/users/
  - Existing installations will be migrated automatically on first use

### Documentation Updates
- **CLAUDE.md**: Updated all references to use 'users' terminology
  - Directory structure examples
  - Command documentation
  - Authentication model
  - Quick start examples

- **README.md**: Updated all examples and documentation
  - Quick start guide
  - CLI reference
  - Directory structure
  - Multi-worktree setup examples

- **SKILL.md**: Updated skill documentation for consistency

### Tests
- **test_atcha.py**: Updated all test function names and assertions
  - All 65 tests passing

### Backwards Compatibility
- The agents CLI command group still works (delegates to users logic)
- Automatic directory migration ensures existing installations continue to work
- No manual intervention required for existing users

The codebase now consistently uses 'users' terminology, which allows for future extension to distinguish between human and AI agent users in profiles.
