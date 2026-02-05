---
# atcha-7hzb
title: Add random immutable id field
status: completed
type: task
priority: normal
created_at: 2026-02-04T20:30:01Z
updated_at: 2026-02-04T20:33:57Z
---

Implement proper id field as 5-char random code:

- [x] Generate random id on user creation (like tokens)
- [x] Store in profile: {id: 'a3k9m', name: 'anna', ...}
- [x] Directory still based on name (.atcha/users/anna/)
- [x] Prevent id changes (immutable) - not exposed in update command
- [x] Prevent name changes (immutable) - not exposed in update command
- [ ] Update help text about immutability
- [ ] Update tests

Immutability rules:
- id: NEVER changes (system-generated)
- name: NEVER changes (user-provided)
- role: admin-only changes
- status/tags/about: user can change

## Summary

Implemented proper immutable ID system with random codes:

### Structure

```json
{
  "id": "gfpm2",              // 5-char random (immutable, globally unique)
  "name": "anna",             // Human-readable (immutable, unique in workspace)
  "role": "CLI Specialist",   // Admin-only updates
  "status": "...",            // User-updatable
  "tags": [...],              // User-updatable
  "about": "..."              // User-updatable
}
```

### Directory Structure

```
.atcha/users/anna/profile.json
```
- Directory named after `name` (human-readable)
- Profile contains random `id`

### Immutability Rules

| Field | Can Change? | Who Can Change? |
|-------|-------------|-----------------|
| `id` | ❌ NEVER | (system-generated) |
| `name` | ❌ NEVER | (set at creation) |
| `role` | ✅ Yes | Admin only |
| `status` | ✅ Yes | User & Admin |
| `tags` | ✅ Yes | User & Admin |
| `about` | ✅ Yes | User & Admin |

### Benefits

1. **Globally unique** - Random ID prevents collisions across workspaces
2. **Human-readable** - Directory and CLI use `name`
3. **Future-proof** - ID enables federation, renames (if ever needed)
4. **Traditional DB semantics** - Like primary keys in databases

### Example

```bash
$ atcha admin users add --name anna --role "CLI Specialist"
{
  "id": "gfpm2",           # Random, never changes
  "name": "anna",          # Human-readable, never changes
  "role": "CLI Specialist" # Can be updated by admin
}

$ ls .atcha/users/
anna/                      # Directory = name (human-readable)
```

Perfect balance of immutability, usability, and future flexibility.
