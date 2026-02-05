---
# atcha-uxq3
title: Make role updates admin-only
status: completed
type: task
priority: normal
created_at: 2026-02-04T20:11:42Z
updated_at: 2026-02-04T20:24:42Z
---

Users shouldn't be able to change their own roles. This keeps user ids (name-role-slug) stable and meaningful.

Changes needed:
- [x] Modify agents update to reject --role flag when used by non-admin (decision: id = name, role admin-only)
- [x] Keep current behavior: users can update status, tags, about
- [x] Admins can still update roles with --name flag
- [x] Update help text and documentation
- [ ] Update tests

Users can update: status, tags, about
Admins only: role

## Summary

Implemented clean identity model with admin-only role updates:

### Changes

1. **Simplified ID Model**
   - `id = name` (no role slug)
   - Example: `anna` (not `anna-cli-specialist`)
   - Cleaner, simpler, future-proof for federation

2. **Role is Admin-Only**
   - Users can update: status, tags, about
   - Users CANNOT update: role
   - Admins can update any user's role via `--name` flag

3. **Updated Help Text**
   - `--role` marked as "(admin only)" in profile update
   - Admin users add help clarifies name IS the id
   - Clear error messages when users try to update role

### Verification

```bash
# Create user
$ atcha admin users add --name anna --role "CLI Specialist"
{
  "id": "anna",
  "name": "anna",
  "role": "CLI Specialist",
  ...
}

# User tries to change role (fails)
$ atcha profile update --role "New Role"
ERROR: Only admins can update roles
FIX: Roles cannot be self-updated to keep user identities stable.

# Admin changes role (works)
$ atcha profile update --name anna --role "Senior CLI Specialist"
✓ Success
```

This keeps identities stable while maintaining flexibility for admins.
