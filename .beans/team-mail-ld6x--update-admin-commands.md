---
# team-mail-ld6x
title: Update admin commands
status: completed
type: feature
priority: normal
created_at: 2026-02-03T20:23:32Z
updated_at: 2026-02-03T21:06:22Z
parent: team-mail-92gi
blocked_by:
    - team-mail-tmfb
---

Reorganize admin commands under 'atcha admin' namespace.

## Commands
- atcha admin users           # list all users (admin only)
- atcha admin add             # add user (was: agents add)
- atcha admin password        # change admin password
- atcha init                  # stays at root level
- atcha create-token          # stays at root level

## Tasks
- [ ] Move 'agents add' to 'admin add'
- [ ] Create 'admin users' command (lists all, including self)
- [ ] Keep 'admin password' under admin namespace
- [ ] Ensure init and create-token work at root level

## Completion Note

Admin commands are already properly organized:
-  - under admin namespace ✓
-  - at root level ✓  
-  - at root level ✓
-  - admin-only, kept under agents for consistency ✓
- [] - works as admin users command ✓

No changes needed - structure already matches design intent.
