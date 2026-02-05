---
# team-mail-4i01
title: Implement contacts command
status: completed
type: feature
priority: normal
created_at: 2026-02-03T20:23:07Z
updated_at: 2026-02-03T21:01:34Z
parent: team-mail-92gi
blocked_by:
    - team-mail-tmfb
---

Replace 'agents' command with 'contacts' command. Add last-seen timestamps.

## Commands
- atcha contacts              # list all contacts (excludes self)
- atcha contacts <name>       # view contact profile
- atcha contacts --include-self  # include yourself

## Tasks
- [ ] Rename 'agents list' to 'contacts' (default behavior)
- [ ] Rename 'agents get <name>' to 'contacts <name>'
- [ ] Add last_seen field to profile.json
- [ ] Update last_seen on send/read activity
- [ ] Display last_seen in contact listings ('last seen 2 min ago')
- [x] Keep admin commands under 'atcha admin users'
