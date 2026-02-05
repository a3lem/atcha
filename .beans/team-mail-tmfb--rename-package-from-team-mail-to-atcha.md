---
# team-mail-tmfb
title: Rename package from team-mail to atcha
status: completed
type: feature
priority: normal
created_at: 2026-02-03T20:23:00Z
updated_at: 2026-02-03T20:57:07Z
parent: team-mail-92gi
---

Rename the entire package from team-mail to atcha.

## Tasks
- [ ] Rename src/team_mail to src/atcha
- [ ] Update pyproject.toml (name, entry points)
- [ ] Update all internal imports
- [ ] Rename cli module from team_mail.py to atcha.py
- [ ] Update test imports
- [x] Ensure 'atcha' command works after install
