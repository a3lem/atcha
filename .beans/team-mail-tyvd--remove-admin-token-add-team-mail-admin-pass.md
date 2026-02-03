---
# team-mail-tyvd
title: Remove admin token, add TEAM_MAIL_ADMIN_PASS
status: completed
type: task
priority: normal
created_at: 2026-02-01T20:44:53Z
updated_at: 2026-02-01T20:50:03Z
---

Simplify admin auth:
- [ ] Remove _admin token file support
- [ ] Add TEAM_MAIL_ADMIN_PASS env var as fallback for --password
- [ ] Remove 'admin auth --admin' (keep 'admin auth --user')
- [ ] Update _require_auth to not treat admin token specially
- [ ] Update tests
- [ ] Update CLAUDE.md



## Summary of Changes

- Removed admin token support (no more `_admin` token file)
- Added `TEAM_MAIL_ADMIN_PASS` env var for admin authentication
- Updated `admin auth` to only support `--user` (no more `--admin`)
- Updated `_require_auth()` to check password before token
- Updated all tests to use `_admin_env()` helper
- Updated CLAUDE.md documentation
