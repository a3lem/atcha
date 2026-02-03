---
# team-mail-50nc
title: 'inbox read: verify filters and exclude ''to'' field'
status: completed
type: task
priority: normal
created_at: 2026-02-01T20:24:17Z
updated_at: 2026-02-01T20:31:37Z
parent: team-mail-88qz
---

Review and update `team-mail inbox read`:

## Verify these filters are implemented and working:
- `--since` - filter by date
- `--from` - filter by sender  
- `--include-read` - include already-read messages

## New behavior:
- Exclude `to` field from JSON output by default (recipient is the authenticated user, so it's redundant)
- Exception: if authenticated user is admin (impersonating), include the `to` field
