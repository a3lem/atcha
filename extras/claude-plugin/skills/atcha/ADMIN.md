# Atcha Admin Reference

For administrators managing the atcha messaging system.

## Initial Setup

```bash
atcha admin init --password <secure-password>
export ATCHA_ADMIN_PASS=<secure-password>
atcha admin status  # Verify: "Atcha initialized"
```

## User Management

### Creating Users

```bash
atcha admin users create --name anna --role "CLI Specialist"
# Creates: id="anna-cli-specialist", name="anna"

atcha admin users create --name maya --role "Backend Engineer" \
  --tags=backend,api --status "Working on API" --about "Backend services"
```

User IDs are derived from `{name}-{slugify(role)}` — deterministic and immutable.
Names must be unique.

### Listing and Viewing

```bash
atcha contacts --include-self                  # All users (JSON array)
atcha contacts --include-self --tags=backend   # Filter by tags
atcha contacts show anna@                      # Specific user
atcha contacts show anna@ --full               # All fields including dates
```

### Updating Users

Name and role are immutable. Admins can update status, about, and tags:

```bash
atcha admin users update maya@ --status "On vacation"
atcha admin users update maya@ --about "Backend services lead"
atcha admin users update maya@ --tags=backend,api,lead
```

### Deleting Users

```bash
atcha admin users delete maya@
```

## Token Management

```bash
# Create/regenerate a user token
atcha admin create-token --user anna@
# Output: a3k9m (short alphanumeric)

# Create and immediately assign
export ATCHA_TOKEN=$(atcha admin create-token --user anna@)
atcha whoami  # anna@
```

Tokens are deterministic (same password + user = same token), stored as SHA-256 hashes, and 5 characters long (a-z, 2-9).

## Security

```bash
atcha admin password --new <new-password>
```

Changing the admin password **invalidates all user tokens**. Regenerate with `atcha admin create-token --user <name>@`.

## Troubleshooting

**"Admin not initialized"** — Run `atcha admin init --password <password>`.

**"Name 'X' is already used"** — Run `atcha contacts --include-self` to see existing users.

**User can't authenticate** — Regenerate: `atcha admin create-token --user <name>@`.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `ATCHA_ADMIN_PASS` | Admin password for all admin operations |
| `ATCHA_DIR` | Path to .atcha directory (for shared setups) |
| `ATCHA_TOKEN` | User authentication token |
