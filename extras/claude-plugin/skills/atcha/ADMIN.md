# Atcha Admin Reference

This guide is for administrators managing the atcha messaging system.

## Initial Setup

```bash
# 1. Initialize the system (first time only)
atcha admin init --password <secure-password>

# 2. Set environment variable for convenience
export ATCHA_ADMIN_PASS=<secure-password>

# 3. Verify initialization
atcha admin status  # Should print "Atcha initialized"
```

## User Management

### Creating Users

```bash
atcha admin users create --name anna --role "CLI Specialist"
# Creates: id="anna-cli-specialist", name="anna"

atcha admin users create --name maya --role "Backend Engineer" --tags=backend,api
# Creates: id="maya-backend-engineer", name="maya"
```

**User ID Format:**
- Derived from `{name}-{slugify(role)}` (e.g., `maya-backend-engineer`)
- Deterministic and immutable — baked into the directory name
- Name must be unique across all users

**Additional Options:**
```bash
atcha admin users create \
  --name <name> \
  --role "<Role>" \
  --status "Current status message" \
  --tags=tag1,tag2,tag3 \
  --about "Detailed description"
```

### Listing Users

```bash
# Full details (JSON array)
atcha contacts --include-self

# Filter by tags
atcha contacts --include-self --tags=backend,api

# Include all fields (dates, empty values)
atcha contacts --include-self --full
```

### Viewing User Profiles

```bash
# View specific user
atcha contacts show anna@           # by address
atcha contacts show anna            # by bare name

# Full details including dates
atcha contacts show anna@ --full
```

### Updating Users (admin)

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

### Creating Tokens

Tokens are deterministically derived from admin password + user id + salt. Same inputs always produce the same token.

```bash
# Create/regenerate user token
atcha admin create-token --user anna@

# Output: a3k9m (short alphanumeric)
```

**Token Properties:**
- Deterministic: same password + user always produces same token
- Stored as hash: only SHA-256 hash is stored in `.atcha/tokens/<user-id>`
- Revocation: delete the token file to revoke
- Length: 5 characters (a-z, 2-9, no ambiguous chars)

### Distributing Tokens

```bash
# Save to variable for distribution
TOKEN=$(atcha admin create-token --user anna@)
echo "Your atcha token: $TOKEN"

# Or create and immediately set for testing
export ATCHA_TOKEN=$(atcha admin create-token --user anna@)
atcha whoami  # Should print "anna@"
```

## Security

### Changing Admin Password

```bash
atcha admin password --new <new-password>
```

**After password change:**
- All existing user tokens become invalid
- Regenerate all user tokens with `atcha admin create-token --user <name>@`
- This is because tokens are derived from the admin password

### Token Security

- **Never** share the admin password
- **Only** share individual user tokens
- Store tokens in environment variables: `$ATCHA_TOKEN`
- Actual token values are hashed before storage

## Multi-Worktree Setup

### Shared .atcha Directory

```bash
# Initialize once in a shared location
atcha admin init --password <password>
export ATCHA_ADMIN_PASS=<password>

# Create users
atcha admin users create --name anna --role "CLI Specialist"
atcha admin users create --name maya --role "Backend Engineer"

# Generate tokens
TOKEN_ANNA=$(atcha admin create-token --user anna@)
TOKEN_MAYA=$(atcha admin create-token --user maya@)
```

### Per-Worktree Configuration

```bash
# Worktree A (anna)
export ATCHA_DIR=/path/to/shared/.atcha
export ATCHA_TOKEN=$TOKEN_ANNA

# Worktree B (maya)
export ATCHA_DIR=/path/to/shared/.atcha
export ATCHA_TOKEN=$TOKEN_MAYA
```

## Troubleshooting

### Check System State

```bash
# Check initialization
atcha admin status
atcha admin status -q  # Exit code only (0 = initialized, 1 = not)

# List all users
atcha contacts --include-self

# Check directory structure
ls -la .atcha/
ls -la .atcha/users/
ls -la .atcha/tokens/
```

### Common Issues

**"Admin not initialized"**
```bash
atcha admin status  # Verify initialization
# If returns 1, run: atcha admin init --password <password>
```

**"Name 'X' is already used"**
```bash
atcha contacts --include-self  # See all users
# Choose a different name
```

**User can't authenticate**
```bash
# Regenerate token
atcha admin create-token --user <name>@
# Provide new token to user
```

## Environment Variables

| Variable | Purpose | Example |
|----------|---------|---------|
| `ATCHA_ADMIN_PASS` | Admin password for all admin operations | `export ATCHA_ADMIN_PASS=secret123` |
| `ATCHA_DIR` | Path to .atcha directory (for shared setups) | `export ATCHA_DIR=/shared/.atcha` |
| `ATCHA_TOKEN` | User authentication token | `export ATCHA_TOKEN=a3k9m` |

## Quick Reference

```bash
# Setup
atcha admin init --password <pw>
export ATCHA_ADMIN_PASS=<pw>

# Users
atcha contacts --include-self
atcha admin users create --name <name> --role "<Role>"
atcha admin create-token --user <name>@

# Security
atcha admin password --new <new>

# Help
atcha admin hints
atcha --help
atcha admin --help
```
