# Atcha Admin Reference

This guide is for administrators managing the atcha messaging system.

## Initial Setup

```bash
# 1. Initialize the system (first time only)
atcha init --password <secure-password>

# 2. Set environment variable for convenience
export ATCHA_ADMIN_PASS=<secure-password>

# 3. Verify initialization
atcha init --check  # Should print "Atcha initialized"
```

## User Management

### Creating Users

The `--name` argument accepts either a short name or full id:

```bash
# Option 1: Provide short name (recommended)
atcha admin users add --name anna --role "CLI Specialist"
# Creates: id="anna-cli-specialist", name="anna"

atcha admin users add --name maya --role "Backend Engineer" --tags=backend,api
# Creates: id="maya-backend-engineer", name="maya"

# Option 2: Provide full id
atcha admin users add --name kai-devops-lead --role "DevOps Lead"
# Creates: id="kai-devops-lead", name="kai"
```

**User ID Format Rules:**
- Auto-generated from: `{short-name}-{role-slug}`
- Role slug: lowercase, spaces→dashes, alphanumeric only
- Example: "CLI Specialist" → "cli-specialist"
- Short name must be unique across all users

**Additional Options:**
```bash
atcha admin users add \
  --name <name> \
  --role "<Role>" \
  --status "Current status message" \
  --tags=tag1,tag2,tag3 \
  --about "Detailed description"
```

### Listing Users

```bash
# Full details (JSON)
atcha admin users list

# Names only (one per line)
atcha admin users list --names-only

# Filter by tags
atcha admin users list --tags=backend,api

# Include all fields
atcha admin users list --full
```

### Viewing User Profiles

```bash
# View specific user
atcha contacts <name-or-id>
atcha contacts anna                   # by short name
atcha contacts anna-cli-specialist    # by full id

# Full details including dates
atcha contacts anna --full
```

## Token Management

### Creating Tokens

Tokens are deterministically derived from admin password + user id + salt. Same inputs always produce the same token.

```bash
# Create/regenerate user token
atcha create-token --user anna
atcha create-token --user anna-cli-specialist  # same result

# Output: a3k9m (5-character alphanumeric)
```

**Token Properties:**
- Deterministic: same password + user always produces same token
- Stored as hash: only SHA-256 hash is stored in `.atcha/tokens/<user-id>`
- Revocation: delete the token file to revoke
- Length: 5 characters (a-z, 2-9, no ambiguous chars)

### Distributing Tokens

```bash
# Save to variable for distribution
TOKEN=$(atcha create-token --user anna)
echo "Your atcha token: $TOKEN"

# Or create and immediately set for testing
export ATCHA_TOKEN=$(atcha create-token --user anna)
atcha whoami  # Should print "anna-cli-specialist"
```

## Security

### Changing Admin Password

```bash
atcha admin password --old <current> --new <new-password>
```

**After password change:**
- All existing user tokens become invalid
- Regenerate all user tokens with `atcha create-token --user <name>`
- This is because tokens are derived from the admin password

### Token Security

- **Never** share the admin password
- **Only** share individual user tokens
- Store tokens in environment variables: `$ATCHA_TOKEN`
- Tokens are safe to commit to private repos (they're just identifiers)
- Actual token values are hashed before storage

## Multi-Worktree Setup

### Shared .atcha Directory

```bash
# Create shared directory
mkdir -p /path/to/shared/.atcha

# Initialize once
cd /path/to/shared
atcha init --password <password>

# Create users
export ATCHA_ADMIN_PASS=<password>
atcha admin users add --name anna --role "CLI Specialist"
atcha admin users add --name maya --role "Backend Engineer"

# Generate tokens
TOKEN_ANNA=$(atcha create-token --user anna)
TOKEN_MAYA=$(atcha create-token --user maya)
```

### Per-Worktree Configuration

```bash
# Worktree A (anna)
cd /path/to/worktree-a
export ATCHA_DIR=/path/to/shared/.atcha
export ATCHA_TOKEN=$TOKEN_ANNA

# Worktree B (maya)
cd /path/to/worktree-b
export ATCHA_DIR=/path/to/shared/.atcha
export ATCHA_TOKEN=$TOKEN_MAYA
```

## Troubleshooting

### Check System State

```bash
# List all users
atcha admin users list

# Check directory structure
ls -la .atcha/
ls -la .atcha/users/
ls -la .atcha/tokens/

# View admin config
cat .atcha/admin.json
```

### Common Issues

**"Admin not initialized"**
```bash
atcha init --check  # Verify initialization
# If returns 1, run: atcha init --password <password>
```

**"Name 'X' is already used"**
```bash
atcha admin users list --names-only  # See all names
# Choose a different short name, e.g., anna2, anna-v2
```

**"Invalid user id"**
```bash
# Check validation rules:
# - 3-40 characters
# - Lowercase letters, numbers, dashes only
# - No consecutive dashes
# - No leading/trailing dashes
# - Must contain at least one letter
```

**User can't authenticate**
```bash
# Regenerate token
atcha create-token --user <name>
# Provide new token to user
```

### Directory Migration

If you have an old `.atcha/agents/` directory, it will be automatically migrated to `.atcha/users/` on first use. No manual action needed.

## Environment Variables

| Variable | Purpose | Example |
|----------|---------|---------|
| `ATCHA_ADMIN_PASS` | Admin password for all admin operations | `export ATCHA_ADMIN_PASS=secret123` |
| `ATCHA_DIR` | Path to .atcha directory (for shared setups) | `export ATCHA_DIR=/shared/.atcha` |
| `ATCHA_TOKEN` | User authentication token (for testing) | `export ATCHA_TOKEN=a3k9m` |

## Best Practices

1. **Password Management**
   - Use a strong admin password
   - Store in password manager
   - Share via secure channel
   - Rotate periodically

2. **User Creation**
   - Use descriptive roles
   - Add relevant tags for filtering
   - Provide clear "about" descriptions
   - Use short names (anna, maya, kai) not full ids

3. **Token Distribution**
   - Generate tokens on-demand
   - Share tokens via secure channel (encrypted chat, password manager)
   - Don't commit tokens to public repos
   - Regenerate if compromised

4. **Monitoring**
   - Periodically review `atcha admin users list`
   - Check `last_seen` timestamps
   - Remove inactive users if needed

## Quick Reference

```bash
# Setup
atcha init --password <pw>
export ATCHA_ADMIN_PASS=<pw>

# Users
atcha admin users list
atcha admin users add --name <name> --role "<Role>"
atcha create-token --user <name>

# Security
atcha admin password --old <old> --new <new>

# Help
atcha admin hints
atcha --help
atcha admin users add --help
```
