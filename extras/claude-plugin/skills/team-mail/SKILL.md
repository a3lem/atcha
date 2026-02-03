---
name: team-mail
description: Send and receive messages with other AI agents working in parallel.
allowed-tools: [Bash(team-mail:*)]
---

# Team-Mail

Message other AI agents running in parallel. Each agent has a unique identity determined by `$TEAM_MAIL_TOKEN`.

## Essential Commands

### Check your identity
```bash
team-mail whoami
```
Output: `You are **maya-backend**. Role: Backend Engineer`

### Find teammates
```bash
team-mail agents list              # JSON array of profiles
team-mail agents list --names-only # Just names, one per line
```

### Send a message
```bash
team-mail send <recipient> "<message>"
```
Example: `team-mail send alex-frontend "API is ready for integration"`

### Read your inbox
```bash
team-mail inbox        # Summary: "2 unread messages: 1 from alice, 1 from bob"
team-mail inbox read   # Full messages as JSONL (marks as read)
```

---

## Filters & Profile Updates

### Filter agents by tag
```bash
team-mail agents list --tags=backend,auth
```

### Update your profile
```bash
team-mail profile update --status "Working on auth refactor"
team-mail profile update --tags "backend,api"
team-mail profile update --about "I handle API development"
```

### Filter inbox messages
```bash
team-mail inbox read --from alice                    # Only from alice
team-mail inbox read --since "2026-01-30T12:00:00Z"  # After timestamp
team-mail inbox read --include-read                  # Include already-read
```

### View another agent's profile
```bash
team-mail agents get alex-frontend
team-mail agents get alex-frontend --full  # Include dates
```

---

## Admin Setup & Troubleshooting

### First-time setup (admin only)
```bash
# Initialize
team-mail init --password <password>
export TEAM_MAIL_ADMIN_PASS=<password>

# Create an agent
team-mail agents add --name maya-backend --role "Backend Engineer"

# Generate token for the agent
team-mail create-token --agent maya-backend
```

### Check initialization status
```bash
# Check if team-mail is initialized (useful in hooks)
team-mail init --check
# Exits with 0 if initialized, 1 if not. Prints "Team-mail initialized" on success.
```

### Agent naming convention
Names follow `{firstname}-{role-slug}`:
- `maya-backend-engineer`
- `kai-frontend-specialist`
- `alex-devops-lead`

### Troubleshooting

**"No token provided"**
```
FIX: Set $TEAM_MAIL_TOKEN or use --token <token>
```

**"Agent not found"**
```bash
team-mail agents list --names-only  # See available agents
```

**"Invalid token"**
Ask admin to regenerate: `team-mail create-token --agent <name>`

---

## Output Formats

| Command | Format | Example |
|---------|--------|---------|
| `agents list` | JSON array | `[{"name":"alice","role":"Engineer"}]` |
| `agents get` | JSON object | `{"name":"alice","role":"Engineer"}` |
| `whoami` | Text | `You are **alice**.\nRole: Engineer` |
| `inbox` | Text | `2 unread messages: 1 from bob` |
| `inbox read` | JSONL | `{"from":"bob","ts":"...","body":"..."}` |
| `send` | JSON | `{"status":"delivered","to":"bob"}` |

## Tips

1. **Check inbox regularly** when you start work or finish a task
2. **Update your status** so others know what you're working on
3. **Use tags** to indicate your expertise areas
4. **Be specific** in messages: what changed, why it matters, what's needed
5. **Coordinate early** before starting work that might conflict with others
