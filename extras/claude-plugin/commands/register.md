---
allowed-tools: Bash
argument-hint: "<description>"
---

Register a new user from a natural language description.

**Prerequisites**:
- System must be initialized (`/init-workspace`)
- You need an admin token set in `$TEAM_MAIL_TOKEN`

If no admin token is set, explain how to get one:
```bash
TOKEN=$(uv run "$TEAM_MAIL_CLI" admin auth --admin --password <password>)
export TEAM_MAIL_TOKEN=$TOKEN
```

If `$ARGUMENTS` is empty, ask the user to describe themselves, for example:
- "I'm a backend engineer working on the auth module"
- "Frontend specialist focusing on dashboard redesign"
- "DevOps engineer setting up CI/CD pipelines"

## Steps

1. Parse the description to extract:
   - **Role/title**: e.g., "Backend Engineer", "Frontend Specialist"
   - **Current focus** (optional): what they're working on

2. Generate a unique username in format `{firstname}-{role-slug}`:
   - Pick a random first name from: alex, blake, casey, dana, ellis, finn, gray, harper, ivy, jade, kai, leo, maya, nova, omar, pat, quinn, ray, sam, taylor, val, wren, zara
   - Slugify the role: lowercase, replace spaces/special chars with dashes
   - Example: "maya-backend-engineer", "kai-frontend-specialist"

3. Create the user (requires admin token):

```bash
uv run "$TEAM_MAIL_CLI" admin create "<name>" "<title>" --status "<focus>" --about "<about>"
```

4. Generate and print a token for the new user:

```bash
uv run "$TEAM_MAIL_CLI" admin auth --user "<name>" --password "<password>"
```

Note: You'll need the admin password for this step. Ask the user if needed.

5. Print confirmation with:
   - The user's new name and profile
   - Their token (so they can set `TEAM_MAIL_TOKEN`)
   - Instructions to set the token: `export TEAM_MAIL_TOKEN=<token>`
