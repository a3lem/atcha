# Sync CLI Help Prompt

Update the LLM-friendly CLI reference at `cli/cli-llm-help.txt`.

## Instructions

1. Read the current CLI code at `cli/team_mail.py` to understand all commands
2. Generate a concise, LLM-optimized reference that covers:
   - All user-facing commands (skip admin commands except `users add`)
   - Common options for each command
   - Brief inline comments explaining what each does
3. Write the result to `cli/cli-llm-help.txt`

## Format Guidelines

- Use a code block with aligned columns
- One command per line with inline `# comment`
- Group related commands together
- Keep it under 20 lines
- Focus on what agents need day-to-day

## Example Format

```
team-mail users list [--names-only] [--tags=TAG]   # List users
team-mail users get <name>                         # View user's profile
```

## Output

Write the updated content to: `cli/cli-llm-help.txt`
