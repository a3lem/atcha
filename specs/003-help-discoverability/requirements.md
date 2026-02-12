---
locked: false
status: draft
---

# Requirements: Help Discoverability

## Overview

### Context

The atcha CLI uses argparse's default help formatting. Running `atcha --help` shows top-level commands with one-line descriptions, but subcommands (`admin users create`, `messages read`, etc.) are invisible until you drill down command by command. Users must run `--help` at each level to discover the full surface area.

### Problem

1. **Hidden subcommands**: `atcha --help` shows `admin` but not `admin users create`, `admin spaces add`, etc. Users don't know what's available without trial and error.
2. **Flat descriptions**: Argparse's default format doesn't convey the tree structure — there's no visual hierarchy showing parent/child relationships.
3. **No quick reference**: There's no single command that shows the entire CLI at a glance, making it hard to remember or reference available operations.

### Goal

Replace the default argparse help output with a custom tree-formatted help that shows the full command hierarchy, key flags, and one-line descriptions at every level. `atcha --help` becomes a complete quick-reference card. Per-subcommand `--help` shows the relevant subtree.

## Functional Requirements

### Top-Level Help

#### FR-001: Full Command Tree in `--help`

WHEN user runs `atcha --help` or `atcha -h`, the CLI SHALL print a custom-formatted command tree showing all commands, subcommands, key flags, and one-line descriptions.

**Acceptance Criteria:**

1. The output SHALL show the full recursive command tree, not just top-level commands
2. Each command SHALL show its one-line description
3. Commands with important flags SHALL show those flags inline (e.g. `--to <address>`, `--from`, `--since`)
4. The tree SHALL use indentation and tree-drawing characters (`├──`, `└──`, `│`) to convey hierarchy
5. The output SHALL include a header with the program name and version
6. The output SHALL include a footer with usage hints (e.g. `Run 'atcha <command> --help' for details`)

**Example output:**

```
atcha v0.1.0 — Get in touch with other users on your team

Usage: atcha <command> [options]

Commands:
  contacts [--include-self] [--tags] [--full]     List contacts
  ├── show <address> [--full]                      View a contact's profile
  messages [--from] [--since] [--limit]            List messages (no side effects)
  ├── check                                        Inbox summary (count + senders)
  └── read <msg-id...> [--no-mark]                 Read and mark messages
  send --to <address> "content"                    Send a message
  ├── --broadcast                                  Send to all contacts
  profile                                          View your profile
  └── update [--status] [--about] [--tags]         Update your profile
  whoami [--id | --name]                           Print your identity
  admin                                            Administrative commands
  ├── init [--password]                            Initialize workspace
  ├── status [-q]                                  Check initialization state
  ├── envs                                         Print env exports for hooks
  ├── password --new <pw>                          Change admin password
  ├── create-token --user <address>                Mint a user token
  ├── hints                                        Show admin hints
  ├── users                                        List all users
  │   ├── create --name --role [--status] ...      Create a user
  │   ├── update <address> [--name] [--role] ...   Update a user
  │   └── delete <address>                         Delete a user
  └── spaces                                       List spaces
      ├── update [--name] [--description]          Update local space
      ├── add <dir>                                Register federated space
      └── drop <id>                                Unregister a space

Auth: --token (or $ATCHA_TOKEN) | --password (or $ATCHA_ADMIN_PASS)
Run 'atcha <command> --help' for command-specific help.
```

#### FR-002: Subcommand Help Shows Subtree

WHEN user runs `atcha <command> --help` for a command that has subcommands, the CLI SHALL show a compact subtree for that command's children, plus its own flags.

**Acceptance Criteria:**

1. The subtree SHALL show child commands with descriptions and key flags, one per line
2. The command's own flags SHALL be listed after the subtree
3. The format SHALL be compact — no argparse-style verbose formatting
4. Commands without subcommands (e.g. `atcha send --help`) SHALL show a compact flag list with descriptions, not the default argparse format

**Example (`atcha admin --help`):**

```
atcha admin — Administrative commands

Subcommands:
  init [--password]                            Initialize workspace
  status [-q]                                  Check initialization state
  envs                                         Print env exports for hooks
  password --new <pw>                          Change admin password
  create-token --user <address>                Mint a user token
  hints                                        Show admin hints
  users                                        List all users
  ├── create --name --role [--status] ...      Create a user
  ├── update <address> [--name] [--role] ...   Update a user
  └── delete <address>                         Delete a user
  spaces                                       List spaces
  ├── update [--name] [--description]          Update local space
  ├── add <dir>                                Register federated space
  └── drop <id>                                Unregister a space

Options:
  --token TOKEN        User token (or $ATCHA_TOKEN)
  --password PASSWORD  Admin password (or $ATCHA_ADMIN_PASS)
  --json               Machine-readable output
```

**Example (`atcha send --help`):**

```
atcha send — Send a message to contact(s)

Usage: atcha send --to <address> "content"
       atcha send --broadcast "content"

Options:
  --to ADDRESS         Recipient address (e.g. maya@, maya@engineering)
  --broadcast          Send to all contacts
  --thread THREAD_ID   Continue a thread
  --reply-to MSG_ID    Reply to a specific message
  --token TOKEN        User token (or $ATCHA_TOKEN)
  --password PASSWORD  Admin password (or $ATCHA_ADMIN_PASS)
  --as-user USER_ID    Act as user (admin only)
```

### Implementation Approach

#### FR-003: Custom Help Formatter

The help SHALL be implemented by overriding argparse's help formatting, not by replacing argparse entirely.

**Acceptance Criteria:**

1. The CLI SHALL use a custom `HelpFormatter` subclass or override `print_help()` on parsers
2. The tree structure SHALL be derived from the actual parser hierarchy (not hardcoded strings), so it stays in sync with the real commands
3. Argparse SHALL still handle argument parsing, validation, and error messages — only help output changes

## Non-Functional Requirements

### NFR-001: Stdlib-Only

1. The implementation SHALL use only Python standard library modules (consistent with the rest of the CLI)

### NFR-002: Automatic Sync

1. The tree output SHALL be generated from the parser structure, so adding a new subcommand automatically appears in `--help`
2. No manual tree maintenance — the tree is always accurate

### NFR-003: Terminal Width

1. The output SHOULD respect terminal width when available (via `shutil.get_terminal_size()`)
2. Descriptions MAY be truncated to fit within the terminal width
3. The tree structure itself (command + flags) SHALL NOT be truncated

## Constraints

- Must not break existing `--help` on leaf commands that users may depend on in scripts (though format will change)
- Must coexist with argparse error messages (e.g. `atcha send` without `--to` should still show the argparse error, not the tree)

## Out of Scope

- Shell completions (bash/zsh/fish)
- Man page generation
- `--help` in non-English languages
- Color/ANSI formatting (plain text only for now)

## Verification

- `atcha --help` shows the full command tree with all commands, subcommands, flags, and descriptions
- `atcha admin --help` shows the admin subtree
- `atcha admin users --help` shows the users subtree
- `atcha send --help` shows send's flags compactly
- Adding a new subcommand to the parser automatically appears in the tree
- Output fits within 80-column terminals without wrapping on the tree structure
