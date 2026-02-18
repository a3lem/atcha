"""CLI argument parser construction."""

from __future__ import annotations

import argparse
import typing as T

from atcha.cli.help import install_tree_help
from atcha.cli._types import VERSION


class Parsers(T.NamedTuple):
    """Container for parsers needed in dispatch."""

    main: argparse.ArgumentParser
    admin: argparse.ArgumentParser


def _build_parser() -> Parsers:
    """Build the argument parser.

    Convention: every plural noun lists when invoked bare, verb subcommands for other actions.
    """
    # Base auth: --password, --token, --json (shared by all commands)
    base_auth = argparse.ArgumentParser(add_help=False)
    _ = base_auth.add_argument("--token", help="User token (or set $ATCHA_TOKEN)")
    _ = base_auth.add_argument("--password", help="Admin password (or set ATCHA_ADMIN_PASS)")
    _ = base_auth.add_argument("--json", action="store_true", dest="json_output", help="Output in JSON format")

    # User auth: adds --as-user (only meaningful on user commands like messages, send, profile)
    user_auth = argparse.ArgumentParser(add_help=False, parents=[base_auth])
    _ = user_auth.add_argument("--as-user", dest="as_user", help="Act as USER (requires admin auth). USER is a user ID, e.g. maya-backend-engineer")

    parser = argparse.ArgumentParser(
        prog="atcha",
        description="Atcha -- Agent Team Chat. Talk to other AI agents on your team\n\nConvention: bare plural = list, subcommand = verb",
        epilog="Run 'atcha <command> --help' for command-specific help.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _ = parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    sub = parser.add_subparsers(dest="command", required=False, metavar="<command>")

    # ---------- contacts (bare = list) ----------
    contacts_parser = sub.add_parser(
        "contacts",
        help="List everyone on your team",
        description="List all contacts. Excludes yourself by default. Includes users from federated spaces.",
        epilog="Examples:\n  atcha contacts\n  atcha contacts show maya@\n  atcha contacts --space frontend\n  atcha contacts --include-self",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[user_auth],
    )
    _ = contacts_parser.add_argument("--space", help="Filter by space handle or ID")
    _ = contacts_parser.add_argument("--include-self", action="store_true", help="Include yourself in list")
    _ = contacts_parser.add_argument("--tags", help="Filter by tags (comma-separated)")
    _ = contacts_parser.add_argument("--full", action="store_true", help="Include all fields (dates, empty values)")
    contacts_sub = contacts_parser.add_subparsers(dest="contacts_command", required=False, metavar="<subcommand>")

    # contacts show <address>
    contacts_show = contacts_sub.add_parser(
        "show",
        help="View a specific contact's profile",
        parents=[user_auth],
    )
    _ = contacts_show.add_argument("name", help="Contact address (e.g. maya@, maya@space) or user ID")
    _ = contacts_show.add_argument("--full", action="store_true", help="Include all fields (dates, empty values)")

    # ---------- messages (bare = list) ----------
    messages_parser = sub.add_parser(
        "messages",
        help="List messages in your inbox",
        description="List messages with previews. Does NOT mark as read.",
        epilog="Examples:\n  atcha messages\n  atcha messages check\n  atcha messages read msg-abc123",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[user_auth],
    )
    _ = messages_parser.add_argument("--from", dest="from_user", help="Filter by sender address")
    _ = messages_parser.add_argument("--since", help="Only messages after this ISO timestamp")
    _ = messages_parser.add_argument("--thread", help="Filter by thread_id")
    _ = messages_parser.add_argument("--limit", type=int, help="Max messages to return")
    _ = messages_parser.add_argument("--include-read", action="store_true", help="Include read messages")
    _ = messages_parser.add_argument("--no-preview", action="store_true", help="Show full content instead of preview")

    _ = messages_parser.add_argument("--id", action="append", dest="ids", help="Filter by message ID (repeatable)")

    messages_sub = messages_parser.add_subparsers(dest="messages_command", metavar="<subcommand>")

    # messages check
    messages_check = messages_sub.add_parser(
        "check",
        help="Quick inbox summary (count + senders)",
        description="Show summary of unread messages without marking as read.",
    )
    _ = messages_check.add_argument(
        "--hook",
        action="store_true",
        help="Hook mode: suppress output when no unread messages (saves context tokens)",
    )

    # messages read [msg-id...] [--all]
    messages_read = messages_sub.add_parser(
        "read",
        help="Read and mark messages as read",
        description="Read specified messages and mark them as read.",
        epilog="Examples:\n  atcha messages read msg-abc123\n  atcha messages read msg-abc123 msg-def456\n  atcha messages read --all",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _ = messages_read.add_argument("ids", nargs="*", metavar="id", help="Message ID to read (one or more)")
    _ = messages_read.add_argument("--all", action="store_true", dest="read_all", help="Read all unread messages")
    _ = messages_read.add_argument("--no-mark", action="store_true", help="Don't mark messages as read")
    _ = messages_read.add_argument("-q", "--quiet", action="store_true", help="Mark as read without printing output")

    # ---------- send ----------
    send_parser = sub.add_parser(
        "send",
        help="Send message to contact(s)",
        description="Send a message to one or more users. Requires user token.",
        epilog='Examples:\n  atcha send --to maya@ "API is ready"\n  atcha send --to maya@ --to alex@ "Changes deployed"\n  atcha send --broadcast "Standup at 10am"',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[user_auth],
    )
    _ = send_parser.add_argument("--to", action="append", dest="recipients", metavar="ADDRESS", help="Recipient address (can be repeated)")
    _ = send_parser.add_argument("--broadcast", action="store_true", help="Send to all contacts (broadcast)")
    _ = send_parser.add_argument("--reply-to", metavar="MSG_ID", help="Reply to all participants of this message's thread (exclusive with --to)")
    _ = send_parser.add_argument("content", help="Message content")

    # ---------- profile (bare = show self) ----------
    profile_parser = sub.add_parser(
        "profile",
        help="View your public profile (visible to all team members)",
        description="View your own profile, or update profile fields. Requires user token.",
        epilog="Examples:\n  atcha profile\n  atcha profile update --status 'Working on auth'",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[user_auth],
    )
    _ = profile_parser.add_argument("--full", action="store_true", help="Include all fields (dates, empty values)")
    profile_sub = profile_parser.add_subparsers(dest="profile_command", metavar="<subcommand>")

    # profile update (no --role or --name — those are immutable)
    profile_update = profile_sub.add_parser(
        "update",
        help="Update your profile (--status, --tags, --about)",
        description="Update your profile fields (status, about, tags). Name and role are immutable.",
        parents=[user_auth],
    )
    _ = profile_update.add_argument("--status", help="Set status")
    _ = profile_update.add_argument("--tags", help="Set tags (comma-separated)")
    _ = profile_update.add_argument("--about", help="Set about description")
    _ = profile_update.add_argument("--full", action="store_true", help="Include all fields in output")

    # ---------- whoami ----------
    whoami_parser = sub.add_parser(
        "whoami",
        help="Print your identity (default: address)",
        description="Print your identity. Default: address format (name@). --id: user ID. --name: bare name.",
        parents=[user_auth],
    )
    whoami_group = whoami_parser.add_mutually_exclusive_group()
    _ = whoami_group.add_argument("--id", action="store_true", dest="show_id", help="Print user ID")
    _ = whoami_group.add_argument("--name", action="store_true", dest="show_name", help="Print bare name")

    # ---------- admin ----------
    admin_parser = sub.add_parser(
        "admin",
        help="Administrative commands (run 'atcha admin --help')",
        description="Administrative commands for managing the atcha system.",
        parents=[base_auth],
    )
    admin_sub = admin_parser.add_subparsers(dest="admin_command", required=False, metavar="<subcommand>")

    # admin init
    admin_init_parser = admin_sub.add_parser(
        "init",
        help="Initialize workspace (first-time setup)",
        description="Initialize .atcha/ directory and set admin password.",
    )
    _ = admin_init_parser.add_argument("--password", help="Admin password (prompts if not provided)")
    _ = admin_init_parser.add_argument("--json", action="store_true", dest="json_output", help="Output in JSON format")

    # admin status
    admin_status_parser = admin_sub.add_parser(
        "status",
        help="Check if atcha is initialized",
        description="Check if atcha is initialized. Exits 0 if yes, 1 if no.",
        parents=[base_auth],
    )
    _ = admin_status_parser.add_argument("-q", "--quiet", action="store_true", help="Suppress output (exit code only)")

    # admin envs
    _ = admin_sub.add_parser(
        "envs",
        help="Print env exports for hooks",
        description="Auto-discover .atcha directory and print shell export statements.",
        parents=[base_auth],
    )

    # admin password
    admin_password = admin_sub.add_parser(
        "password",
        help="Change admin password",
        description="Change the admin password.",
        parents=[base_auth],
    )
    _ = admin_password.add_argument("--new", required=True, help="New password")

    # admin create-token
    admin_create_token = admin_sub.add_parser(
        "create-token",
        help="Mint a token for a user",
        description="Generate authentication token for a user.",
        parents=[base_auth],
    )
    _ = admin_create_token.add_argument("--user", required=True, help="User address (e.g. maya@) or name")

    # admin users (bare = list)
    admin_users = admin_sub.add_parser(
        "users",
        help="List users",
        description="List all users, or create/update/delete users.",
        parents=[base_auth],
    )
    admin_users_sub = admin_users.add_subparsers(dest="users_command", required=False, metavar="<subcommand>")

    # admin users create
    admin_users_create = admin_users_sub.add_parser(
        "create",
        help="Create a new user",
        description="Create a new user account.",
        parents=[base_auth],
    )
    _ = admin_users_create.add_argument("--name", required=True, help="User name (e.g. 'maya')")
    _ = admin_users_create.add_argument("--role", required=True, help="User role (e.g. 'Backend Engineer')")
    _ = admin_users_create.add_argument("--status", help="Initial status")
    _ = admin_users_create.add_argument("--tags", help="Comma-separated tags")
    _ = admin_users_create.add_argument("--about", help="About description")

    # admin users update <address> — no --name/--role (immutable)
    admin_users_update = admin_users_sub.add_parser(
        "update",
        help="Update a user (status, about, tags)",
        description="Update a user's mutable profile fields. Name and role are immutable.",
        parents=[base_auth],
    )
    _ = admin_users_update.add_argument("address", help="User address (e.g. maya@)")
    _ = admin_users_update.add_argument("--status", help="New status")
    _ = admin_users_update.add_argument("--about", help="New about")
    _ = admin_users_update.add_argument("--tags", help="New tags (comma-separated)")

    # admin users delete <address>
    admin_users_delete = admin_users_sub.add_parser(
        "delete",
        help="Delete a user",
        description="Remove a user's directory and token file.",
        parents=[base_auth],
    )
    _ = admin_users_delete.add_argument("address", help="User address (e.g. maya@)")

    # admin hints
    _ = admin_sub.add_parser(
        "hints",
        help="Show helpful admin hints and reminders",
        parents=[base_auth],
    )

    # admin prime
    _ = admin_sub.add_parser(
        "prime",
        help="Print session-start primer (identity + essential commands)",
        description="Print a concise primer for AI agent sessions: identity and essential commands. Exits silently if no auth is available.",
        parents=[base_auth],
    )

    # admin onboard
    _ = admin_sub.add_parser(
        "onboard",
        help="Print CLAUDE.md snippet for this project",
        description="Print markdown snippet to add to AGENTS.md/CLAUDE.md, telling agents this project uses atcha.",
        parents=[base_auth],
    )

    # admin spaces (bare = list)
    admin_spaces = admin_sub.add_parser(
        "spaces",
        help="List spaces",
        description="List local + federated spaces, or update/add/drop.",
        parents=[base_auth],
    )
    admin_spaces_sub = admin_spaces.add_subparsers(dest="spaces_command", required=False, metavar="<subcommand>")

    # admin spaces update
    admin_spaces_update_parser = admin_spaces_sub.add_parser(
        "update",
        help="Update local space name/description",
        parents=[base_auth],
    )
    _ = admin_spaces_update_parser.add_argument("--name", dest="new_space_name", help="New name for the space")
    _ = admin_spaces_update_parser.add_argument("--description", help="Set space description")

    # admin spaces add
    admin_spaces_add = admin_spaces_sub.add_parser(
        "add",
        help="Register a federated space",
        parents=[base_auth],
    )
    _ = admin_spaces_add.add_argument("path", help="Path to remote .atcha/ directory (or its parent)")
    _ = admin_spaces_add.add_argument("--force", action="store_true", help="Proceed despite handle collision")

    # admin spaces drop
    admin_spaces_drop = admin_spaces_sub.add_parser(
        "drop",
        help="Unregister a federated space",
        parents=[base_auth],
    )
    _ = admin_spaces_drop.add_argument("identifier", help="Space handle or ID to remove")

    install_tree_help(
        parser,
        prog="atcha",
        description="Agent Team Chat. Message other AI agents on your team.\nCoordinate work, ask for help, avoid conflicts.",
        version=VERSION,
    )

    return Parsers(main=parser, admin=admin_parser)
