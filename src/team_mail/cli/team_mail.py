#!/usr/bin/env python
"""team-mail: Token-authenticated messaging between parallel Claude Code sessions.

This CLI provides a hierarchical command structure with token-based authentication.

Commands:
  admin init                    First-time password setup
  admin password                Change admin password
  admin auth --user <name>      Mint user token
  admin auth --admin            Mint admin token
  admin create <name> <title>   Create user account

  team                          List all users
  profile                       View own profile (requires token)
  profile <name>                View someone's profile (public)
  profile update [options]      Update own profile (requires token)

  inbox                         Check inbox summary
  inbox read                    Read full messages, mark as read
  send <to> <body>              Send message
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import sys
import typing as T
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = "0.1.0"
TEAM_MAIL_DIR_NAME: T.Final[str] = ".team-mail"
TOKEN_LENGTH: T.Final[int] = 5  # 5-char random token


# ---------------------------------------------------------------------------
# Type definitions
# ---------------------------------------------------------------------------


class AdminConfig(T.TypedDict):
    """Admin configuration stored in admin.json."""

    password_hash: str
    salt: str


class AgentProfile(T.TypedDict):
    """Agent profile stored in profile.json."""

    name: str
    role: str
    status: str
    about: str
    tags: list[str]
    joined: str
    updated: str


class MailState(T.TypedDict, total=False):
    """Mail state stored in state.json."""

    last_read: str


Message = T.TypedDict(
    "Message",
    {
        "from": str,
        "to": str,
        "ts": str,
        "type": str,
        "body": str,
    },
)


# ---------------------------------------------------------------------------
# Error helpers
# ---------------------------------------------------------------------------


def _error(msg: str, fix: str | None = None, available: list[str] | None = None) -> T.NoReturn:
    """Print structured error and exit."""
    print(f"ERROR: {msg}", file=sys.stderr)
    if available:
        print(f"AVAILABLE: {', '.join(available)}", file=sys.stderr)
    if fix:
        print(f"FIX: {fix}", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Directory structure helpers (Task 1.1)
# ---------------------------------------------------------------------------


def _get_team_mail_dir() -> Path | None:
    """Get .team-mail directory from env var or find by walking up."""
    # First check env var
    env_dir = os.environ.get("TEAM_MAIL_DIR")
    if env_dir:
        p = Path(env_dir)
        if p.is_dir():
            return p
        return None

    # Walk up looking for .team-mail/
    d = Path.cwd().resolve()
    while True:
        candidate = d / TEAM_MAIL_DIR_NAME
        if candidate.is_dir():
            return candidate
        parent = d.parent
        if parent == d:
            return None
        d = parent


def _require_team_mail_dir() -> Path:
    """Get .team-mail directory or exit with error."""
    team_mail_dir = _get_team_mail_dir()
    if team_mail_dir is None:
        _error(
            ".team-mail directory not found",
            fix="Run 'team-mail admin init' to initialize",
        )
    assert team_mail_dir is not None
    return team_mail_dir


def _ensure_team_mail_dir() -> Path:
    """Create .team-mail directory structure. Returns the directory path."""
    team_mail_dir = Path.cwd() / TEAM_MAIL_DIR_NAME
    team_mail_dir.mkdir(exist_ok=True)
    (team_mail_dir / "tokens").mkdir(exist_ok=True)
    (team_mail_dir / "users").mkdir(exist_ok=True)
    return team_mail_dir


def _get_users_dir(team_mail_dir: Path) -> Path:
    """Get the users directory."""
    return team_mail_dir / "users"


def _get_user_dir(team_mail_dir: Path, username: str) -> Path:
    """Get a specific user's directory."""
    return _get_users_dir(team_mail_dir) / username


def _ensure_user_dir(team_mail_dir: Path, username: str) -> Path:
    """Create user directory structure."""
    user_dir = _get_user_dir(team_mail_dir, username)
    user_dir.mkdir(parents=True, exist_ok=True)
    mail_dir = user_dir / "mail"
    mail_dir.mkdir(exist_ok=True)
    for name in ("inbox.jsonl", "sent.jsonl"):
        f = mail_dir / name
        if not f.exists():
            f.touch()
    state = mail_dir / "state.json"
    if not state.exists():
        _ = state.write_text("{}\n")
    return user_dir


# ---------------------------------------------------------------------------
# Password hashing utilities (Task 1.2)
# ---------------------------------------------------------------------------


def _generate_salt() -> str:
    """Generate a random salt for password hashing."""
    return secrets.token_hex(16)


def _hash_password(password: str, salt: str) -> str:
    """Hash a password with the given salt using SHA-256."""
    combined = f"{salt}:{password}"
    return hashlib.sha256(combined.encode()).hexdigest()


def _verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Verify a password against a stored hash."""
    return _hash_password(password, salt) == stored_hash


# ---------------------------------------------------------------------------
# Token management utilities (Task 1.3)
# ---------------------------------------------------------------------------


def _generate_token() -> str:
    """Generate a random 5-character token."""
    # Use alphanumeric characters (no ambiguous chars like 0/O, 1/l)
    alphabet = "23456789abcdefghjkmnpqrstuvwxyz"
    return "".join(secrets.choice(alphabet) for _ in range(TOKEN_LENGTH))


def _get_token_file(team_mail_dir: Path, name: str) -> Path:
    """Get path to token file for a user or admin."""
    return team_mail_dir / "tokens" / name


def _store_token(team_mail_dir: Path, name: str, token: str) -> None:
    """Store a token for a user or admin."""
    token_file = _get_token_file(team_mail_dir, name)
    _ = token_file.write_text(token + "\n")


def _read_token(team_mail_dir: Path, name: str) -> str | None:
    """Read a stored token for a user or admin."""
    token_file = _get_token_file(team_mail_dir, name)
    if not token_file.exists():
        return None
    return token_file.read_text().strip()


def _validate_token(team_mail_dir: Path, token: str) -> tuple[str, bool] | None:
    """Validate a token and return (username, is_admin) or None if invalid.

    Checks token against all stored tokens.
    Returns ("_admin", True) for admin token, (username, False) for user token.
    """
    tokens_dir = team_mail_dir / "tokens"
    if not tokens_dir.is_dir():
        return None

    for token_file in tokens_dir.iterdir():
        if not token_file.is_file():
            continue
        stored_token = token_file.read_text().strip()
        if stored_token == token:
            name = token_file.name
            is_admin = name == "_admin"
            return (name, is_admin)

    return None


def _get_token_user(team_mail_dir: Path, token: str) -> str | None:
    """Get username for a token, or None if invalid."""
    result = _validate_token(team_mail_dir, token)
    if result is None:
        return None
    name, _ = result
    return name


# ---------------------------------------------------------------------------
# Auth context helpers (Task 1.4)
# ---------------------------------------------------------------------------


def _get_token_from_env() -> str | None:
    """Get token from $TEAM_MAIL_TOKEN environment variable."""
    return os.environ.get("TEAM_MAIL_TOKEN")


# Global to hold --token from CLI (set during arg parsing)
_cli_token: str | None = None


def _get_token() -> str | None:
    """Get token from CLI option (--token) or env var ($TEAM_MAIL_TOKEN)."""
    if _cli_token:
        return _cli_token
    return _get_token_from_env()


# Global to hold --password from CLI (set during arg parsing)
_cli_password: str | None = None

# Global to hold --user from CLI (for admin impersonation)
_cli_user: str | None = None


def _require_auth() -> tuple[Path, str, bool]:
    """Validate auth from CLI or env, return (team_mail_dir, user, is_admin). Exits on error.

    Priority: --password > --token > TEAM_MAIL_TOKEN
    """
    team_mail_dir = _require_team_mail_dir()

    # Priority: --password > --token > TEAM_MAIL_TOKEN
    if _cli_password:
        _require_admin(team_mail_dir, _cli_password)
        return team_mail_dir, "_admin", True

    token = _get_token()
    if not token:
        _error(
            "No token provided",
            fix="Use --token <token> or set TEAM_MAIL_TOKEN env var",
        )

    assert token is not None
    result = _validate_token(team_mail_dir, token)
    if result is None:
        _error("Invalid token", fix="Check your TEAM_MAIL_TOKEN value")

    assert result is not None
    user, is_admin = result
    return team_mail_dir, user, is_admin


def _require_admin(team_mail_dir: Path, password: str) -> None:
    """Validate admin password. Exits on error."""
    admin_file = team_mail_dir / "admin.json"
    if not admin_file.exists():
        _error(
            "Admin not initialized",
            fix="Run 'team-mail admin init' first",
        )

    admin_config = T.cast(AdminConfig, json.loads(admin_file.read_text()))
    if not _verify_password(password, admin_config["password_hash"], admin_config["salt"]):
        _error("Invalid password")


def _require_user() -> tuple[Path, str]:
    """Validate user token from env, return (team_mail_dir, username). Exits on error.

    Supports admin impersonation via --user when authenticated as admin.
    """
    team_mail_dir, user, is_admin = _require_auth()

    if is_admin:
        # Admin can impersonate users with --user
        if _cli_user:
            # Verify the target user exists
            user_dir = _get_user_dir(team_mail_dir, _cli_user)
            if not user_dir.is_dir():
                users = list(_iter_usernames(team_mail_dir))
                _error(
                    f"User '{_cli_user}' not found",
                    available=users if users else None,
                )
            return team_mail_dir, _cli_user

        # Admin without --user cannot use user commands
        if _cli_password:
            _error(
                "--password authenticates as admin, not as a user",
                fix="Use --user <name> to act on behalf of a user, or use a user token",
            )
        _error(
            "Admin token cannot be used for user operations",
            fix="Use --user <name> to act on behalf of a user, or use a user token",
        )

    # Non-admin with --user is an error
    if _cli_user:
        _error(
            "--user requires admin authentication",
            fix="Use --password or admin --token with --user",
        )

    return team_mail_dir, user


def _require_user_or_admin() -> tuple[Path, str, bool]:
    """Validate token from env, return (team_mail_dir, user, is_admin). Exits on error.

    Unlike _require_user(), allows both admin and user tokens.
    """
    return _require_auth()


# ---------------------------------------------------------------------------
# User name helpers
# ---------------------------------------------------------------------------


def _validate_username(name: str) -> tuple[bool, str]:
    """Validate username format. Returns (is_valid, error_message)."""
    if not name:
        return False, "Name cannot be empty"

    if len(name) < 3:
        return False, "Name must be at least 3 characters"

    if len(name) > 40:
        return False, "Name must be at most 40 characters"

    if not re.match(r"^[a-z0-9-]+$", name):
        return False, "Name must contain only lowercase letters, numbers, and dashes"

    if name.startswith("-") or name.endswith("-"):
        return False, "Name cannot start or end with a dash"

    if "--" in name:
        return False, "Name cannot contain consecutive dashes"

    if not re.search(r"[a-z]", name):
        return False, "Name must contain at least one letter"

    return True, ""


# ---------------------------------------------------------------------------
# General helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _iter_usernames(team_mail_dir: Path) -> Iterator[str]:
    """Iterate over all usernames."""
    users_dir = _get_users_dir(team_mail_dir)
    if not users_dir.is_dir():
        return
    for user_dir in users_dir.iterdir():
        if user_dir.is_dir():
            yield user_dir.name


def _load_profile(user_dir: Path) -> AgentProfile | None:
    """Load a user's profile.json."""
    profile_path = user_dir / "profile.json"
    if not profile_path.exists():
        return None
    return T.cast(AgentProfile, json.loads(profile_path.read_text()))


def _save_profile(user_dir: Path, profile: AgentProfile) -> None:
    """Save a user's profile.json."""
    profile_path = user_dir / "profile.json"
    _ = profile_path.write_text(json.dumps(profile, indent=2) + "\n")


# ---------------------------------------------------------------------------
# Admin commands (Tasks 2.1-2.4)
# ---------------------------------------------------------------------------


def cmd_admin_init(args: argparse.Namespace) -> None:
    """First-time password setup."""
    # Check if already initialized
    existing_dir = _get_team_mail_dir()
    if existing_dir is not None:
        admin_file = existing_dir / "admin.json"
        if admin_file.exists():
            _error(
                "Already initialized",
                fix="Use 'team-mail admin password' to change the password",
            )

    # Get password
    password = T.cast(str | None, args.password)
    if not password:
        _error("Password required", fix="Use --password <password>")

    assert password is not None

    # Create directory structure
    team_mail_dir = _ensure_team_mail_dir()

    # Store password hash
    salt = _generate_salt()
    password_hash = _hash_password(password, salt)
    admin_config: AdminConfig = {
        "password_hash": password_hash,
        "salt": salt,
    }
    admin_file = team_mail_dir / "admin.json"
    _ = admin_file.write_text(json.dumps(admin_config, indent=2) + "\n")

    print(f"Initialized .team-mail/ at {team_mail_dir}")


def cmd_admin_password(args: argparse.Namespace) -> None:
    """Change admin password."""
    team_mail_dir = _require_team_mail_dir()

    old_password = T.cast(str | None, args.old)
    new_password = T.cast(str | None, args.new)

    if not old_password:
        _error("Old password required", fix="Use --old <password>")
    if not new_password:
        _error("New password required", fix="Use --new <password>")

    assert old_password is not None
    assert new_password is not None

    # Verify old password
    _require_admin(team_mail_dir, old_password)

    # Update password
    salt = _generate_salt()
    password_hash = _hash_password(new_password, salt)
    admin_config: AdminConfig = {
        "password_hash": password_hash,
        "salt": salt,
    }
    admin_file = team_mail_dir / "admin.json"
    _ = admin_file.write_text(json.dumps(admin_config, indent=2) + "\n")

    print("Password updated")


def cmd_admin_auth(args: argparse.Namespace) -> None:
    """Mint tokens."""
    team_mail_dir = _require_team_mail_dir()

    password = T.cast(str | None, args.password)
    if not password:
        _error("Password required", fix="Use --password <password>")

    assert password is not None
    _require_admin(team_mail_dir, password)

    is_admin_token = T.cast(bool, args.admin)
    user = T.cast(str | None, args.user)
    force = T.cast(bool, getattr(args, "force", False))

    if is_admin_token and user:
        _error("Cannot specify both --admin and --user")

    if not is_admin_token and not user:
        _error("Must specify --admin or --user <name>")

    if is_admin_token:
        # Return existing token if it exists (unless --force)
        existing = _read_token(team_mail_dir, "_admin")
        if existing and not force:
            print(existing)
            return

        # Mint new admin token
        token = _generate_token()
        _store_token(team_mail_dir, "_admin", token)
        print(token)
    else:
        assert user is not None
        # Check user exists
        user_dir = _get_user_dir(team_mail_dir, user)
        if not user_dir.is_dir():
            users = list(_iter_usernames(team_mail_dir))
            _error(
                f"User '{user}' not found",
                fix="Create user with 'team-mail admin create'",
                available=users if users else None,
            )

        # Return existing token if it exists (unless --force)
        existing = _read_token(team_mail_dir, user)
        if existing and not force:
            print(existing)
            return

        # Mint new token
        token = _generate_token()
        _store_token(team_mail_dir, user, token)
        print(token)


def cmd_users_add(args: argparse.Namespace) -> None:
    """Create user account."""
    team_mail_dir, user, is_admin = _require_auth()

    if not is_admin:
        _error("Admin token required", fix="Set TEAM_MAIL_TOKEN to an admin token")

    name = T.cast(str, args.name)
    role = T.cast(str, args.role)

    # Validate username
    valid, err = _validate_username(name)
    if not valid:
        _error(f"Invalid username '{name}': {err}")

    # Check if user already exists
    user_dir = _get_user_dir(team_mail_dir, name)
    if user_dir.is_dir():
        _error(f"User '{name}' already exists")

    # Create user directory
    user_dir = _ensure_user_dir(team_mail_dir, name)

    # Create profile
    status = T.cast(str | None, args.status) or ""
    about = T.cast(str | None, args.about) or ""
    tags_str = T.cast(str | None, args.tags)
    tags = [t.strip() for t in tags_str.split(",") if t.strip()] if tags_str else []

    profile: AgentProfile = {
        "name": name,
        "role": role,
        "status": status,
        "about": about,
        "tags": tags,
        "joined": _now_iso(),
        "updated": _now_iso(),
    }
    _save_profile(user_dir, profile)

    print(json.dumps(profile, indent=2))


# ---------------------------------------------------------------------------
# User commands (Tasks 3.1-3.3)
# ---------------------------------------------------------------------------


def _compact_profile(profile: AgentProfile, full: bool = False) -> dict[str, T.Any]:
    """Return profile dict, optionally compacted.

    When full=False (default): excludes dates and empty fields.
    When full=True: includes all fields.
    """
    if full:
        return dict(profile.items())
    skip = {"joined", "updated"}
    return {
        k: v for k, v in profile.items()
        if k not in skip and v not in ("", [], None)
    }


def cmd_users_list(args: argparse.Namespace) -> None:
    """List team members."""
    team_mail_dir = _get_team_mail_dir()
    if team_mail_dir is None:
        print("[]")
        return

    names_only = T.cast(bool, getattr(args, "names_only", False))
    no_self = T.cast(bool, getattr(args, "no_self", False))
    full = T.cast(bool, getattr(args, "full", False))
    tags_filter = T.cast(str | None, getattr(args, "tags", None))
    tags_set = {t.strip() for t in tags_filter.split(",") if t.strip()} if tags_filter else None

    # Get current user if authenticated (for --no-self)
    current_user: str | None = None
    if no_self:
        token = _get_token()
        if token:
            result = _validate_token(team_mail_dir, token)
            if result:
                current_user, _ = result

    if names_only:
        # Just usernames
        for username in sorted(_iter_usernames(team_mail_dir)):
            if no_self and username == current_user:
                continue
            if tags_set:
                user_dir = _get_user_dir(team_mail_dir, username)
                profile = _load_profile(user_dir)
                if profile and not tags_set.intersection(profile.get("tags", [])):
                    continue
            print(username)
    else:
        # List all profiles as JSON array
        profiles: list[dict[str, T.Any]] = []
        for username in sorted(_iter_usernames(team_mail_dir)):
            if no_self and username == current_user:
                continue
            user_dir = _get_user_dir(team_mail_dir, username)
            profile = _load_profile(user_dir)
            if profile is None:
                continue
            if tags_set and not tags_set.intersection(profile.get("tags", [])):
                continue
            profiles.append(_compact_profile(profile, full=full))

        print(json.dumps(profiles, indent=2))


def cmd_users_get(args: argparse.Namespace) -> None:
    """View a specific user's profile."""
    team_mail_dir = _get_team_mail_dir()
    if team_mail_dir is None:
        _error(".team-mail directory not found")

    assert team_mail_dir is not None
    name = T.cast(str, args.name)
    full = T.cast(bool, getattr(args, "full", False))

    user_dir = _get_user_dir(team_mail_dir, name)
    if not user_dir.is_dir():
        users = list(_iter_usernames(team_mail_dir))
        _error(
            f"User '{name}' not found",
            available=users if users else None,
        )

    profile = _load_profile(user_dir)
    if profile is None:
        _error(f"No profile found for '{name}'")

    assert profile is not None
    output = _compact_profile(profile, full=full)
    print(json.dumps(output, indent=2))


def cmd_profile_show(_args: argparse.Namespace) -> None:
    """View own profile (LLM-friendly format)."""
    team_mail_dir, user = _require_user()

    user_dir = _get_user_dir(team_mail_dir, user)
    profile = _load_profile(user_dir)
    if profile is None:
        _error(f"No profile found for '{user}'")

    assert profile is not None

    print(f"You are **{user}**.")
    print(f"Role: {profile['role']}")
    if profile.get("about"):
        print(f"About: {profile['about']}")
    if profile.get("status"):
        print(f"Status: {profile['status']}")
    if profile.get("tags"):
        print(f"Tags: {', '.join(profile['tags'])}")


def cmd_profile_update(args: argparse.Namespace) -> None:
    """Update own profile."""
    status = T.cast(str | None, getattr(args, "status", None))
    tags_str = T.cast(str | None, getattr(args, "tags", None))
    about = T.cast(str | None, getattr(args, "about", None))

    team_mail_dir, user = _require_user()

    user_dir = _get_user_dir(team_mail_dir, user)
    profile = _load_profile(user_dir)
    if profile is None:
        _error(f"No profile found for '{user}'")

    assert profile is not None

    if status is not None:
        profile["status"] = status
    if tags_str is not None:
        profile["tags"] = [t.strip() for t in tags_str.split(",") if t.strip()]
    if about is not None:
        profile["about"] = about

    profile["updated"] = _now_iso()
    _save_profile(user_dir, profile)

    output = _compact_profile(profile)
    print(json.dumps(output, indent=2))


# ---------------------------------------------------------------------------
# Mail commands (Tasks 4.1-4.3)
# ---------------------------------------------------------------------------


def cmd_inbox(args: argparse.Namespace) -> None:
    """Check inbox summary."""
    team_mail_dir, user = _require_user()

    user_dir = _get_user_dir(team_mail_dir, user)
    inbox = user_dir / "mail" / "inbox.jsonl"

    if not inbox.exists() or inbox.stat().st_size == 0:
        print("No messages")
        return

    # Get last_read for unread filtering
    state_file = user_dir / "mail" / "state.json"
    last_read: str | None = None
    if state_file.exists():
        state = T.cast(MailState, json.loads(state_file.read_text()))
        last_read = state.get("last_read")

    # Collect and count messages
    messages: list[Message] = []
    sender_counts: dict[str, int] = {}

    for line in inbox.read_text().splitlines():
        if not line.strip():
            continue
        try:
            msg = T.cast(Message, json.loads(line))
        except json.JSONDecodeError:
            continue

        # Filter by last_read (show only unread)
        if last_read and msg["ts"] <= last_read:
            continue

        messages.append(msg)
        sender = msg["from"]
        sender_counts[sender] = sender_counts.get(sender, 0) + 1

    if not messages:
        print("No messages")
        return

    count = len(messages)
    if count == 1:
        sender = messages[0]["from"]
        print(f"1 unread message from {sender}")
    else:
        breakdown = ", ".join(
            f"{cnt} from {sender}"
            for sender, cnt in sorted(sender_counts.items(), key=lambda x: -x[1])
        )
        print(f"{count} unread messages: {breakdown}")


def cmd_inbox_read(_args: argparse.Namespace) -> None:
    """Read full messages, mark as read."""
    team_mail_dir, user = _require_user()

    user_dir = _get_user_dir(team_mail_dir, user)
    inbox = user_dir / "mail" / "inbox.jsonl"

    if not inbox.exists() or inbox.stat().st_size == 0:
        return  # Silent exit

    # Get last_read for unread filtering
    state_file = user_dir / "mail" / "state.json"
    last_read: str | None = None
    if state_file.exists():
        state = T.cast(MailState, json.loads(state_file.read_text()))
        last_read = state.get("last_read")

    latest_ts: str | None = None

    for line in inbox.read_text().splitlines():
        if not line.strip():
            continue
        try:
            msg = T.cast(Message, json.loads(line))
        except json.JSONDecodeError:
            continue

        # Filter by last_read (show only unread)
        if last_read and msg["ts"] <= last_read:
            continue

        # Track latest timestamp
        if latest_ts is None or msg["ts"] > latest_ts:
            latest_ts = msg["ts"]

        print(json.dumps(msg, separators=(",", ":")))

    # Mark as read
    if latest_ts is not None:
        state: MailState = {}
        if state_file.exists():
            state = T.cast(MailState, json.loads(state_file.read_text()))
        state["last_read"] = latest_ts
        _ = state_file.write_text(json.dumps(state) + "\n")


def cmd_send(args: argparse.Namespace) -> None:
    """Send message."""
    team_mail_dir, sender = _require_user()

    recipient = T.cast(str, args.to)
    body = T.cast(str, args.body)

    # Check recipient exists
    recipient_dir = _get_user_dir(team_mail_dir, recipient)
    if not recipient_dir.is_dir():
        users = list(_iter_usernames(team_mail_dir))
        _error(
            f"User '{recipient}' not found",
            available=users if users else None,
        )

    sender_dir = _get_user_dir(team_mail_dir, sender)

    # Construct message
    msg: Message = {
        "from": sender,
        "to": recipient,
        "ts": _now_iso(),
        "type": "message",
        "body": body,
    }
    line = json.dumps(msg, separators=(",", ":")) + "\n"

    # Write to recipient inbox
    recipient_inbox = recipient_dir / "mail" / "inbox.jsonl"
    try:
        with open(recipient_inbox, "a") as f:
            _ = f.write(line)
    except OSError as e:
        _error(f"Failed to write to recipient inbox: {e}")

    # Write to sender sent log
    sender_sent = sender_dir / "mail" / "sent.jsonl"
    try:
        with open(sender_sent, "a") as f:
            _ = f.write(line)
    except OSError as e:
        print(f"WARNING: Message delivered but sent log failed: {e}", file=sys.stderr)

    print(json.dumps({"status": "delivered", "to": recipient, "ts": msg["ts"]}))


# ---------------------------------------------------------------------------
# Prompt command (for SessionStart hook)
# ---------------------------------------------------------------------------


_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from text."""
    return _ANSI_ESCAPE_RE.sub("", text)


def _collect_help(
    parser: argparse.ArgumentParser,
    prefix: str = "",
    skip: set[str] | None = None,
) -> str:
    """Recursively collect help text from parser and all subparsers.

    Args:
        parser: The argument parser to collect help from.
        prefix: Current command prefix (e.g., "users" or "users add").
        skip: Set of top-level command names to skip (e.g., {"admin"}).
    """
    lines: list[str] = []

    # Get this parser's help (strip ANSI codes for consistent processing)
    lines.append(_strip_ansi(parser.format_help()))

    # Find subparsers action if any
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, subparser in action.choices.items():
                # Skip excluded top-level commands
                if not prefix and skip and name in skip:
                    continue
                subprefix = f"{prefix} {name}" if prefix else name
                lines.append(f"\n{'=' * 60}\n{subprefix}\n{'=' * 60}\n")
                lines.append(_collect_help(subparser, subprefix, skip))

    return "\n".join(lines)


def _dedupe_help_options(text: str) -> str:
    """Post-process help text to show -h/--help only once at the end.

    For each 'options:' block containing '-h, --help':
    - If the block has only 2 lines (header + help line), drop the entire block
    - Otherwise, drop just the -h/--help line
    Keep the final occurrence intact.
    """
    lines = text.split("\n")
    result: list[str] = []

    # Track options blocks to process
    # Each block: (start_idx, help_line_idx, block_line_count)
    options_blocks: list[tuple[int, int, int]] = []

    i = 0
    while i < len(lines):
        line = lines[i]
        result.append(line)

        # Detect start of options block
        if line.strip() == "options:":
            options_start = len(result) - 1
            help_line_idx: int | None = None
            block_lines = 1

            # Scan the options block
            j = i + 1
            while j < len(lines):
                next_line = lines[j]
                # Options block ends at empty line or non-indented line (except empty)
                if next_line and not next_line.startswith(" "):
                    break
                result.append(next_line)
                block_lines += 1
                if "-h, --help" in next_line:
                    help_line_idx = len(result) - 1
                j += 1
            i = j - 1  # Will be incremented at end of loop

            if help_line_idx is not None:
                options_blocks.append((options_start, help_line_idx, block_lines))

        i += 1

    # Process all but the last options block
    if len(options_blocks) > 1:
        # Process in reverse order to maintain indices
        for options_start, help_line_idx, block_lines in reversed(options_blocks[:-1]):
            # Count actual content lines (non-empty lines after "options:")
            content_count = 0
            for k in range(options_start + 1, options_start + block_lines):
                if k < len(result) and result[k].strip():
                    content_count += 1

            if content_count <= 1:
                # Only -h/--help in this block, remove entire block
                # Find where block ends (next non-empty after options content)
                end_idx = options_start + block_lines
                # Remove the block
                del result[options_start:end_idx]
            else:
                # Remove just the -h/--help line
                del result[help_line_idx]

    return "\n".join(result)


def _load_cli_help() -> str:
    """Load CLI help from cli-llm-help.txt."""
    help_file = Path(__file__).parent / "cli-llm-help.txt"
    if help_file.exists():
        return help_file.read_text().strip()
    return "(CLI help not found - run /sync-cli-help-prompt)"


def cmd_prompt(_args: argparse.Namespace) -> None:
    """Print comprehensive prompt for SessionStart hook."""
    # Gather identity info
    team_mail_dir = _get_team_mail_dir()
    token = _get_token() if team_mail_dir else None
    auth_result = _validate_token(team_mail_dir, token) if team_mail_dir and token else None

    # Build the prompt
    sections: list[str] = []

    # 1. Intro + CLI Reference
    cli_help = _load_cli_help()
    sections.append(f"""\
<instructions topic="team-mail">

# team-mail

Message other AI agents running in parallel. Each agent has a unique identity.

{cli_help}

## When to Use

- **Coordinate**: Avoid conflicts by sharing what you're working on
- **Request help**: Ask teammates with relevant expertise
- **Share updates**: Notify others when you complete dependencies
- **Ask questions**: Get clarification from domain experts

Run `team-mail users list --no-self` to find teammates.""")

    # 2. Status (only if there's a problem)
    if not team_mail_dir:
        sections.append("## Status\n\n**Not initialized.** Run `team-mail admin init`.")
    elif not token:
        sections.append("## Status\n\n**No token.** Set $TEAM_MAIL_TOKEN.")
    elif not auth_result:
        sections.append("## Status\n\n**Invalid token.** Check $TEAM_MAIL_TOKEN.")

    # 3. Your Identity (at the end)
    if auth_result:
        username, is_admin = auth_result
        if is_admin:
            sections.append("## Your Identity\n\nYou are **admin**. Use `--user <name>` to act as a user.")
        else:
            assert team_mail_dir is not None
            user_dir = _get_user_dir(team_mail_dir, username)
            profile = _load_profile(user_dir)

            identity_lines = ["## Your Identity", ""]
            if profile:
                identity_lines.append(f"**{username}** — {profile.get('role', 'User')}")
                if profile.get("about"):
                    identity_lines.append(f"{profile['about']}")
                if profile.get("status"):
                    identity_lines.append(f"Status: {profile['status']}")
                if profile.get("tags"):
                    identity_lines.append(f"Tags: {', '.join(profile['tags'])}")
            else:
                identity_lines.append(f"**{username}**")
            sections.append("\n".join(identity_lines))

    sections.append("</instructions>")

    print("\n\n".join(sections))


# ---------------------------------------------------------------------------
# Env command (for hook discovery)
# ---------------------------------------------------------------------------


def cmd_env(_args: argparse.Namespace) -> None:
    """Auto-discover .team-mail dir and print env exports."""
    team_mail_dir = _get_team_mail_dir()
    if team_mail_dir is None:
        sys.exit(0)  # Silent - plugin inactive

    print(f'export TEAM_MAIL_DIR="{team_mail_dir}"')


# ---------------------------------------------------------------------------
# CLI entry point (Task 5.1)
# ---------------------------------------------------------------------------


class Parsers(T.NamedTuple):
    """Container for parsers needed in dispatch."""

    main: argparse.ArgumentParser
    admin: argparse.ArgumentParser
    users: argparse.ArgumentParser
    profile: argparse.ArgumentParser


def _build_parser() -> Parsers:
    """Build and return the argument parser with all subparsers."""
    parser = argparse.ArgumentParser(
        prog="team-mail",
        description="Token-authenticated inter-agent messaging.",
        epilog="Run 'team-mail <command> --help' for command-specific help.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    sub = parser.add_subparsers(dest="command", required=False, metavar="<command>")

    # ---------- admin ----------
    admin_parser = sub.add_parser(
        "admin",
        help="Administrative commands",
        description="Administrative commands for managing the team-mail system.",
    )
    admin_sub = admin_parser.add_subparsers(dest="admin_command", required=False, metavar="<subcommand>")

    # admin init
    admin_init = admin_sub.add_parser(
        "init",
        help="First-time password setup",
        description="Initialize .team-mail/ directory and set admin password.",
    )
    _ = admin_init.add_argument("--password", required=True, help="Admin password")

    # admin password
    admin_password = admin_sub.add_parser(
        "password",
        help="Change admin password",
        description="Change the admin password.",
    )
    _ = admin_password.add_argument("--old", required=True, help="Current password")
    _ = admin_password.add_argument("--new", required=True, help="New password")

    # admin auth
    admin_auth = admin_sub.add_parser(
        "auth",
        help="Mint tokens",
        description="Generate authentication tokens for users or admin.",
    )
    _ = admin_auth.add_argument("--password", required=True, help="Admin password")
    _ = admin_auth.add_argument("--force", action="store_true", help="Regenerate token even if one exists (invalidates old token)")
    auth_target = admin_auth.add_mutually_exclusive_group(required=True)
    _ = auth_target.add_argument("--admin", action="store_true", help="Mint admin token")
    _ = auth_target.add_argument("--user", help="Mint token for specified user")

    # ---------- users ----------
    users_parser = sub.add_parser(
        "users",
        help="Discover and manage users",
        description="List users, view profiles, or add new users. Use 'profile' for your own identity.",
    )
    users_sub = users_parser.add_subparsers(dest="users_command", required=False, metavar="<subcommand>")

    # users list
    users_list = users_sub.add_parser(
        "list",
        help="List all users",
        description="List all users as JSON array (excludes dates by default).",
    )
    _ = users_list.add_argument("--names-only", action="store_true", help="Only output usernames, one per line")
    _ = users_list.add_argument("--no-self", action="store_true", help="Exclude yourself from the list")
    _ = users_list.add_argument("--tags", help="Filter by tags (comma-separated)")
    _ = users_list.add_argument("--full", action="store_true", help="Include all fields (dates, empty values)")

    # users get
    users_get = users_sub.add_parser(
        "get",
        help="View a user's profile",
        description="View a specific user's profile as JSON (excludes dates by default).",
    )
    _ = users_get.add_argument("name", help="Username to view")
    _ = users_get.add_argument("--full", action="store_true", help="Include all fields (dates, empty values)")

    # users add (requires admin auth)
    users_add = users_sub.add_parser(
        "add",
        help="Add a new user (admin only)",
        description="Create a new user account. Requires admin auth via --password, --token, or $TEAM_MAIL_TOKEN.",
    )
    _ = users_add.add_argument("name", help="Username (3-40 chars, lowercase, letters/numbers/dashes)")
    _ = users_add.add_argument("role", help="User role (e.g. 'Backend Engineer')")
    _ = users_add.add_argument("--token", help="Admin token")
    _ = users_add.add_argument("--password", help="Admin password (alternative to --token)")
    _ = users_add.add_argument("--status", help="Initial status")
    _ = users_add.add_argument("--tags", help="Comma-separated tags")
    _ = users_add.add_argument("--about", help="About description")

    # ---------- profile ----------
    profile_parser = sub.add_parser(
        "profile",
        help="Your identity",
        description="View or update your own profile. Requires token. Use 'team' to discover others.",
    )
    profile_sub = profile_parser.add_subparsers(dest="profile_command", required=False, metavar="<subcommand>")

    # profile show
    profile_show = profile_sub.add_parser(
        "show",
        help="View your profile",
        description="View your own profile. Requires user token.",
    )
    _ = profile_show.add_argument("--token", help="User token (or set $TEAM_MAIL_TOKEN)")
    _ = profile_show.add_argument("--password", help="Admin password (requires --user)")
    _ = profile_show.add_argument("--user", help="Act as this user (requires admin auth)")

    # profile update
    profile_update = profile_sub.add_parser(
        "update",
        help="Update your profile",
        description="Update your profile fields. Requires user token.",
    )
    _ = profile_update.add_argument("--token", help="User token (or set $TEAM_MAIL_TOKEN)")
    _ = profile_update.add_argument("--password", help="Admin password (requires --user)")
    _ = profile_update.add_argument("--user", help="Act as this user (requires admin auth)")
    _ = profile_update.add_argument("--status", help="Set your status")
    _ = profile_update.add_argument("--tags", help="Set your tags (comma-separated)")
    _ = profile_update.add_argument("--about", help="Set your about description")

    # ---------- inbox ----------
    inbox_parser = sub.add_parser(
        "inbox",
        help="Check inbox",
        description="Check inbox summary or read full messages. Requires user token.",
    )
    _ = inbox_parser.add_argument("--token", help="User token (or set $TEAM_MAIL_TOKEN)")
    _ = inbox_parser.add_argument("--password", help="Admin password (requires --user)")
    _ = inbox_parser.add_argument("--user", help="Act as this user (requires admin auth)")

    inbox_sub = inbox_parser.add_subparsers(dest="inbox_command", metavar="<subcommand>")

    # inbox read
    inbox_read = inbox_sub.add_parser(
        "read",
        help="Read full messages, mark as read",
        description="Read all unread messages as JSONL and mark them as read. Requires user token.",
    )
    _ = inbox_read.add_argument("--token", help="User token (or set $TEAM_MAIL_TOKEN)")
    _ = inbox_read.add_argument("--password", help="Admin password (requires --user)")
    _ = inbox_read.add_argument("--user", help="Act as this user (requires admin auth)")

    # ---------- send ----------
    send_parser = sub.add_parser(
        "send",
        help="Send message",
        description="Send a message to another user. Requires user token.",
    )
    _ = send_parser.add_argument("--token", help="User token (or set $TEAM_MAIL_TOKEN)")
    _ = send_parser.add_argument("--password", help="Admin password (requires --user)")
    _ = send_parser.add_argument("--user", help="Send as this user (requires admin auth)")
    _ = send_parser.add_argument("to", help="Recipient username")
    _ = send_parser.add_argument("body", help="Message body")

    # ---------- env (for hooks) ----------
    _ = sub.add_parser(
        "env",
        help="Print env exports for hooks",
        description="Auto-discover .team-mail directory and print shell export statements.",
    )

    # ---------- prompt (for SessionStart hook) ----------
    _ = sub.add_parser(
        "prompt",
        help="Print onboarding prompt for agents",
        description="Print comprehensive prompt with CLI reference and current user identity.",
    )

    return Parsers(main=parser, admin=admin_parser, users=users_parser, profile=profile_parser)


def main() -> None:
    global _cli_token, _cli_password, _cli_user

    parsers = _build_parser()

    # ---------- Parse and dispatch ----------
    args = parsers.main.parse_args()

    # Set global auth from CLI if provided
    # Priority: --password > --token > TEAM_MAIL_TOKEN
    _cli_token = T.cast(str | None, getattr(args, "token", None))
    _cli_password = T.cast(str | None, getattr(args, "password", None))
    _cli_user = T.cast(str | None, getattr(args, "user", None))

    if args.command is None:
        parsers.main.print_help()
        sys.exit(0)

    command = T.cast(str, args.command)

    if command == "admin":
        admin_command = T.cast(str | None, args.admin_command)
        if admin_command is None:
            parsers.admin.print_help()
            sys.exit(0)
        admin_cmd_map: dict[str, T.Callable[[argparse.Namespace], None]] = {
            "init": cmd_admin_init,
            "password": cmd_admin_password,
            "auth": cmd_admin_auth,
        }
        admin_cmd_map[admin_command](args)

    elif command == "users":
        users_command = T.cast(str | None, getattr(args, "users_command", None))
        if users_command == "list":
            cmd_users_list(args)
        elif users_command == "get":
            cmd_users_get(args)
        elif users_command == "add":
            cmd_users_add(args)
        else:
            parsers.users.print_help()
            sys.exit(0)

    elif command == "profile":
        profile_command = T.cast(str | None, getattr(args, "profile_command", None))
        if profile_command == "show":
            cmd_profile_show(args)
        elif profile_command == "update":
            cmd_profile_update(args)
        else:
            parsers.profile.print_help()
            sys.exit(0)

    elif command == "inbox":
        inbox_command = T.cast(str | None, getattr(args, "inbox_command", None))
        if inbox_command == "read":
            cmd_inbox_read(args)
        else:
            cmd_inbox(args)

    else:
        cmd_map: dict[str, T.Callable[[argparse.Namespace], None]] = {
            "send": cmd_send,
            "env": cmd_env,
            "prompt": cmd_prompt,
        }
        cmd_map[command](args)


if __name__ == "__main__":
    main()
