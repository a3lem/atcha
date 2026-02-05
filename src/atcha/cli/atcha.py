#!/usr/bin/env python
"""atcha: Token-authenticated messaging between parallel Claude Code sessions.

This CLI provides a hierarchical command structure with token-based authentication.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
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
ATCHA_DIR_NAME: T.Final[str] = ".atcha"
TOKEN_LENGTH: T.Final[int] = 5  # 5-char random token


# ---------------------------------------------------------------------------
# Type definitions
# ---------------------------------------------------------------------------


class AdminConfig(T.TypedDict):
    """Admin configuration stored in admin.json."""

    password_hash: str
    salt: str


class UserProfile(T.TypedDict):
    """User profile stored in profile.json.

    - id: Full identifier (e.g., 'maya-backend-engineer'), matches directory name
    - name: Short name (e.g., 'maya'), first component of id, always unique
    - last_seen: Last activity timestamp (updated on send/read)
    """

    id: str
    name: str
    role: str
    status: str
    about: str
    tags: list[str]
    last_seen: str
    joined: str
    updated: str


class MailState(T.TypedDict, total=False):
    """Mail state stored in state.json."""

    last_read: str


# Message type - using dict to avoid TypedDict complexity with reserved keywords
Message = dict[str, T.Any]  # Fields: id, thread_id, reply_to (optional), from, to, ts, type, content


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


def _get_atcha_dir() -> Path | None:
    """Get .atcha directory from env var or find by walking up."""
    # First check env var
    env_dir = os.environ.get("ATCHA_DIR")
    if env_dir:
        p = Path(env_dir)
        if p.is_dir():
            return p
        return None

    # Walk up looking for .atcha/
    d = Path.cwd().resolve()
    while True:
        candidate = d / ATCHA_DIR_NAME
        if candidate.is_dir():
            return candidate
        parent = d.parent
        if parent == d:
            return None
        d = parent


def _require_atcha_dir() -> Path:
    """Get .atcha directory or exit with error."""
    atcha_dir = _get_atcha_dir()
    if atcha_dir is None:
        _error(
            ".atcha directory not found",
            fix="Run 'atcha init' to initialize",
        )
    assert atcha_dir is not None
    return atcha_dir


def _ensure_atcha_dir() -> Path:
    """Create .atcha directory structure. Returns the directory path."""
    atcha_dir = Path.cwd() / ATCHA_DIR_NAME
    atcha_dir.mkdir(exist_ok=True)
    (atcha_dir / "tokens").mkdir(exist_ok=True)
    (atcha_dir / "users").mkdir(exist_ok=True)
    return atcha_dir


def _get_users_dir(atcha_dir: Path) -> Path:
    """Get the users directory.

    Automatically migrates from old 'agents/' directory name to 'users/' if found.
    """
    users_dir = atcha_dir / "users"
    old_agents_dir = atcha_dir / "agents"

    # Auto-migrate from old 'agents' directory to 'users'
    if not users_dir.exists() and old_agents_dir.exists():
        try:
            _ = old_agents_dir.rename(users_dir)
        except OSError:
            # If rename fails, just return users_dir and let the caller handle it
            pass

    return users_dir


def _get_user_dir(atcha_dir: Path, user_id: str) -> Path:
    """Get a specific user's directory by id."""
    return _get_users_dir(atcha_dir) / user_id


def _extract_name(user_id: str) -> str:
    """Extract short name from user id.

    The name is the first component before any dash followed by a role.
    E.g., 'maya-backend-engineer' -> 'maya'
    """
    return user_id.split("-")[0]


def _resolve_user(atcha_dir: Path, identifier: str) -> str | None:
    """Resolve an identifier (id or name) to the full user id.

    Args:
        atcha_dir: Path to .atcha directory
        identifier: Either a full id ('maya-backend-engineer') or short name ('maya')

    Returns:
        The full user id if found, None otherwise.

    Raises:
        SystemExit if the short name matches multiple users (ambiguous).
    """
    users_dir = _get_users_dir(atcha_dir)
    if not users_dir.exists():
        return None

    # First, try exact match on id (directory name)
    if (users_dir / identifier).is_dir():
        return identifier

    # Otherwise, try to match on name (first component)
    matches: list[str] = []
    for user_dir in users_dir.iterdir():
        if user_dir.is_dir():
            user_id = user_dir.name
            if _extract_name(user_id) == identifier:
                matches.append(user_id)

    if len(matches) == 1:
        return matches[0]
    elif len(matches) > 1:
        _error(
            f"Name '{identifier}' matches multiple users: {', '.join(matches)}",
            fix="User names must be unique. This indicates a data inconsistency - rename one of the users",
        )

    return None


def _is_name_unique(atcha_dir: Path, name: str, exclude_id: str | None = None) -> bool:
    """Check if a short name is unique among all users.

    Args:
        atcha_dir: Path to .atcha directory
        name: The short name to check
        exclude_id: Optional user id to exclude from the check (for updates)

    Returns:
        True if the name is unique, False otherwise.
    """
    users_dir = _get_users_dir(atcha_dir)
    if not users_dir.exists():
        return True

    for user_dir in users_dir.iterdir():
        if user_dir.is_dir():
            user_id = user_dir.name
            if exclude_id and user_id == exclude_id:
                continue
            if _extract_name(user_id) == name:
                return False

    return True


def _find_duplicate_names(atcha_dir: Path) -> dict[str, list[str]]:
    """Find user names that are used by multiple users.

    Names must be unique. This detects data inconsistencies from manual edits.

    Returns:
        Dict mapping name to list of user ids that share it.
        Only includes names with 2+ users.
    """
    users_dir = _get_users_dir(atcha_dir)
    if not users_dir.exists():
        return {}

    name_to_ids: dict[str, list[str]] = {}
    for user_dir in users_dir.iterdir():
        if user_dir.is_dir():
            user_id = user_dir.name
            short_name = _extract_name(user_id)
            if short_name not in name_to_ids:
                name_to_ids[short_name] = []
            name_to_ids[short_name].append(user_id)

    # Return only duplicates
    return {name: ids for name, ids in name_to_ids.items() if len(ids) > 1}


def _ensure_user_dir(atcha_dir: Path, user_id: str) -> Path:
    """Create user directory structure."""
    user_dir = _get_user_dir(atcha_dir, user_id)
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

# Alphabet for token encoding (no ambiguous chars like 0/O, 1/l)
TOKEN_ALPHABET: T.Final[str] = "23456789abcdefghjkmnpqrstuvwxyz"


def _generate_user_id() -> str:
    """Generate a random user ID.

    Uses the same alphabet as tokens (no ambiguous chars).
    Returns a 5-character random string for use as immutable user identifier.
    """
    result = []
    for _ in range(TOKEN_LENGTH):
        result.append(secrets.choice(TOKEN_ALPHABET))
    return "".join(result)


def _derive_token(password: str, user_name: str, salt: str) -> str:
    """Derive a deterministic token from admin password and agent name.

    Uses HMAC-SHA256 with the password as key, then encodes to TOKEN_LENGTH chars.
    Same password + agent + salt always produces the same token.
    """
    key = password.encode()
    message = f"token:{user_name}:{salt}".encode()
    derived = hmac.new(key, message, hashlib.sha256).digest()

    # Convert first bytes to our alphabet
    result = []
    for i in range(TOKEN_LENGTH):
        idx = derived[i] % len(TOKEN_ALPHABET)
        result.append(TOKEN_ALPHABET[idx])
    return "".join(result)


def _hash_token(token: str) -> str:
    """Hash a token for storage. Uses SHA-256."""
    return hashlib.sha256(token.encode()).hexdigest()


def _get_token_file(atcha_dir: Path, name: str) -> Path:
    """Get path to token file for a user or admin."""
    return atcha_dir / "tokens" / name


def _store_token_hash(atcha_dir: Path, name: str, token: str) -> None:
    """Store a hashed token for a user."""
    token_file = _get_token_file(atcha_dir, name)
    token_hash = _hash_token(token)
    _ = token_file.write_text(token_hash + "\n")


def _validate_token(atcha_dir: Path, token: str) -> tuple[str, bool] | None:
    """Validate a token and return (username, is_admin) or None if invalid.

    Hashes the provided token and checks against stored hashes.
    Returns (username, False) for valid user token.
    Admin does not use tokens - use password instead.
    """
    tokens_dir = atcha_dir / "tokens"
    if not tokens_dir.is_dir():
        return None

    # Hash the provided token once
    provided_hash = _hash_token(token)

    for token_file in tokens_dir.iterdir():
        if not token_file.is_file():
            continue
        # Skip legacy _admin token if present
        if token_file.name == "_admin":
            continue
        stored_hash = token_file.read_text().strip()
        if stored_hash == provided_hash:
            return (token_file.name, False)

    return None


# ---------------------------------------------------------------------------
# Auth context helpers (Task 1.4)
# ---------------------------------------------------------------------------


def _get_token_from_env() -> str | None:
    """Get token from $ATCHA_TOKEN environment variable."""
    return os.environ.get("ATCHA_TOKEN")


# Global to hold --token from CLI (set during arg parsing)
_cli_token: str | None = None


def _get_token() -> str | None:
    """Get token from CLI option (--token) or env var ($ATCHA_TOKEN)."""
    if _cli_token:
        return _cli_token
    return _get_token_from_env()


# Global to hold --password from CLI (set during arg parsing)
_cli_password: str | None = None

# Global to hold --user from CLI (for admin impersonation)
_cli_user: str | None = None


def _get_password_from_env() -> str | None:
    """Get admin password from $ATCHA_ADMIN_PASS environment variable."""
    return os.environ.get("ATCHA_ADMIN_PASS")


def _get_password() -> str | None:
    """Get password from CLI option (--password) or env var ($ATCHA_ADMIN_PASS)."""
    if _cli_password:
        return _cli_password
    return _get_password_from_env()


def _require_auth() -> tuple[Path, str, bool]:
    """Validate auth from CLI or env, return (atcha_dir, user, is_admin). Exits on error.

    Priority: --password/ATCHA_ADMIN_PASS > --token/ATCHA_TOKEN
    """
    atcha_dir = _require_atcha_dir()

    # Check password first (admin auth)
    password = _get_password()
    if password:
        _require_admin(atcha_dir, password)
        return atcha_dir, "_admin", True

    # Then check token (user auth)
    token = _get_token()
    if not token:
        _error(
            "No token provided",
            fix="Use --token <token> or set ATCHA_TOKEN env var",
        )

    assert token is not None
    result = _validate_token(atcha_dir, token)
    if result is None:
        _error("Invalid token", fix="Check your ATCHA_TOKEN value")

    assert result is not None
    user, is_admin = result
    return atcha_dir, user, is_admin


def _require_admin(atcha_dir: Path, password: str) -> None:
    """Validate admin password. Exits on error."""
    admin_file = atcha_dir / "admin.json"
    if not admin_file.exists():
        _error(
            "Admin not initialized",
            fix="Run 'atcha init' first",
        )

    admin_config = T.cast(AdminConfig, json.loads(admin_file.read_text()))
    if not _verify_password(password, admin_config["password_hash"], admin_config["salt"]):
        _error("Invalid password")


def _require_user() -> tuple[Path, str]:
    """Validate user token from env, return (atcha_dir, user_name). Exits on error.

    Supports admin impersonation via --user when authenticated as admin.
    """
    atcha_dir, user_name, is_admin = _require_auth()

    if is_admin:
        # Admin can impersonate users with --user
        if _cli_user:
            # Resolve and verify the target agent exists
            user_id = _resolve_user(atcha_dir, _cli_user)
            if user_id is None:
                users = list(_iter_user_names(atcha_dir))
                _error(
                    f"Agent '{_cli_user}' not found",
                    available=users if users else None,
                )
            assert user_id is not None
            return atcha_dir, user_id

        # Admin without --user cannot use agent commands
        if _cli_password:
            _error(
                "--password authenticates as admin, not as a user",
                fix="Use --user <id-or-name> to act on behalf of a user, or use a user token",
            )
        _error(
            "Admin token cannot be used for user operations",
            fix="Use --user <id-or-name> to act on behalf of a user, or use a user token",
        )

    # Non-admin with --user is an error
    if _cli_user:
        _error(
            "--user requires admin authentication",
            fix="Use --password or admin --token with --user",
        )

    return atcha_dir, user_name


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


def _slugify_role(role: str) -> str:
    """Convert a role string to a slug suitable for user ids.

    Examples:
        'CLI Specialist' -> 'cli-specialist'
        'Backend Engineer' -> 'backend-engineer'
    """
    # Convert to lowercase, replace spaces with dashes, remove non-alphanumeric except dashes
    slug = role.lower().strip()
    slug = re.sub(r'\s+', '-', slug)  # Replace spaces with dashes
    slug = re.sub(r'[^a-z0-9-]', '', slug)  # Remove non-alphanumeric except dashes
    slug = re.sub(r'-+', '-', slug)  # Collapse multiple dashes
    slug = slug.strip('-')  # Remove leading/trailing dashes
    return slug


def _build_user_id(name: str, role: str) -> str:
    """Build a full user id from a short name and role.

    Args:
        name: Short name (e.g., 'anna')
        role: Role description (e.g., 'CLI Specialist')

    Returns:
        Full user id (e.g., 'anna-cli-specialist')
    """
    role_slug = _slugify_role(role)
    if role_slug:
        return f"{name}-{role_slug}"
    else:
        return name


# ---------------------------------------------------------------------------
# General helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _generate_message_id(sender: str, timestamp: str) -> str:
    """Generate a short unique message ID from sender, timestamp, and random salt."""
    salt = secrets.token_hex(4)  # 4 bytes = 8 hex chars of randomness
    data = f"{sender}:{timestamp}:{salt}".encode()
    hash_digest = hashlib.sha256(data).hexdigest()
    return f"msg-{hash_digest[:8]}"  # 8 char hex = ~4 billion possibilities


def _update_last_seen(user_dir: Path) -> None:
    """Update the last_seen timestamp for a user."""
    profile = _load_profile(user_dir)
    if profile:
        profile["last_seen"] = _now_iso()
        _save_profile(user_dir, profile)


def _format_time_ago(iso_timestamp: str) -> str:
    """Format ISO timestamp as 'X min/hours/days ago'."""
    try:
        ts = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        delta = now - ts

        seconds = int(delta.total_seconds())
        if seconds < 60:
            return "just now"
        elif seconds < 3600:
            minutes = seconds // 60
            return f"{minutes} min ago"
        elif seconds < 86400:
            hours = seconds // 3600
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        else:
            days = seconds // 86400
            return f"{days} day{'s' if days != 1 else ''} ago"
    except Exception:
        return "unknown"


def _iter_user_names(atcha_dir: Path) -> Iterator[str]:
    """Iterate over all user names."""
    users_dir = _get_users_dir(atcha_dir)
    if not users_dir.is_dir():
        return
    for user_dir in users_dir.iterdir():
        if user_dir.is_dir():
            yield user_dir.name


def _load_profile(user_dir: Path) -> UserProfile | None:
    """Load a user's profile.json.

    Handles migration from old format (name=full id) to new format (id + name + last_seen).
    """
    profile_path = user_dir / "profile.json"
    if not profile_path.exists():
        return None

    data = json.loads(profile_path.read_text())
    needs_save = False

    # Migrate old format: if no 'id' field, derive from directory name
    if "id" not in data:
        user_id = user_dir.name
        data["id"] = user_id
        data["name"] = _extract_name(user_id)
        needs_save = True

    # Migrate: add last_seen if missing
    if "last_seen" not in data:
        data["last_seen"] = data.get("updated", data.get("joined", _now_iso()))
        needs_save = True

    if needs_save:
        _ = profile_path.write_text(json.dumps(data, indent=2) + "\n")

    return T.cast(UserProfile, data)


def _save_profile(user_dir: Path, profile: UserProfile) -> None:
    """Save a user's profile.json."""
    profile_path = user_dir / "profile.json"
    _ = profile_path.write_text(json.dumps(profile, indent=2) + "\n")


# ---------------------------------------------------------------------------
# Admin commands (Tasks 2.1-2.4)
# ---------------------------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> None:
    """Initialize workspace (first-time setup)."""
    # Handle --check mode
    if getattr(args, "check", False):
        existing_dir = _get_atcha_dir()
        if existing_dir is not None and (existing_dir / "admin.json").exists():
            print("Atcha initialized")
            sys.exit(0)
        else:
            sys.exit(1)

    # Check if already initialized
    existing_dir = _get_atcha_dir()
    if existing_dir is not None:
        admin_file = existing_dir / "admin.json"
        if admin_file.exists():
            _error(
                "Already initialized",
                fix="Use 'atcha admin password' to change the password",
            )

    # Get password from CLI arg or prompt interactively
    password = T.cast(str | None, args.password)
    if not password:
        # Interactive prompt
        try:
            password = getpass.getpass("Admin password: ")
            if not password:
                _error("Password cannot be empty")
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                _error("Passwords do not match")
        except (EOFError, KeyboardInterrupt):
            print()  # Newline after ^C
            sys.exit(1)

    assert password is not None

    # Create directory structure
    atcha_dir = _ensure_atcha_dir()

    # Store password hash
    salt = _generate_salt()
    password_hash = _hash_password(password, salt)
    admin_config: AdminConfig = {
        "password_hash": password_hash,
        "salt": salt,
    }
    admin_file = atcha_dir / "admin.json"
    _ = admin_file.write_text(json.dumps(admin_config, indent=2) + "\n")

    print(f"Initialized .atcha/ at {atcha_dir}")


def cmd_admin_password(args: argparse.Namespace) -> None:
    """Change admin password."""
    atcha_dir = _require_atcha_dir()

    old_password = T.cast(str | None, args.old)
    new_password = T.cast(str | None, args.new)

    if not old_password:
        _error("Old password required", fix="Use --old <password>")
    if not new_password:
        _error("New password required", fix="Use --new <password>")

    assert old_password is not None
    assert new_password is not None

    # Verify old password
    _require_admin(atcha_dir, old_password)

    # Update password
    salt = _generate_salt()
    password_hash = _hash_password(new_password, salt)
    admin_config: AdminConfig = {
        "password_hash": password_hash,
        "salt": salt,
    }
    admin_file = atcha_dir / "admin.json"
    _ = admin_file.write_text(json.dumps(admin_config, indent=2) + "\n")

    print("Password updated")


def cmd_admin_hints(args: argparse.Namespace) -> None:
    """Print helpful hints and reminders for admins."""
    hints = """# Atcha Admin Hints

## Environment Variables

| Variable | Purpose | Usage |
|----------|---------|-------|
| `ATCHA_DIR` | Path to `.atcha/` directory | Auto-discovered if not set. Override for shared setup across worktrees. |
| `ATCHA_TOKEN` | User authentication token | Set this to authenticate as a specific user. Get token with `atcha create-token`. |
| `ATCHA_ADMIN_PASS` | Admin password | Used for admin operations instead of tokens. Set once, use for all admin commands. |

## Common Admin Tasks

### Creating a New User
```bash
export ATCHA_ADMIN_PASS=your-password
atcha admin users add --name alice-backend --role "Backend Engineer" --tags=backend,auth
```

### Getting a User's Token
```bash
atcha create-token --user alice-backend
# Copy the token and share it with the user (or set in their .env)
```

### Listing All Users
```bash
atcha admin users list              # JSON format
atcha admin users list --names-only # Just names
```

### Updating Another User's Profile
```bash
atcha profile update --name alice-backend --status "On vacation" --password $ATCHA_ADMIN_PASS
```

## Directory Structure

```
.atcha/
├── admin.json              # Admin password hash + salt
├── tokens/
│   ├── _admin              # Admin token hash (unused)
│   └── <user-name>         # User token hashes
└── users/
    └── <user-name>/
        ├── profile.json    # User profile
        └── mail/
            ├── inbox.jsonl # Incoming messages
            ├── sent.jsonl  # Sent messages
            └── state.json  # Read state
```

## Token Security

- Tokens are **deterministic**: Same password + agent always produces the same token
- Only **hashes** are stored in `.atcha/tokens/`
- **Never** share your admin password; share individual user tokens instead
- **Token format**: 5-character alphanumeric (e.g., `a3k9m`)

## Multi-Worktree Setup

```bash
# Shared .atcha directory
export ATCHA_DIR=/path/to/shared/.atcha

# Worktree 1 - as alice
export ATCHA_TOKEN=<alice-token>

# Worktree 2 - as bob
export ATCHA_TOKEN=<bob-token>
```

## Quick Reference

| Need to... | Command |
|------------|---------|
| Change admin password | `atcha admin password --old <old> --new <new>` |
| Check initialization | `atcha init --check` |
| Create user token | `atcha create-token --user <name>` |
| View user profile | `atcha contacts <name>` |
| List all users | `atcha admin users list` |
"""
    print(hints)


def cmd_admin_users(args: argparse.Namespace) -> None:
    """Admin users command - list all users or add new users."""
    users_command = T.cast(str | None, getattr(args, "users_command", None))

    if users_command == "list":
        # List all users (admin context, so include_self=True by default)
        list_args = argparse.Namespace()
        list_args.names_only = T.cast(bool, getattr(args, "names_only", False))
        list_args.include_self = True  # Admin sees all
        list_args.tags = T.cast(str | None, getattr(args, "tags", None))
        list_args.full = T.cast(bool, getattr(args, "full", False))
        cmd_agents_list(list_args)

    elif users_command == "add":
        # Delegate to agents_add (requires admin auth via $ATCHA_ADMIN_PASS)
        # Set password from env for users_add
        add_args = argparse.Namespace()
        add_args.name = T.cast(str, args.name)
        add_args.role = T.cast(str, args.role)
        add_args.password = _get_password_from_env()
        add_args.token = None
        add_args.status = T.cast(str | None, getattr(args, "status", None))
        add_args.tags = T.cast(str | None, getattr(args, "tags", None))
        add_args.about = T.cast(str | None, getattr(args, "about", None))
        cmd_agents_add(add_args)

    else:
        print("Usage: atcha admin users {list|add}", file=sys.stderr)
        sys.exit(1)


def cmd_create_token(args: argparse.Namespace) -> None:
    """Create user token (admin only).

    Derives the token deterministically from password + agent name + salt.
    Same inputs always produce the same token. Stores only the hash.
    """
    atcha_dir = _require_atcha_dir()

    # Get password from CLI or env
    password = T.cast(str | None, args.password) or _get_password_from_env()
    if not password:
        _error("Password required", fix="Use --password <password> or set ATCHA_ADMIN_PASS")

    assert password is not None
    _require_admin(atcha_dir, password)

    identifier = T.cast(str, args.user)

    # Resolve identifier (can be id or short name)
    user_id = _resolve_user(atcha_dir, identifier)
    if user_id is None:
        users = list(_iter_user_names(atcha_dir))
        _error(
            f"Agent '{identifier}' not found",
            fix="Create user with 'atcha users add'",
            available=users if users else None,
        )

    assert user_id is not None

    # Load salt from admin config
    admin_file = atcha_dir / "admin.json"
    admin_config = T.cast(AdminConfig, json.loads(admin_file.read_text()))
    salt = admin_config["salt"]

    # Derive token deterministically (same password + agent + salt = same token)
    token = _derive_token(password, user_id, salt)

    # Store hash (idempotent - same token always produces same hash)
    _store_token_hash(atcha_dir, user_id, token)

    print(token)


def cmd_agents_add(args: argparse.Namespace) -> None:
    """Create user account."""
    atcha_dir, user, is_admin = _require_auth()

    if not is_admin:
        _error("Admin token required", fix="Set ATCHA_TOKEN to an admin token")

    user_name = T.cast(str, args.name)
    role = T.cast(str, args.role)

    # Validate user name
    valid, err = _validate_username(user_name)
    if not valid:
        _error(f"Invalid user name '{user_name}': {err}")

    # Check if user already exists
    user_dir = _get_user_dir(atcha_dir, user_name)
    if user_dir.is_dir():
        _error(f"User '{user_name}' already exists")

    # Generate unique immutable id
    user_id = _generate_user_id()

    # Create user directory (based on name for human readability)
    user_dir = _ensure_user_dir(atcha_dir, user_name)

    # Create profile
    status = T.cast(str | None, args.status) or ""
    about = T.cast(str | None, args.about) or ""
    tags_str = T.cast(str | None, args.tags)
    tags = [t.strip() for t in tags_str.split(",") if t.strip()] if tags_str else []

    now = _now_iso()
    profile: UserProfile = {
        "id": user_id,        # Random 5-char code (immutable, globally unique)
        "name": user_name,    # Human-readable name (immutable, unique within workspace)
        "role": role,
        "status": status,
        "about": about,
        "tags": tags,
        "last_seen": now,
        "joined": now,
        "updated": now,
    }
    _save_profile(user_dir, profile)

    print(json.dumps(profile, indent=2))


# ---------------------------------------------------------------------------
# User commands (Tasks 3.1-3.3)
# ---------------------------------------------------------------------------


def _compact_profile(profile: UserProfile, full: bool = False, show_last_seen_ago: bool = True) -> dict[str, T.Any]:
    """Return profile dict, optionally compacted.

    When full=False (default): excludes dates and empty fields, but includes last_seen.
    When full=True: includes all fields.
    When show_last_seen_ago=True: adds last_seen_ago field with human-readable format.
    """
    if full:
        result = dict(profile.items())
    else:
        skip = {"joined", "updated"}
        result = {
            k: v for k, v in profile.items()
            if k not in skip and v not in ("", [], None)
        }

    # Add human-readable last_seen_ago field
    if show_last_seen_ago and "last_seen" in result:
        last_seen = result["last_seen"]
        if isinstance(last_seen, str):
            result["last_seen_ago"] = _format_time_ago(last_seen)

    return result


def cmd_contacts(args: argparse.Namespace) -> None:
    """List contacts or view a specific contact."""
    name = T.cast(str | None, args.name)

    # If name provided, show specific contact (delegates to users get)
    if name:
        # Create a modified args for users_get
        get_args = argparse.Namespace()
        get_args.name = name
        get_args.full = T.cast(bool, getattr(args, "full", False))
        cmd_agents_get(get_args)
        return

    # Otherwise list all contacts (delegates to agents_list)
    list_args = argparse.Namespace()
    list_args.names_only = T.cast(bool, getattr(args, "names_only", False))
    list_args.include_self = T.cast(bool, getattr(args, "include_self", False))
    list_args.tags = T.cast(str | None, getattr(args, "tags", None))
    list_args.full = T.cast(bool, getattr(args, "full", False))
    cmd_agents_list(list_args)


def cmd_agents_list(args: argparse.Namespace) -> None:
    """List team agents."""
    atcha_dir = _get_atcha_dir()
    if atcha_dir is None:
        print("[]")
        return

    # Check for duplicate names and error
    duplicates = _find_duplicate_names(atcha_dir)
    if duplicates:
        lines = [f"  name '{name}' used by: {', '.join(ids)}" for name, ids in duplicates.items()]
        _error(
            "Duplicate agent names detected:\n" + "\n".join(lines),
            fix="Agent names must be unique. Rename users so each has a distinct name (first component of id)",
        )

    names_only = T.cast(bool, getattr(args, "names_only", False))
    include_self = T.cast(bool, getattr(args, "include_self", False))
    full = T.cast(bool, getattr(args, "full", False))
    tags_filter = T.cast(str | None, getattr(args, "tags", None))
    tags_set = {t.strip() for t in tags_filter.split(",") if t.strip()} if tags_filter else None

    # Determine if we should exclude self (default: yes, unless --include-self or admin)
    current_user: str | None = None
    is_admin = False
    token = _get_token()
    if token:
        result = _validate_token(atcha_dir, token)
        if result:
            current_user, is_admin = result

    # Admin sees all; otherwise exclude self unless --include-self
    exclude_self = not is_admin and not include_self

    if names_only:
        # Just agent names
        for user_name in sorted(_iter_user_names(atcha_dir)):
            if exclude_self and user_name == current_user:
                continue
            if tags_set:
                user_dir = _get_user_dir(atcha_dir, user_name)
                profile = _load_profile(user_dir)
                if profile and not tags_set.intersection(profile.get("tags", [])):
                    continue
            print(user_name)
    else:
        # List all profiles as JSON array
        profiles: list[dict[str, T.Any]] = []
        for user_name in sorted(_iter_user_names(atcha_dir)):
            if exclude_self and user_name == current_user:
                continue
            user_dir = _get_user_dir(atcha_dir, user_name)
            profile = _load_profile(user_dir)
            if profile is None:
                continue
            if tags_set and not tags_set.intersection(profile.get("tags", [])):
                continue
            profiles.append(_compact_profile(profile, full=full))

        print(json.dumps(profiles, indent=2))


def cmd_agents_get(args: argparse.Namespace) -> None:
    """View a specific user's profile."""
    atcha_dir = _get_atcha_dir()
    if atcha_dir is None:
        _error(".atcha directory not found")

    assert atcha_dir is not None
    identifier = T.cast(str, args.name)
    full = T.cast(bool, getattr(args, "full", False))

    # Resolve identifier (can be id or short name)
    user_id = _resolve_user(atcha_dir, identifier)
    if user_id is None:
        users = list(_iter_user_names(atcha_dir))
        _error(
            f"Agent '{identifier}' not found",
            available=users if users else None,
        )

    assert user_id is not None
    user_dir = _get_user_dir(atcha_dir, user_id)
    profile = _load_profile(user_dir)
    if profile is None:
        _error(f"No profile found for '{user_id}'")

    assert profile is not None
    output = _compact_profile(profile, full=full)
    print(json.dumps(output, indent=2))


def cmd_whoami(_args: argparse.Namespace) -> None:
    """Print your username."""
    _atcha_dir, user_name = _require_user()
    print(user_name)


def cmd_agents_update(args: argparse.Namespace) -> None:
    """Update a user's profile.

    Immutable fields: id, name
    Admin-only fields: role
    User-updatable fields: status, tags, about
    """
    identifier = T.cast(str | None, getattr(args, "name", None))
    status = T.cast(str | None, getattr(args, "status", None))
    tags_str = T.cast(str | None, getattr(args, "tags", None))
    about = T.cast(str | None, getattr(args, "about", None))
    role = T.cast(str | None, getattr(args, "role", None))
    full = getattr(args, "full", False)

    atcha_dir = _require_atcha_dir()

    # Determine if user is admin (needed for role update check)
    is_admin = False
    if identifier is None:
        # Updating self
        _, user_id, is_admin = _require_auth()
    else:
        # Updating another user - requires admin
        _, _auth_user, is_admin = _require_auth()
        if not is_admin:
            _error(
                "Admin authentication required to update other users",
                fix="Use --password or set ATCHA_ADMIN_PASS",
            )
        # Resolve identifier
        user_id = _resolve_user(atcha_dir, identifier)
        if user_id is None:
            users = list(_iter_user_names(atcha_dir))
            _error(
                f"User '{identifier}' not found",
                available=users if users else None,
            )
        assert user_id is not None

    # Role updates are admin-only
    if role is not None and not is_admin:
        _error(
            "Only admins can update roles",
            fix="Roles cannot be self-updated to keep user identities stable. Contact admin if needed.",
        )

    user_dir = _get_user_dir(atcha_dir, user_id)
    if not user_dir.exists():
        _error(f"User '{user_id}' does not exist")

    profile = _load_profile(user_dir)
    if profile is None:
        _error(f"No profile found for '{user_id}'")

    assert profile is not None

    if status is not None:
        profile["status"] = status
    if tags_str is not None:
        profile["tags"] = [t.strip() for t in tags_str.split(",") if t.strip()]
    if about is not None:
        profile["about"] = about
    if role is not None:
        profile["role"] = role

    profile["updated"] = _now_iso()
    _save_profile(user_dir, profile)

    output = _compact_profile(profile, full=full)
    print(json.dumps(output, indent=2))


# ---------------------------------------------------------------------------
# Mail commands (Tasks 4.1-4.3)
# ---------------------------------------------------------------------------


def cmd_profile(args: argparse.Namespace) -> None:
    """Profile command - update user profile."""
    profile_command = T.cast(str | None, getattr(args, "profile_command", None))

    if profile_command == "update":
        # Delegate to agents_update
        update_args = argparse.Namespace()
        update_args.name = T.cast(str | None, getattr(args, "name", None))
        update_args.token = T.cast(str | None, getattr(args, "token", None))
        update_args.password = T.cast(str | None, getattr(args, "password", None))
        update_args.status = T.cast(str | None, getattr(args, "status", None))
        update_args.role = T.cast(str | None, getattr(args, "role", None))
        update_args.tags = T.cast(str | None, getattr(args, "tags", None))
        update_args.about = T.cast(str | None, getattr(args, "about", None))
        update_args.full = T.cast(bool, getattr(args, "full", False))
        cmd_agents_update(update_args)
    else:
        print("Usage: atcha profile update [options]", file=sys.stderr)
        sys.exit(1)


def _get_message_content(msg: Message) -> str:
    """Get message content, with fallback for old 'body' field."""
    return T.cast(str, msg.get("content") or msg.get("body", ""))


def cmd_messages(args: argparse.Namespace) -> None:
    """Check messages summary or read messages."""
    messages_command = T.cast(str | None, getattr(args, "messages_command", None))

    if messages_command is None:
        print("Usage: atcha messages <check|list|read> [options]", file=sys.stderr)
        sys.exit(1)
    elif messages_command == "check":
        cmd_messages_check(args)
    elif messages_command == "read":
        # Handle --all as alias for --include-read
        if getattr(args, "all", False):
            args.include_read = True
        cmd_messages_read(args)
    elif messages_command == "list":
        cmd_messages_list(args)


def cmd_messages_check(args: argparse.Namespace) -> None:
    """Check inbox summary."""
    atcha_dir, user_name = _require_user()

    user_dir = _get_user_dir(atcha_dir, user_name)
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


def cmd_messages_read(args: argparse.Namespace) -> None:
    """Read full messages, mark as read."""
    atcha_dir, user_id, is_admin = _require_auth()

    # Admin must use --user to read a user's inbox
    if is_admin:
        if not _cli_user:
            if _cli_password:
                _error(
                    "--password authenticates as admin, not as a user",
                    fix="Use --user <id-or-name> to act on behalf of a user, or use a user token",
                )
            _error(
                "Admin token cannot be used for user operations",
                fix="Use --user <id-or-name> to act on behalf of a user, or use a user token",
            )
        # Resolve and verify the target agent exists
        resolved_id = _resolve_user(atcha_dir, _cli_user)
        if resolved_id is None:
            users = list(_iter_user_names(atcha_dir))
            _error(
                f"Agent '{_cli_user}' not found",
                available=users if users else None,
            )
        assert resolved_id is not None
        user_id = resolved_id
        user_dir = _get_user_dir(atcha_dir, user_id)
    else:
        if _cli_user:
            _error(
                "--user requires admin authentication",
                fix="Use --password or admin --token with --user",
            )
        user_dir = _get_user_dir(atcha_dir, user_id)

    # Determine if we should include 'to' field (only for admin impersonating)
    include_to_field = is_admin and _cli_user is not None

    inbox = user_dir / "mail" / "inbox.jsonl"

    if not inbox.exists() or inbox.stat().st_size == 0:
        return  # Silent exit

    # Parse filter options
    since_filter = T.cast(str | None, getattr(args, "since", None))
    from_filter = T.cast(str | None, getattr(args, "from_user", None))
    include_read = T.cast(bool, getattr(args, "include_read", False))
    no_mark = T.cast(bool, getattr(args, "no_mark", False))
    target_ids = T.cast(list[str] | None, getattr(args, "ids", None))
    target_ids_set = set(target_ids) if target_ids else None

    # Get last_read for unread filtering
    state_file = user_dir / "mail" / "state.json"
    last_read: str | None = None
    if not include_read and state_file.exists():
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

        # If specific IDs requested, filter by them
        if target_ids_set:
            if msg.get("id") not in target_ids_set:
                continue
        else:
            # Filter by last_read (show only unread, unless --include-read)
            if last_read and msg["ts"] <= last_read:
                continue

        # Filter by --since
        if since_filter and msg["ts"] <= since_filter:
            continue

        # Filter by --from
        if from_filter and msg["from"] != from_filter:
            continue

        # Track latest timestamp
        if latest_ts is None or msg["ts"] > latest_ts:
            latest_ts = msg["ts"]

        # Prepare output (exclude 'to' field unless admin impersonating)
        if include_to_field:
            output = msg
        else:
            output = {k: v for k, v in msg.items() if k != "to"}

        print(json.dumps(output, separators=(",", ":")))

    # Mark as read (unless --no-mark)
    if latest_ts is not None and not no_mark:
        state: MailState = {}
        if state_file.exists():
            state = T.cast(MailState, json.loads(state_file.read_text()))
        state["last_read"] = latest_ts
        _ = state_file.write_text(json.dumps(state) + "\n")

        # Update user's last_seen timestamp
        _update_last_seen(user_dir)


def cmd_messages_list(args: argparse.Namespace) -> None:
    """List messages as JSON array with previews. No side effects."""
    atcha_dir, user_id, is_admin = _require_auth()

    # Admin must use --user to read a user's inbox
    if is_admin:
        if not _cli_user:
            if _cli_password:
                _error(
                    "--password authenticates as admin, not as a user",
                    fix="Use --user <id-or-name> to act on behalf of a user, or use a user token",
                )
            _error(
                "Admin token cannot be used for user operations",
                fix="Use --user <id-or-name> to act on behalf of a user, or use a user token",
            )
        # Resolve and verify the target agent exists
        resolved_id = _resolve_user(atcha_dir, _cli_user)
        if resolved_id is None:
            users = list(_iter_user_names(atcha_dir))
            _error(
                f"Agent '{_cli_user}' not found",
                available=users if users else None,
            )
        assert resolved_id is not None
        user_id = resolved_id
        user_dir = _get_user_dir(atcha_dir, user_id)
    else:
        if _cli_user:
            _error(
                "--user requires admin authentication",
                fix="Use --password or admin --token with --user",
            )
        user_dir = _get_user_dir(atcha_dir, user_id)

    # Determine if we should include 'to' field (only for admin impersonating)
    include_to_field = is_admin and _cli_user is not None

    inbox = user_dir / "mail" / "inbox.jsonl"

    if not inbox.exists() or inbox.stat().st_size == 0:
        print("[]")
        return

    # Parse filter options
    from_filter = T.cast(str | None, getattr(args, "from_user", None))
    thread_filter = T.cast(str | None, getattr(args, "thread", None))
    limit = T.cast(int | None, getattr(args, "limit", None))
    include_all = T.cast(bool, getattr(args, "all", False))
    no_preview = T.cast(bool, getattr(args, "no_preview", False))

    # Get last_read for unread filtering
    state_file = user_dir / "mail" / "state.json"
    last_read: str | None = None
    if not include_all and state_file.exists():
        state = T.cast(MailState, json.loads(state_file.read_text()))
        last_read = state.get("last_read")

    messages: list[dict[str, T.Any]] = []

    for line in inbox.read_text().splitlines():
        if not line.strip():
            continue
        try:
            msg = T.cast(Message, json.loads(line))
        except json.JSONDecodeError:
            continue

        # Filter by last_read (show only unread, unless --all)
        if last_read and msg["ts"] <= last_read:
            continue

        # Filter by --from
        if from_filter and msg["from"] != from_filter:
            continue

        # Filter by --thread
        if thread_filter and msg.get("thread_id") != thread_filter:
            continue

        # Prepare output
        if include_to_field:
            output: dict[str, T.Any] = dict(msg)
        else:
            output = {k: v for k, v in msg.items() if k != "to"}

        # Handle content/body field
        content = _get_message_content(msg)

        # Add preview or full content
        if no_preview:
            output["content"] = content
        else:
            # Truncate to 50 chars with ellipsis
            if len(content) > 50:
                output["preview"] = content[:50] + "..."
            else:
                output["preview"] = content

        # Remove old body field from output, we've handled it
        output.pop("body", None)
        if not no_preview:
            output.pop("content", None)

        messages.append(output)

        # Check limit
        if limit and len(messages) >= limit:
            break

    print(json.dumps(messages, indent=2))


def _find_message_by_id(atcha_dir: Path, user: str, msg_id: str) -> Message | None:
    """Find a message by ID in user's inbox or sent messages."""
    user_dir = _get_user_dir(atcha_dir, user)

    # Check inbox
    inbox_file = user_dir / "mail" / "inbox.jsonl"
    if inbox_file.exists():
        for line in inbox_file.read_text().splitlines():
            if not line.strip():
                continue
            try:
                msg = T.cast(Message, json.loads(line))
                if msg.get("id") == msg_id:
                    return msg
            except json.JSONDecodeError:
                continue

    # Check sent
    sent_file = user_dir / "mail" / "sent.jsonl"
    if sent_file.exists():
        for line in sent_file.read_text().splitlines():
            if not line.strip():
                continue
            try:
                msg = T.cast(Message, json.loads(line))
                if msg.get("id") == msg_id:
                    return msg
            except json.JSONDecodeError:
                continue

    return None


def _get_thread_participants(atcha_dir: Path, thread_id: str) -> list[str]:
    """Get all unique participants in a thread by searching all agent inboxes and sent logs."""
    participants: set[str] = set()

    users_dir = atcha_dir / "users"
    if not users_dir.exists():
        return []

    # Search all agent directories for messages in this thread
    for user_dir in users_dir.iterdir():
        if not user_dir.is_dir():
            continue

        # Check inbox
        inbox_file = user_dir / "mail" / "inbox.jsonl"
        if inbox_file.exists():
            for line in inbox_file.read_text().splitlines():
                if not line.strip():
                    continue
                try:
                    msg = T.cast(Message, json.loads(line))
                    if msg.get("thread_id") == thread_id:
                        # Add sender
                        if "from" in msg:
                            participants.add(msg["from"])
                        # Add recipients
                        if "to" in msg:
                            to_field = msg["to"]
                            if isinstance(to_field, list):
                                participants.update(to_field)
                            else:
                                participants.add(to_field)
                except json.JSONDecodeError:
                    continue

        # Check sent
        sent_file = user_dir / "mail" / "sent.jsonl"
        if sent_file.exists():
            for line in sent_file.read_text().splitlines():
                if not line.strip():
                    continue
                try:
                    msg = T.cast(Message, json.loads(line))
                    if msg.get("thread_id") == thread_id:
                        # Add sender
                        if "from" in msg:
                            participants.add(msg["from"])
                        # Add recipients
                        if "to" in msg:
                            to_field = msg["to"]
                            if isinstance(to_field, list):
                                participants.update(to_field)
                            else:
                                participants.add(to_field)
                except json.JSONDecodeError:
                    continue

    return sorted(participants)


def cmd_send(args: argparse.Namespace) -> None:
    """Send message."""
    atcha_dir, sender = _require_user()
    sender_dir = _get_user_dir(atcha_dir, sender)

    content = T.cast(str, args.content)
    recipient_ids = T.cast(list[str] | None, args.recipients)
    send_all = T.cast(bool, args.all)
    reply_to_id = T.cast(str | None, args.reply_to)

    # Validate recipient combinations
    if send_all and reply_to_id:
        _error(
            "Cannot use --all with --reply-to (ambiguous)",
            fix="Use '--reply-to MSG_ID' to reply to thread participants, or '--all' to broadcast to all contacts",
        )

    if not recipient_ids and not send_all and not reply_to_id:
        _error(
            "No recipients specified",
            fix="Use '--to NAME', '--all', or '--reply-to MSG_ID'",
        )

    # Determine final recipient list and thread context
    recipients: list[str] = []
    thread_id: str | None = None
    reply_to_msg: Message | None = None

    if reply_to_id:
        # Load the message we're replying to
        reply_to_msg = _find_message_by_id(atcha_dir, sender, reply_to_id)
        if reply_to_msg is None:
            _error(
                f"Message '{reply_to_id}' not found",
                fix="Check your inbox and sent messages for valid message IDs",
            )

        # Inherit thread_id from the message we're replying to
        thread_id = T.cast(str, reply_to_msg.get("thread_id") or reply_to_msg["id"])

        # Get thread participants (original sender + all recipients in thread)
        thread_participants = _get_thread_participants(atcha_dir, thread_id)

        if recipient_ids:
            # Explicit recipients with --to: validate they're in the thread
            for recip_id in recipient_ids:
                resolved = _resolve_user(atcha_dir, recip_id)
                if resolved is None:
                    users = list(_iter_user_names(atcha_dir))
                    _error(
                        f"Agent '{recip_id}' not found",
                        available=users if users else None,
                    )
                if resolved not in thread_participants:
                    _error(
                        f"Agent '{resolved}' is not in thread '{thread_id}'",
                        fix=f"Thread participants: {', '.join(thread_participants)}. Use '--to' without '--reply-to' to start a new thread.",
                    )
                recipients.append(resolved)
        else:
            # No --to: reply to all thread participants (excluding self)
            recipients = [p for p in thread_participants if p != sender]

    elif send_all:
        # Broadcast to all contacts (excluding self)
        all_agents = list(_iter_user_names(atcha_dir))
        recipients = [a for a in all_agents if a != sender]

    elif recipient_ids:
        # Explicit recipients: resolve each name/id
        for recip_id in recipient_ids:
            resolved = _resolve_user(atcha_dir, recip_id)
            if resolved is None:
                users = list(_iter_user_names(atcha_dir))
                _error(
                    f"Agent '{recip_id}' not found",
                    available=users if users else None,
                )
            recipients.append(resolved)

    # Remove duplicates while preserving order
    seen: set[str] = set()
    recipients = [r for r in recipients if r not in seen and not seen.add(r)]  # type: ignore

    if not recipients:
        _error(
            "No recipients after filtering",
            fix="Ensure you're not the only agent, or that thread has other participants",
        )

    # Construct message
    ts = _now_iso()
    msg_id = _generate_message_id(sender, ts)

    # Determine thread_id: inherit from reply-to, or start new thread
    if thread_id is None:
        thread_id = msg_id  # First message in thread: thread_id = id

    msg: Message = {
        "id": msg_id,
        "thread_id": thread_id,
        "from": sender,
        "to": recipients,
        "ts": ts,
        "type": "message",
        "content": content,
    }

    # Add reply_to field if replying
    if reply_to_id:
        msg["reply_to"] = reply_to_id

    line = json.dumps(msg, separators=(",", ":")) + "\n"

    # Write to each recipient's inbox
    for recipient in recipients:
        recipient_dir = _get_user_dir(atcha_dir, recipient)
        recipient_inbox = recipient_dir / "mail" / "inbox.jsonl"
        try:
            with open(recipient_inbox, "a") as f:
                _ = f.write(line)
        except OSError as e:
            _error(f"Failed to write to {recipient}'s inbox: {e}")

    # Write to sender sent log
    sender_sent = sender_dir / "mail" / "sent.jsonl"
    try:
        with open(sender_sent, "a") as f:
            _ = f.write(line)
    except OSError as e:
        print(f"WARNING: Message delivered but sent log failed: {e}", file=sys.stderr)

    # Update sender's last_seen timestamp
    _update_last_seen(sender_dir)

    print(json.dumps({"status": "delivered", "to": recipients, "count": len(recipients), "ts": msg["ts"]}))


# ---------------------------------------------------------------------------
# Env command (for hook discovery)
# ---------------------------------------------------------------------------


def cmd_env(_args: argparse.Namespace) -> None:
    """Auto-discover .atcha dir and print env exports."""
    atcha_dir = _get_atcha_dir()
    if atcha_dir is None:
        sys.exit(0)  # Silent - plugin inactive

    print(f'export ATCHA_DIR="{atcha_dir}"')


# ---------------------------------------------------------------------------
# CLI entry point (Task 5.1)
# ---------------------------------------------------------------------------


class Parsers(T.NamedTuple):
    """Container for parsers needed in dispatch."""

    main: argparse.ArgumentParser
    admin: argparse.ArgumentParser


def _build_parser() -> Parsers:
    """Build and return the argument parser with all subparsers."""
    parser = argparse.ArgumentParser(
        prog="atcha",
        description="Agent Team Chat 󰭹 -- Get in touch with other AI agents and humans on your team",
        epilog="Run 'atcha <command> --help' for command-specific help.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    sub = parser.add_subparsers(dest="command", required=False, metavar="<command>")

    # ---------- init (top-level) ----------
    init_parser = sub.add_parser(
        "init",
        help="Initialize workspace (first-time setup)",
        description="Initialize .atcha/ directory and set admin password. Prompts interactively if --password not provided.",
    )
    _ = init_parser.add_argument("--password", help="Admin password (prompts if not provided)")
    _ = init_parser.add_argument("--check", action="store_true", help="Check if initialized (exit 0 if yes, 1 if no)")

    # ---------- create-token (top-level) ----------
    create_token_parser = sub.add_parser(
        "create-token",
        help="Create user token (admin only)",
        description="Generate authentication token for a user. Requires admin password.",
    )
    _ = create_token_parser.add_argument("--password", help="Admin password (or set ATCHA_ADMIN_PASS)")
    _ = create_token_parser.add_argument("--user", required=True, help="User id or name")

    # ---------- contacts ----------
    contacts_parser = sub.add_parser(
        "contacts",
        help="Discover who is on your team",
        description="List all contacts or view a specific contact's profile. Excludes yourself by default.",
        epilog="Examples:\n  atcha contacts\n  atcha contacts maya\n  atcha contacts --include-self",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _ = contacts_parser.add_argument("name", nargs="?", help="Contact name to view (optional)")
    _ = contacts_parser.add_argument("--include-self", action="store_true", help="Include yourself in list")
    _ = contacts_parser.add_argument("--names-only", action="store_true", help="Only output names, one per line")
    _ = contacts_parser.add_argument("--tags", help="Filter by tags (comma-separated)")
    _ = contacts_parser.add_argument("--full", action="store_true", help="Include all fields (dates, empty values)")

    # ---------- admin ----------
    admin_parser = sub.add_parser(
        "admin",
        help="Administrative commands",
        description="Administrative commands for managing the atcha system.",
    )
    admin_sub = admin_parser.add_subparsers(dest="admin_command", required=False, metavar="<subcommand>")

    # admin password
    admin_password = admin_sub.add_parser(
        "password",
        help="Change admin password",
        description="Change the admin password.",
    )
    _ = admin_password.add_argument("--old", required=True, help="Current password")
    _ = admin_password.add_argument("--new", required=True, help="New password")

    # admin users
    admin_users = admin_sub.add_parser(
        "users",
        help="Manage users (admin only)",
        description="List all users or add new users. Requires admin auth.",
        epilog="Examples:\n  atcha admin users list\n  atcha admin users add --name maya-backend --role 'Backend Engineer'",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    admin_users_sub = admin_users.add_subparsers(dest="users_command", required=False, metavar="<subcommand>")

    # admin users list
    admin_users_list = admin_users_sub.add_parser(
        "list",
        help="List all users",
        description="List all users in the system.",
    )
    _ = admin_users_list.add_argument("--names-only", action="store_true", help="Only output user ids, one per line")
    _ = admin_users_list.add_argument("--tags", help="Filter by tags (comma-separated)")
    _ = admin_users_list.add_argument("--full", action="store_true", help="Include all fields (dates, empty values)")

    # admin users add
    admin_users_add = admin_users_sub.add_parser(
        "add",
        help="Add a new user",
        description="Create a new user account. The user's name IS their id (no role slug). Roles can only be updated by admins.",
        epilog="Examples:\n  atcha admin users add --name anna --role 'CLI Specialist'  # Creates user 'anna'\n  atcha admin users add --name maya --role 'Backend Engineer'  # Creates user 'maya'",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _ = admin_users_add.add_argument("--name", required=True, help="User name (becomes their id, e.g. 'anna')")
    _ = admin_users_add.add_argument("--role", required=True, help="User role (e.g. 'Backend Engineer', admin-only to update)")
    _ = admin_users_add.add_argument("--status", help="Initial status")
    _ = admin_users_add.add_argument("--tags", help="Comma-separated tags")
    _ = admin_users_add.add_argument("--about", help="About description")

    # admin hints
    _ = admin_sub.add_parser(
        "hints",
        help="Show helpful admin hints and reminders",
        description="Display environment variables, common tasks, and configuration reminders.",
    )

    # ---------- messages ----------
    messages_parser = sub.add_parser(
        "messages",
        help="Check and read messages",
        description="Check message summary or read full messages. Requires user token.",
        epilog="Examples:\n  atcha messages check\n  atcha messages read\n  atcha messages read --all",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _ = messages_parser.add_argument("--token", help="User token (or set $ATCHA_TOKEN)")
    _ = messages_parser.add_argument("--password", help="Admin password (requires --user)")
    _ = messages_parser.add_argument("--user", help="User id or name to act as (requires admin auth)")

    messages_sub = messages_parser.add_subparsers(dest="messages_command", metavar="<subcommand>")

    # messages check
    _ = messages_sub.add_parser(
        "check",
        help="Check messages summary",
        description="Show summary of unread messages.",
    )

    # messages read
    messages_read = messages_sub.add_parser(
        "read",
        help="Read messages and mark as read",
        description="Read all unread messages as JSONL and mark them as read.",
        epilog="Examples:\n  atcha messages read --from alice\n  atcha messages read --since 2026-01-30T12:00:00Z",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _ = messages_read.add_argument("ids", nargs="*", help="Message IDs to read (all unread if omitted)")
    _ = messages_read.add_argument("--since", help="Only messages after this ISO timestamp")
    _ = messages_read.add_argument("--from", dest="from_user", help="Only messages from this user")
    _ = messages_read.add_argument("--include-read", action="store_true", help="Include already-read messages")
    _ = messages_read.add_argument("--all", action="store_true", help="Alias for --include-read")
    _ = messages_read.add_argument("--no-mark", action="store_true", help="Don't mark messages as read")

    # messages list
    messages_list = messages_sub.add_parser(
        "list",
        help="List messages (no side effects)",
        description="List messages as JSON array with previews. Does NOT mark as read.",
        epilog="Examples:\n  atcha messages list\n  atcha messages list --limit 5\n  atcha messages list --no-preview",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _ = messages_list.add_argument("--from", dest="from_user", help="Filter by sender")
    _ = messages_list.add_argument("--thread", help="Filter by thread_id")
    _ = messages_list.add_argument("--limit", type=int, help="Max messages to return")
    _ = messages_list.add_argument("--all", action="store_true", help="Include read messages")
    _ = messages_list.add_argument("--no-preview", action="store_true", help="Show full content instead of preview")

    # ---------- send ----------
    send_parser = sub.add_parser(
        "send",
        help="Send message to contact(s)",
        description="Send a message to one or more agents. Requires user token.",
        epilog="Examples:\n  atcha send --to maya \"API is ready\"\n  atcha send --to maya --to alex \"Changes deployed\"\n  atcha send --all \"Standup at 10am\"\n  atcha send --reply-to msg-abc123 \"Agreed\"\n  atcha send --to maya --reply-to msg-abc123 \"Thanks\"",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _ = send_parser.add_argument("--token", help="User token (or set $ATCHA_TOKEN)")
    _ = send_parser.add_argument("--password", help="Admin password (requires --user)")
    _ = send_parser.add_argument("--user", help="User id or name to send as (requires admin auth)")
    _ = send_parser.add_argument("--to", action="append", dest="recipients", help="Recipient id or name (can be repeated)")
    _ = send_parser.add_argument("--all", action="store_true", help="Send to all contacts (broadcast)")
    _ = send_parser.add_argument("--reply-to", help="Message ID to reply to (inherits thread context)")
    _ = send_parser.add_argument("content", help="Message content")

    # ---------- profile ----------
    profile_parser = sub.add_parser(
        "profile",
        help="Update your profile so others know who you are",
        description="Update your profile fields. Requires user token.",
        epilog="Examples:\n  atcha profile update --status 'Working on auth'\n  atcha profile update --tags backend,api",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    profile_sub = profile_parser.add_subparsers(dest="profile_command", metavar="<subcommand>")

    # profile update
    profile_update = profile_sub.add_parser(
        "update",
        help="Update profile fields",
        description="Update your profile fields (or another user's with admin auth).",
    )
    _ = profile_update.add_argument("--token", help="User token (or set $ATCHA_TOKEN)")
    _ = profile_update.add_argument("--password", help="Admin password (for updating other users)")
    _ = profile_update.add_argument("--name", help="User id or name to update (default: self, requires admin for others)")
    _ = profile_update.add_argument("--status", help="Set status")
    _ = profile_update.add_argument("--role", help="Set role (admin only)")
    _ = profile_update.add_argument("--tags", help="Set tags (comma-separated)")
    _ = profile_update.add_argument("--about", help="Set about description")
    _ = profile_update.add_argument("--full", action="store_true", help="Include all fields in output")

    # ---------- whoami ----------
    whoami_parser = sub.add_parser(
        "whoami",
        help="Print your username",
        description="Print your username. Requires user token.",
    )
    _ = whoami_parser.add_argument("--token", help="User token (or set $ATCHA_TOKEN)")
    _ = whoami_parser.add_argument("--password", help="Admin password (requires --user)")
    _ = whoami_parser.add_argument("--user", help="User id or name to act as (requires admin auth)")

    # ---------- env (for hooks) ----------
    _ = sub.add_parser(
        "env",
        help="Print env exports for hooks",
        description="Auto-discover .atcha directory and print shell export statements.",
    )

    return Parsers(main=parser, admin=admin_parser)


def main() -> None:
    global _cli_token, _cli_password, _cli_user

    parsers = _build_parser()

    # ---------- Parse and dispatch ----------
    args = parsers.main.parse_args()

    # Set global auth from CLI if provided
    # Priority: --password > --token > ATCHA_TOKEN
    _cli_token = T.cast(str | None, getattr(args, "token", None))
    _cli_password = T.cast(str | None, getattr(args, "password", None))
    _cli_user = T.cast(str | None, getattr(args, "user", None))

    if args.command is None:
        parsers.main.print_help()
        sys.exit(0)

    command = T.cast(str, args.command)

    if command == "init":
        cmd_init(args)

    elif command == "create-token":
        cmd_create_token(args)

    elif command == "admin":
        admin_command = T.cast(str | None, args.admin_command)
        if admin_command is None:
            parsers.admin.print_help()
            sys.exit(0)
        admin_cmd_map: dict[str, T.Callable[[argparse.Namespace], None]] = {
            "password": cmd_admin_password,
            "users": cmd_admin_users,
            "hints": cmd_admin_hints,
        }
        admin_cmd_map[admin_command](args)

    elif command == "messages":
        cmd_messages(args)

    else:
        cmd_map: dict[str, T.Callable[[argparse.Namespace], None]] = {
            "contacts": cmd_contacts,
            "profile": cmd_profile,
            "send": cmd_send,
            "whoami": cmd_whoami,
            "env": cmd_env,
        }
        cmd_map[command](args)


if __name__ == "__main__":
    main()
