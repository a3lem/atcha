#!/usr/bin/env python
"""atcha: Token-authenticated messaging between parallel Claude Code sessions.

This CLI provides a hierarchical command structure with token-based authentication.
"""

from __future__ import annotations

import argparse
import dataclasses
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
USER_ID_PREFIX: T.Final[str] = "usr-"


# ---------------------------------------------------------------------------
# Type definitions
# ---------------------------------------------------------------------------


class AdminConfig(T.TypedDict):
    """Admin configuration stored in admin.json."""

    password_hash: str
    salt: str


class UserProfile(T.TypedDict):
    """User profile stored in profile.json.

    - id: Unique identifier (e.g., 'usr-a3k9m'), immutable
    - name: Short name (e.g., 'maya'), matches directory name, always unique
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


class MessagesState(T.TypedDict, total=False):
    """Message state stored in state.json."""

    last_read: str


# Message type - using dict to avoid TypedDict complexity with reserved keywords
Message = dict[str, T.Any]  # Fields: id, thread_id, reply_to (optional), from, from_space (optional), to, to_space (optional), ts, type, content


class SpaceConfig(T.TypedDict):
    """Space identity stored in space.json.

    - id: Unique immutable identifier (format: spc-{5-char})
    - name: Human-readable name, mutable, derived from directory at init
    - created: ISO timestamp of space creation
    """

    id: str
    name: str
    created: str


# Space ID prefix for disambiguation from user IDs
SPACE_ID_PREFIX: T.Final[str] = "spc-"


class FederatedSpace(T.TypedDict):
    """Entry in federation.local.json.

    - id: Space ID (copied from remote space.json at registration)
    - name: Space name (copied from remote space.json, updated on access)
    - path: Absolute path to the remote .atcha/ directory
    - added: ISO timestamp of when this space was registered
    """

    id: str
    name: str
    path: str
    added: str


class FederationConfig(T.TypedDict):
    """Federation registry stored in federation.local.json."""

    spaces: list[FederatedSpace]


# ---------------------------------------------------------------------------
# Auth context — replaces global mutable state for CLI auth
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class AuthContext:
    """Immutable auth context built once from parsed CLI args and env vars."""

    token: str | None
    password: str | None
    as_user: str | None  # --as-user <user-id>: act as this user (admin only, user commands only)
    json_output: bool  # whether --json was passed


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
# Directory structure helpers
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
            fix="Run 'atcha admin init' to initialize",
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
    """Resolve an identifier (user ID, directory name, or short name) to the directory name.

    Args:
        atcha_dir: Path to .atcha directory
        identifier: A user ID ('usr-a3k9m'), directory name ('maya'), or short name

    Returns:
        The directory name (username) if found, None otherwise.

    Raises:
        SystemExit if the short name matches multiple users (ambiguous).
    """
    users_dir = _get_users_dir(atcha_dir)
    if not users_dir.exists():
        return None

    # Try exact match on directory name (username)
    if (users_dir / identifier).is_dir():
        return identifier

    # If identifier is a user ID (usr-xxx), scan profiles to find the matching user
    if identifier.startswith(USER_ID_PREFIX):
        for user_dir in users_dir.iterdir():
            if not user_dir.is_dir():
                continue
            profile_path = user_dir / "profile.json"
            if profile_path.exists():
                profile = json.loads(profile_path.read_text())
                profile_id = profile.get("id")
                if profile_id is not None and profile_id == identifier:
                    return user_dir.name
        return None

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


def _validate_address_format(value: str) -> str:
    """Validate that a user reference is an address (name@, name@space) or user ID, not a bare name.

    Bare names are rejected because they're ambiguous -- could be local or cross-space.
    Returns the value unchanged if valid. Calls _error() if bare name.
    """
    if value.startswith(USER_ID_PREFIX):
        return value  # usr-xxxxx is always valid
    if "@" in value:
        return value  # name@ or name@space
    _error(
        f"bare name '{value}' is ambiguous",
        fix=f"use '{value}@' for local or '{value}@<space>' for cross-space",
    )


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
    messages_dir = user_dir / "messages"
    messages_dir.mkdir(exist_ok=True)
    for name in ("inbox.jsonl", "sent.jsonl"):
        f = messages_dir / name
        if not f.exists():
            f.touch()
    state = messages_dir / "state.json"
    if not state.exists():
        _ = state.write_text("{}\n")
    return user_dir


# ---------------------------------------------------------------------------
# Password hashing utilities
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
# Token management utilities
# ---------------------------------------------------------------------------

# Alphabet for token encoding (no ambiguous chars like 0/O, 1/l)
TOKEN_ALPHABET: T.Final[str] = "23456789abcdefghjkmnpqrstuvwxyz"


def _generate_user_id() -> str:
    """Generate a random user ID with usr- prefix.

    Uses the same alphabet as tokens (no ambiguous chars).
    Returns a string like 'usr-a3k9m' for use as immutable user identifier.
    """
    chars = "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(TOKEN_LENGTH))
    return f"{USER_ID_PREFIX}{chars}"


def _generate_space_id() -> str:
    """Generate a random space ID with spc- prefix.

    Uses the same alphabet as user IDs (no ambiguous chars).
    Format: spc-{5-char}, e.g., spc-a3k9m
    """
    chars = "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(TOKEN_LENGTH))
    return f"{SPACE_ID_PREFIX}{chars}"


def _derive_token(password: str, user_name: str, salt: str) -> str:
    """Derive a deterministic token from admin password and user name.

    Uses HMAC-SHA256 with the password as key, then encodes to TOKEN_LENGTH chars.
    Same password + user + salt always produces the same token.
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
# Auth context helpers
# ---------------------------------------------------------------------------


def _get_token(auth: AuthContext) -> str | None:
    """Get token from AuthContext or env var ($ATCHA_TOKEN)."""
    if auth.token:
        return auth.token
    return os.environ.get("ATCHA_TOKEN")


def _get_password(auth: AuthContext) -> str | None:
    """Get password from AuthContext or env var ($ATCHA_ADMIN_PASS)."""
    if auth.password:
        return auth.password
    return os.environ.get("ATCHA_ADMIN_PASS")


def _get_password_from_env() -> str | None:
    """Get admin password from $ATCHA_ADMIN_PASS environment variable."""
    return os.environ.get("ATCHA_ADMIN_PASS")


def _require_auth(auth: AuthContext) -> tuple[Path, str, bool]:
    """Validate auth from AuthContext or env, return (atcha_dir, user, is_admin). Exits on error.

    Priority: --password/ATCHA_ADMIN_PASS > --token/ATCHA_TOKEN
    """
    atcha_dir = _require_atcha_dir()

    # Check password first (admin auth)
    password = _get_password(auth)
    if password:
        _require_admin(atcha_dir, password)
        return atcha_dir, "_admin", True

    # Then check token (user auth)
    token = _get_token(auth)
    if not token:
        _error(
            "Cannot identify user — no token provided",
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
            fix="Run 'atcha admin init' first",
        )

    admin_config = T.cast(AdminConfig, json.loads(admin_file.read_text()))
    if not _verify_password(password, admin_config["password_hash"], admin_config["salt"]):
        _error("Invalid password")


def _require_user(auth: AuthContext) -> tuple[Path, str]:
    """Validate user token from env, return (atcha_dir, user_name). Exits on error.

    Supports --as-user for admin to act as a specific user.
    """
    atcha_dir, user_name, is_admin = _require_auth(auth)

    if is_admin:
        # Admin can act as another user with --as-user
        if auth.as_user:
            # --as-user requires a user ID (usr-xxx), not an address
            if not auth.as_user.startswith(USER_ID_PREFIX):
                _error(
                    "--as-user requires a user ID (usr-xxx), not an address",
                    fix="use the user ID, e.g. --as-user usr-xxxxx",
                )
            # Resolve and verify the target user exists
            user_id = _resolve_user(atcha_dir, auth.as_user)
            if user_id is None:
                users = list(_iter_user_names(atcha_dir))
                _error(
                    f"User '{auth.as_user}' not found",
                    available=users if users else None,
                )
            assert user_id is not None
            return atcha_dir, user_id

        # Admin without --as-user cannot use user commands
        if auth.password:
            _error(
                "--password authenticates as admin, not as a user",
                fix="Use --as-user <user-id> to act as a user, or use a user token",
            )
        _error(
            "Admin token cannot be used for user operations",
            fix="Use --as-user <user-id> to act as a user, or use a user token",
        )

    # Non-admin with --as-user is an error
    if auth.as_user:
        _error(
            "--as-user requires admin authentication",
            fix="Use --password with --as-user",
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


def _slugify_name(name: str) -> str:
    """Convert a directory name to a valid space handle.

    Handle format: [a-z0-9][a-z0-9-]{0,38}[a-z0-9] (2-40 chars, no leading/trailing dashes)

    Examples:
        'my-project' -> 'my-project'
        'My Project' -> 'my-project'
        'agent_team_mail' -> 'agent-team-mail'
    """
    slug = name.lower().strip()
    slug = re.sub(r'[\s_]+', '-', slug)  # Replace spaces/underscores with dashes
    slug = re.sub(r'[^a-z0-9-]', '', slug)  # Remove non-alphanumeric except dashes
    slug = re.sub(r'-+', '-', slug)  # Collapse multiple dashes
    slug = slug.strip('-')  # Remove leading/trailing dashes
    # Ensure minimum length
    if len(slug) < 2:
        slug = "space"
    # Truncate to max 40 chars
    if len(slug) > 40:
        slug = slug[:40].rstrip('-')
    return slug


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
# Space identity helpers (Federation)
# ---------------------------------------------------------------------------


def _load_space_config(atcha_dir: Path) -> SpaceConfig | None:
    """Load space.json if it exists."""
    space_file = atcha_dir / "space.json"
    if not space_file.exists():
        return None
    try:
        return T.cast(SpaceConfig, json.loads(space_file.read_text()))
    except (json.JSONDecodeError, OSError):
        return None


def _save_space_config(atcha_dir: Path, config: SpaceConfig) -> None:
    """Save space.json."""
    space_file = atcha_dir / "space.json"
    _ = space_file.write_text(json.dumps(config, indent=2) + "\n")


def _ensure_space_config(atcha_dir: Path) -> SpaceConfig:
    """Load or auto-create space.json for backward compatibility.

    For existing spaces without space.json (pre-federation), this auto-generates
    a space ID and derives a handle from the parent directory name.
    """
    config = _load_space_config(atcha_dir)
    if config is not None:
        # Validate space ID format
        space_id = config.get("id", "")
        if not space_id.startswith(SPACE_ID_PREFIX) or len(space_id) != len(SPACE_ID_PREFIX) + TOKEN_LENGTH:
            _error("corrupt space identity", fix="Regenerate space.json or restore from backup")
        return config

    # Auto-create for existing spaces (backward compatibility)
    space_name = _slugify_name(atcha_dir.parent.name)
    config = SpaceConfig(
        id=_generate_space_id(),
        name=space_name,
        created=_now_iso(),
    )
    _save_space_config(atcha_dir, config)
    return config


# ---------------------------------------------------------------------------
# Federation registry helpers
# ---------------------------------------------------------------------------


def _load_federation(atcha_dir: Path) -> FederationConfig:
    """Load federation.local.json, returns empty config if not exists."""
    federation_file = atcha_dir / "federation.local.json"
    if not federation_file.exists():
        return FederationConfig(spaces=[])
    try:
        data = json.loads(federation_file.read_text())
        return T.cast(FederationConfig, data)
    except (json.JSONDecodeError, OSError):
        return FederationConfig(spaces=[])


def _save_federation(atcha_dir: Path, config: FederationConfig) -> None:
    """Save federation.local.json."""
    federation_file = atcha_dir / "federation.local.json"
    _ = federation_file.write_text(json.dumps(config, indent=2) + "\n")


def _is_space_available(space: FederatedSpace) -> bool:
    """Check if federated space path is accessible."""
    return Path(space["path"]).is_dir()


def _find_space(federation: FederationConfig, identifier: str) -> FederatedSpace | None:
    """Find space by handle or ID in federation config."""
    for space in federation["spaces"]:
        if space["name"] == identifier or space["id"] == identifier:
            return space
    return None


# ---------------------------------------------------------------------------
# Cross-space address resolution (Federation)
# ---------------------------------------------------------------------------


def _parse_address(address: str) -> tuple[str, str | None]:
    """Parse 'name' or 'name@space' into (name, space_ref).

    Returns (name, None) for local addresses.
    Returns (name, space_ref) for cross-space addresses.
    """
    if "@" in address:
        name, space_ref = address.rsplit("@", 1)
        return name, space_ref
    return address, None


def _resolve_space(
    atcha_dir: Path, identifier: str
) -> tuple[Path, SpaceConfig] | None:
    """Resolve space handle or ID to (atcha_dir, space_config).

    Checks local space first, then federation.local.json.
    Returns None if not found or unavailable.
    """
    # Check local space first
    local_config = _load_space_config(atcha_dir)
    if local_config and (local_config["name"] == identifier or local_config["id"] == identifier):
        return atcha_dir, local_config

    # Check federated spaces
    federation = _load_federation(atcha_dir)
    federated = _find_space(federation, identifier)
    if federated:
        federated_path = Path(federated["path"])
        if federated_path.is_dir():
            federated_config = _load_space_config(federated_path)
            if federated_config:
                return federated_path, federated_config
    return None


def _resolve_user_cross_space(
    local_atcha_dir: Path, address: str
) -> tuple[str, Path, SpaceConfig] | None:
    """Resolve potentially cross-space address to (user_id, target_atcha_dir, space_config).

    For local addresses: resolves in local space, then checks federated spaces for ambiguity.
    For qualified addresses (name@space): resolves directly in specified space.

    Returns None if user not found. Exits with error if ambiguous.
    """
    name, space_ref = _parse_address(address)

    if space_ref:
        # Qualified address: name@space
        resolved = _resolve_space(local_atcha_dir, space_ref)
        if resolved is None:
            _error(
                f"unknown space: {space_ref}",
                fix="Check available spaces with 'atcha admin federated list'",
            )
        target_dir, space_config = resolved
        user_id = _resolve_user(target_dir, name)
        if user_id is None:
            _error(f"user not found: {name} in {space_config['name']}")
        return user_id, target_dir, space_config

    # Bare address: check local first, then federated
    local_config = _ensure_space_config(local_atcha_dir)
    local_user = _resolve_user(local_atcha_dir, name)

    # Check federated spaces for matches
    federation = _load_federation(local_atcha_dir)
    federated_matches: list[tuple[str, Path, SpaceConfig]] = []

    for space in federation["spaces"]:
        space_path = Path(space["path"])
        if not space_path.is_dir():
            continue
        space_config = _load_space_config(space_path)
        if not space_config:
            continue
        user_id = _resolve_user(space_path, name)
        if user_id:
            federated_matches.append((user_id, space_path, space_config))

    if local_user and not federated_matches:
        return local_user, local_atcha_dir, local_config
    elif federated_matches and not local_user:
        if len(federated_matches) == 1:
            return federated_matches[0]
        else:
            spaces = [m[2]["name"] for m in federated_matches]
            _error(
                f"ambiguous recipient: {name} exists in {', '.join(spaces)}",
                fix=f"Use {name}@<space> to specify",
            )
    elif local_user and federated_matches:
        all_spaces = [local_config["name"]] + [m[2]["name"] for m in federated_matches]
        _error(
            f"ambiguous recipient: {name} exists in {', '.join(all_spaces)}",
            fix=f"Use {name}@<space> to specify",
        )

    return None


def _find_space_by_id(federation: FederationConfig, space_id: str) -> FederatedSpace | None:
    """Find a federated space by its ID."""
    for space in federation["spaces"]:
        if space["id"] == space_id:
            return space
    return None


def _get_sender_name(msg: Message) -> str:
    """Extract sender name from message (handles both old and new formats)."""
    from_field = msg["from"]
    if isinstance(from_field, dict):
        return from_field["name"]
    return from_field


def _get_sender_space(msg: Message) -> str | None:
    """Extract sender space name from message (handles both old and new formats).

    Returns None if the message has no space info (local-only or old format).
    """
    from_field = msg["from"]
    if isinstance(from_field, dict):
        space_info = from_field.get("space")
        if space_info:
            return space_info.get("name")
    return None


def _match_sender_address(msg: Message, from_filter: str) -> bool:
    """Check if a message's sender matches an address filter.

    - 'name' (no @) -> matches any sender with that name (backward compatible)
    - 'name@space' -> matches only that name in that space
    - 'name@' (empty space) -> matches only that name when sender has no space info (local)
    """
    filter_name, filter_space = _parse_address(from_filter)
    sender_name = _get_sender_name(msg)

    if sender_name != filter_name:
        return False

    if filter_space is None:
        # Bare name: match any sender with that name
        return True

    # Qualified: match on space
    sender_space = _get_sender_space(msg)
    if filter_space == "":
        # name@ -> match only local (no space info)
        return sender_space is None
    return sender_space == filter_space


def _format_sender(
    msg: Message, local_space_id: str, federation: FederationConfig
) -> tuple[str, str | None]:
    """Format sender for display, adding @space suffix if cross-space.

    Returns (formatted_sender, warning) where warning is set if from_space is unknown.
    """
    from_field = msg["from"]

    # New format: from is a structured object
    if isinstance(from_field, dict):
        sender_name = from_field["name"]
        space_info = from_field.get("space")

        # No space info or local space: just show name
        if space_info is None or space_info.get("id") == local_space_id:
            return sender_name, None

        # Cross-space: show name@space_name
        space_name = space_info.get("name")
        if space_name:
            return f"{sender_name}@{space_name}", None

        # Fallback: use space ID if name not available
        space_id = space_info.get("id", "unknown")
        return f"{sender_name}@{space_id}", f"unknown space: {space_id}"

    # Old format: from is a string
    sender = from_field
    from_space = msg.get("from_space")

    # No from_space or local space: just show name
    if from_space is None or from_space == local_space_id:
        return sender, None

    # Look up space name in federation by ID
    space = _find_space_by_id(federation, from_space)
    if space:
        return f"{sender}@{space['name']}", None
    else:
        # Unknown space: show raw ID and return warning
        warning = f"unknown space: {from_space}"
        return f"{sender}@{from_space}", warning


# ---------------------------------------------------------------------------
# Admin commands
# ---------------------------------------------------------------------------


def cmd_status(auth: AuthContext) -> None:
    """Check if atcha is initialized."""
    existing_dir = _get_atcha_dir()
    if existing_dir is not None and (existing_dir / "admin.json").exists():
        if auth.json_output:
            print(json.dumps({"initialized": True}))
        else:
            print("Atcha initialized")
        sys.exit(0)
    else:
        if auth.json_output:
            print(json.dumps({"initialized": False}))
        sys.exit(1)


def cmd_init(args: argparse.Namespace, auth: AuthContext) -> None:
    """Initialize workspace (first-time setup)."""
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

    # Create space.json for federation support
    space_name = _slugify_name(atcha_dir.parent.name)
    space_config: SpaceConfig = {
        "id": _generate_space_id(),
        "name": space_name,
        "created": _now_iso(),
    }
    _save_space_config(atcha_dir, space_config)

    if auth.json_output:
        print(json.dumps({"status": "initialized", "path": str(atcha_dir)}))
    else:
        print(f"Initialized .atcha/ at {atcha_dir}")


def cmd_admin_password(auth: AuthContext, args: argparse.Namespace) -> None:
    """Change admin password. Uses standard auth (--password or env) for old password."""
    atcha_dir = _require_atcha_dir()

    # Authenticate with current password via standard auth mechanism
    password = _get_password(auth)
    if not password:
        _error("Admin password required", fix="Use --password <password> or set ATCHA_ADMIN_PASS")
    assert password is not None
    _require_admin(atcha_dir, password)

    new_password = T.cast(str | None, args.new)
    if not new_password:
        _error("New password required", fix="Use --new <password>")
    assert new_password is not None

    # Update password
    salt = _generate_salt()
    password_hash = _hash_password(new_password, salt)
    new_admin_config: AdminConfig = {
        "password_hash": password_hash,
        "salt": salt,
    }
    admin_file = atcha_dir / "admin.json"
    _ = admin_file.write_text(json.dumps(new_admin_config, indent=2) + "\n")

    if auth.json_output:
        print(json.dumps({"status": "updated"}))
    else:
        print("Password updated")


def cmd_admin_hints(auth: AuthContext) -> None:
    """Print helpful hints and reminders for admins."""
    hints = """# Atcha Admin Hints

## Environment Variables

| Variable | Purpose | Usage |
|----------|---------|-------|
| `ATCHA_DIR` | Path to `.atcha/` directory | Auto-discovered if not set. Override for shared setup across worktrees. |
| `ATCHA_TOKEN` | User authentication token | Set this to authenticate as a specific user. Get token with `atcha admin create-token`. |
| `ATCHA_ADMIN_PASS` | Admin password | Used for admin operations instead of tokens. Set once, use for all admin commands. |

## Common Admin Tasks

### Creating a New User
```bash
export ATCHA_ADMIN_PASS=your-password
atcha admin users create --name alice --role "Backend Engineer" --tags=backend,auth
```

### Getting a User's Token
```bash
atcha admin create-token --user alice
# Copy the token and share it with the user (or set in their .env)
```

### Listing All Users
```bash
atcha contacts --include-self          # JSON format
atcha contacts --include-self --names-only # Just names
```

### Updating Another User's Profile
```bash
atcha admin users update alice@ --status "On vacation" --password $ATCHA_ADMIN_PASS
```

## Directory Structure

```
.atcha/
\u251c\u2500\u2500 admin.json              # Admin password hash + salt
\u251c\u2500\u2500 tokens/
\u2502   \u2514\u2500\u2500 <user-name>         # User token hashes
\u2514\u2500\u2500 users/
    \u2514\u2500\u2500 <user-name>/
        \u251c\u2500\u2500 profile.json    # User profile
        \u2514\u2500\u2500 messages/
            \u251c\u2500\u2500 inbox.jsonl # Incoming messages
            \u251c\u2500\u2500 sent.jsonl  # Sent messages
            \u2514\u2500\u2500 state.json  # Read state
```

## Token Security

- Tokens are **deterministic**: Same password + user always produces the same token
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
| Change admin password | `atcha admin password --password <old> --new <new>` |
| Check initialization | `atcha admin status` |
| Create user token | `atcha admin create-token --user <name>` |
| View user profile | `atcha contacts <name>` |
| List all users | `atcha contacts --include-self` |
"""
    print(hints)



def cmd_admin_space_rename(auth: AuthContext, args: argparse.Namespace) -> None:
    """Rename the current space's name. Legacy entry point -- delegates to cmd_admin_spaces_update."""
    cmd_admin_spaces_update(auth, args)


def cmd_admin_spaces_update(auth: AuthContext, args: argparse.Namespace) -> None:
    """Update the current space's name and/or description."""
    atcha_dir = _require_atcha_dir()

    # Require admin auth
    password = _get_password(auth)
    if not password:
        _error("Admin password required", fix="Use --password or set ATCHA_ADMIN_PASS")
    assert password is not None
    _require_admin(atcha_dir, password)

    new_name = T.cast(str | None, getattr(args, "new_space_name", None))
    description = T.cast(str | None, getattr(args, "description", None))

    if new_name is None and description is None:
        _error("Nothing to update", fix="Use --name and/or --description")

    # Load current space config
    space_config = _ensure_space_config(atcha_dir)
    result: dict[str, str] = {"id": space_config["id"]}

    if new_name is not None:
        # Validate name format (same rules as user names)
        valid, err = _validate_username(new_name)
        if not valid:
            _error(f"Invalid name format: {err}")

        old_name = space_config["name"]
        space_config["name"] = new_name
        result["old_name"] = old_name
        result["new_name"] = new_name

    if description is not None:
        space_config["description"] = description  # type: ignore[typeddict-unknown-key]
        result["description"] = description

    _save_space_config(atcha_dir, space_config)
    result["status"] = "updated"
    print(json.dumps(result, indent=2))



def cmd_admin_federated_add(auth: AuthContext, args: argparse.Namespace) -> None:
    """Register a federated space.

    Reads remote space.json, copies id and handle, stores path.
    Detects handle collisions and requires --force to override.
    """
    atcha_dir = _require_atcha_dir()

    # Require admin auth
    password = _get_password(auth)
    if not password:
        _error("Admin password required", fix="Use --password or set ATCHA_ADMIN_PASS")
    assert password is not None
    _require_admin(atcha_dir, password)

    path_arg = T.cast(str, args.path)
    force = T.cast(bool, getattr(args, "force", False))

    # Resolve path: if it's a directory with .atcha/, use that; otherwise assume it IS the .atcha/ dir
    path = Path(path_arg).resolve()
    if not path.exists():
        _error(f"Path does not exist: {path}")

    # Check if path is a parent directory with .atcha/ inside
    if (path / ATCHA_DIR_NAME).is_dir():
        path = path / ATCHA_DIR_NAME
    elif not path.name == ATCHA_DIR_NAME:
        # Check if this directory contains admin.json (i.e., is an atcha dir)
        if not (path / "admin.json").exists():
            _error(
                f"Not a valid atcha space: {path}",
                fix=f"Provide path to .atcha/ directory or its parent",
            )

    # Read remote space.json
    remote_space_config = _load_space_config(path)
    if remote_space_config is None:
        _error(
            f"Not a valid atcha space: {path}",
            fix="The remote directory must have a space.json file. Run 'atcha init' there first.",
        )
    assert remote_space_config is not None

    remote_id = remote_space_config["id"]
    remote_name = remote_space_config["name"]

    # Validate space ID format
    if not remote_id.startswith(SPACE_ID_PREFIX) or len(remote_id) != len(SPACE_ID_PREFIX) + TOKEN_LENGTH:
        _error(f"Corrupt space identity in {path}", fix="Regenerate space.json in the remote space")

    # Load current federation config
    federation = _load_federation(atcha_dir)

    # Check if this space ID is already registered
    existing_by_id = _find_space(federation, remote_id)
    if existing_by_id:
        _error(
            f"Space already registered: {remote_id} ({existing_by_id['name']})",
            fix="Use 'admin federated remove' first to unregister",
        )

    # Check for handle collision
    existing_by_name = _find_space(federation, remote_name)
    if existing_by_name and not force:
        _error(
            f"Handle collision: '{remote_name}' already registered ({existing_by_name['id']})",
            fix="Use --force to add anyway, or rename one of the spaces",
        )

    # Check that we're not adding the local space
    local_space = _load_space_config(atcha_dir)
    if local_space and local_space["id"] == remote_id:
        _error(
            "Cannot add local space to federation",
            fix="The local space is always implicitly available",
        )

    # Add to federation
    new_space: FederatedSpace = {
        "id": remote_id,
        "name": remote_name,
        "path": str(path),
        "added": _now_iso(),
    }
    federation["spaces"].append(new_space)
    _save_federation(atcha_dir, federation)

    result = {
        "status": "added",
        "id": remote_id,
        "name": remote_name,
        "path": str(path),
    }
    print(json.dumps(result, indent=2))


def cmd_admin_federated_remove(auth: AuthContext, args: argparse.Namespace) -> None:
    """Unregister a federated space."""
    atcha_dir = _require_atcha_dir()

    # Require admin auth
    password = _get_password(auth)
    if not password:
        _error("Admin password required", fix="Use --password or set ATCHA_ADMIN_PASS")
    assert password is not None
    _require_admin(atcha_dir, password)

    identifier = T.cast(str, args.identifier)

    # Load federation config
    federation = _load_federation(atcha_dir)

    # Find the space
    space = _find_space(federation, identifier)
    if space is None:
        available = [s["name"] for s in federation["spaces"]]
        _error(
            f"Space not found: {identifier}",
            available=available if available else None,
            fix="Use 'admin federated list' to see registered spaces",
        )
    assert space is not None

    # Remove from federation
    federation["spaces"] = [s for s in federation["spaces"] if s["id"] != space["id"]]
    _save_federation(atcha_dir, federation)

    result = {
        "status": "removed",
        "id": space["id"],
        "name": space["name"],
    }
    print(json.dumps(result, indent=2))


def cmd_admin_federated_list(auth: AuthContext) -> None:
    """List federated spaces with availability status."""
    atcha_dir = _require_atcha_dir()

    # Load federation config
    federation = _load_federation(atcha_dir)

    # Build output with availability status
    output: list[dict[str, T.Any]] = []
    for space in federation["spaces"]:
        output.append({
            "id": space["id"],
            "name": space["name"],
            "path": space["path"],
            "available": _is_space_available(space),
        })

    print(json.dumps(output, indent=2))


def cmd_admin_users_list(auth: AuthContext) -> None:
    """List all users as JSON array (admin only).

    Iterates user directories and loads each profile, giving admins
    a quick overview of all registered users.
    """
    atcha_dir = _require_atcha_dir()

    password = _get_password(auth)
    if not password:
        _error("Admin password required", fix="Use --password or set ATCHA_ADMIN_PASS")
    assert password is not None
    _require_admin(atcha_dir, password)

    users_dir = _get_users_dir(atcha_dir)
    profiles: list[dict[str, T.Any]] = []
    if users_dir.is_dir():
        for user_name in sorted(_iter_user_names(atcha_dir)):
            user_dir = _get_user_dir(atcha_dir, user_name)
            profile = _load_profile(user_dir)
            if profile is not None:
                profiles.append(dict(profile.items()))

    print(json.dumps(profiles, indent=2))


def cmd_admin_users_update(auth: AuthContext, args: argparse.Namespace) -> None:
    """Update user profile with admin-only fields (name, role, status, about, tags).

    Unlike profile update (self-service), this accepts --name and --role
    and takes the user address as a positional argument.
    """
    atcha_dir = _require_atcha_dir()

    password = _get_password(auth)
    if not password:
        _error("Admin password required", fix="Use --password or set ATCHA_ADMIN_PASS")
    assert password is not None
    _require_admin(atcha_dir, password)

    address = T.cast(str, args.address)
    _validate_address_format(address)

    # Resolve user
    name_part, space_ref = _parse_address(address)
    if space_ref:
        # Cross-space admin update not supported
        _error("admin users update only works on local users")
    user_id = _resolve_user(atcha_dir, name_part)
    if user_id is None:
        users = list(_iter_user_names(atcha_dir))
        _error(
            f"User '{address}' not found",
            available=users if users else None,
        )
    assert user_id is not None

    user_dir = _get_user_dir(atcha_dir, user_id)
    profile = _load_profile(user_dir)
    if profile is None:
        _error(f"No profile found for '{user_id}'")
    assert profile is not None

    # Apply updates
    new_name = T.cast(str | None, getattr(args, "name", None))
    role = T.cast(str | None, getattr(args, "role", None))
    status = T.cast(str | None, getattr(args, "status", None))
    about = T.cast(str | None, getattr(args, "about", None))
    tags_str = T.cast(str | None, getattr(args, "tags", None))

    if new_name is not None:
        # Validate new name
        valid, err = _validate_username(new_name)
        if not valid:
            _error(f"Invalid name '{new_name}': {err}")
        # Check uniqueness
        existing = _resolve_user(atcha_dir, new_name)
        if existing is not None and existing != user_id:
            _error(f"Name '{new_name}' already exists")
        profile["name"] = new_name

    if role is not None:
        profile["role"] = role
    if status is not None:
        profile["status"] = status
    if about is not None:
        profile["about"] = about
    if tags_str is not None:
        profile["tags"] = [t.strip() for t in tags_str.split(",") if t.strip()]

    profile["updated"] = _now_iso()
    _save_profile(user_dir, profile)

    print(json.dumps(dict(profile.items()), indent=2))


def cmd_admin_users_delete(auth: AuthContext, args: argparse.Namespace) -> None:
    """Delete a user: remove their directory and token file.

    This is irreversible -- the user's messages and profile are permanently lost.
    """
    import shutil

    atcha_dir = _require_atcha_dir()

    password = _get_password(auth)
    if not password:
        _error("Admin password required", fix="Use --password or set ATCHA_ADMIN_PASS")
    assert password is not None
    _require_admin(atcha_dir, password)

    address = T.cast(str, args.address)
    _validate_address_format(address)

    name_part, space_ref = _parse_address(address)
    if space_ref:
        _error("admin users delete only works on local users")
    user_id = _resolve_user(atcha_dir, name_part)
    if user_id is None:
        users = list(_iter_user_names(atcha_dir))
        _error(
            f"User '{address}' not found",
            available=users if users else None,
        )
    assert user_id is not None

    # Remove user directory
    user_dir = _get_user_dir(atcha_dir, user_id)
    if user_dir.is_dir():
        shutil.rmtree(user_dir)

    # Remove token file
    token_file = _get_token_file(atcha_dir, user_id)
    if token_file.exists():
        token_file.unlink()

    result = {"status": "deleted", "user": user_id}
    print(json.dumps(result, indent=2))


def cmd_admin_spaces_list(auth: AuthContext) -> None:
    """List local space + federated spaces.

    Combines the local space identity with the federation registry
    into a single unified listing.
    """
    atcha_dir = _require_atcha_dir()

    password = _get_password(auth)
    if not password:
        _error("Admin password required", fix="Use --password or set ATCHA_ADMIN_PASS")
    assert password is not None
    _require_admin(atcha_dir, password)

    # Local space
    local_space = _ensure_space_config(atcha_dir)
    output: list[dict[str, T.Any]] = [
        {
            "id": local_space["id"],
            "name": local_space["name"],
            "scope": "local",
            "available": True,
        }
    ]

    # Federated spaces
    federation = _load_federation(atcha_dir)
    for space in federation["spaces"]:
        output.append({
            "id": space["id"],
            "name": space["name"],
            "path": space["path"],
            "scope": "federated",
            "available": _is_space_available(space),
        })

    print(json.dumps(output, indent=2))


def cmd_create_token(auth: AuthContext, args: argparse.Namespace) -> None:
    """Create user token (admin only).

    Derives the token deterministically from password + user name + salt.
    Same inputs always produce the same token. Stores only the hash.
    """
    atcha_dir = _require_atcha_dir()

    # Get password from auth context or env
    password = _get_password(auth)
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
            f"User '{identifier}' not found",
            fix="Create user with 'atcha admin users add'",
            available=users if users else None,
        )

    assert user_id is not None

    # Load salt from admin config
    admin_file = atcha_dir / "admin.json"
    admin_config = T.cast(AdminConfig, json.loads(admin_file.read_text()))
    salt = admin_config["salt"]

    # Derive token deterministically (same password + user + salt = same token)
    token = _derive_token(password, user_id, salt)

    # Store hash (idempotent - same token always produces same hash)
    _store_token_hash(atcha_dir, user_id, token)

    print(token)


def cmd_users_add(auth: AuthContext, args: argparse.Namespace) -> None:
    """Create user account."""
    atcha_dir, user, is_admin = _require_auth(auth)

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

    # Generate unique immutable id with usr- prefix
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
        "id": user_id,        # Random usr-XXXXX code (immutable, globally unique)
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
# User commands
# ---------------------------------------------------------------------------


def _compact_profile(
    profile: UserProfile,
    full: bool = False,
    show_last_seen_ago: bool = True,
    space_name: str | None = None,
    is_local: bool | None = None,
) -> dict[str, T.Any]:
    """Return profile dict, optionally compacted.

    When full=False (default): excludes dates and empty fields, but includes last_seen.
    When full=True: includes all fields.
    When show_last_seen_ago=True: adds last_seen_ago field with human-readable format.
    When space_name and is_local are provided: adds address and scope fields.
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

    # Add address and scope fields when space info is provided
    if space_name is not None and is_local is not None:
        name = profile["name"]
        if is_local:
            result["address"] = name
            result["scope"] = "local"
        else:
            result["address"] = f"{name}@{space_name}"
            result["scope"] = "federated"

    return result



def cmd_users_list(auth: AuthContext, args: argparse.Namespace) -> None:
    """List team users from local and federated spaces."""
    atcha_dir = _get_atcha_dir()
    if atcha_dir is None:
        print("[]")
        return

    # Check for duplicate names and error (only for local space)
    duplicates = _find_duplicate_names(atcha_dir)
    if duplicates:
        lines = [f"  name '{name}' used by: {', '.join(ids)}" for name, ids in duplicates.items()]
        _error(
            "Duplicate user names detected:\n" + "\n".join(lines),
            fix="User names must be unique. Rename users so each has a distinct name (first component of id)",
        )

    include_self = T.cast(bool, getattr(args, "include_self", False))
    full = T.cast(bool, getattr(args, "full", False))
    tags_filter = T.cast(str | None, getattr(args, "tags", None))
    tags_set = {t.strip() for t in tags_filter.split(",") if t.strip()} if tags_filter else None
    space_filter = T.cast(str | None, getattr(args, "space", None))

    # Determine if we should exclude self (default: yes, unless --include-self or admin)
    current_user: str | None = None
    is_admin = False
    token = _get_token(auth)
    if token:
        result = _validate_token(atcha_dir, token)
        if result:
            current_user, is_admin = result

    # Admin sees all; otherwise exclude self unless --include-self
    exclude_self = not is_admin and not include_self

    # Load local space config
    local_space = _ensure_space_config(atcha_dir)
    local_name = local_space["name"]

    # Load federation config
    federation = _load_federation(atcha_dir)

    # Track unavailable spaces for warning
    unavailable_spaces: list[tuple[str, str]] = []  # (handle, path)

    # Build list of (space_path, space_name, is_local) to iterate
    spaces_to_check: list[tuple[Path, str, bool]] = []

    # Check if we should include local space
    if space_filter is None or space_filter == local_name or space_filter == local_space["id"]:
        spaces_to_check.append((atcha_dir, local_name, True))

    # Check federated spaces
    for fed_space in federation["spaces"]:
        # If filtering by space, check if this matches
        if space_filter is not None:
            if fed_space["name"] != space_filter and fed_space["id"] != space_filter:
                continue

        space_path = Path(fed_space["path"])
        if not space_path.is_dir():
            unavailable_spaces.append((fed_space["name"], fed_space["path"]))
            continue

        # Refresh handle from remote space.json if available
        remote_config = _load_space_config(space_path)
        if remote_config:
            space_name = remote_config["name"]
        else:
            space_name = fed_space["name"]

        spaces_to_check.append((space_path, space_name, False))

    # If filtering by space and no matches found, check if it was an invalid filter
    if space_filter is not None and not spaces_to_check and not unavailable_spaces:
        available = [local_name] + [s["name"] for s in federation["spaces"]]
        _error(
            f"Unknown space: {space_filter}",
            available=available,
            fix="Use 'admin federated list' to see available spaces",
        )

    # List all profiles as JSON array
    profiles: list[dict[str, T.Any]] = []
    for space_path, space_name, is_local in spaces_to_check:
        for user_name in sorted(_iter_user_names(space_path)):
            if exclude_self and is_local and user_name == current_user:
                continue
            user_dir = _get_user_dir(space_path, user_name)
            profile = _load_profile(user_dir)
            if profile is None:
                continue
            if tags_set and not tags_set.intersection(profile.get("tags", [])):
                continue
            # Include address and scope for all users
            profiles.append(_compact_profile(profile, full=full, space_name=space_name, is_local=is_local))

    print(json.dumps(profiles, indent=2))

    # Print unavailable space warnings to stderr
    for handle, path in unavailable_spaces:
        print(f"WARNING: space unavailable: {handle} (path not found: {path})", file=sys.stderr)


def cmd_users_get(auth: AuthContext, args: argparse.Namespace) -> None:
    """View a specific user's profile.

    Supports cross-space lookup with name@space syntax.
    When a bare name matches users in multiple spaces, shows all matches.
    """
    atcha_dir = _get_atcha_dir()
    if atcha_dir is None:
        _error(".atcha directory not found")

    assert atcha_dir is not None
    identifier = T.cast(str, args.name)
    full = T.cast(bool, getattr(args, "full", False))
    space_filter = T.cast(str | None, getattr(args, "space", None))

    # Parse address for potential cross-space lookup
    name, space_ref = _parse_address(identifier)

    # If --space flag was provided, use it as the space_ref
    if space_filter and not space_ref:
        space_ref = space_filter

    # Load local space config
    local_space = _ensure_space_config(atcha_dir)
    local_name = local_space["name"]

    # Load federation config
    federation = _load_federation(atcha_dir)

    if space_ref:
        # Qualified address: name@space or --space filter
        resolved = _resolve_space(atcha_dir, space_ref)
        if resolved is None:
            available = [local_name] + [s["name"] for s in federation["spaces"]]
            _error(
                f"Unknown space: {space_ref}",
                available=available,
                fix="Use 'admin federated list' to see available spaces",
            )
        target_dir, space_config = resolved
        user_id = _resolve_user(target_dir, name)
        if user_id is None:
            users = list(_iter_user_names(target_dir))
            _error(
                f"User '{name}' not found in {space_config['name']}",
                available=users if users else None,
            )
        assert user_id is not None
        user_dir = _get_user_dir(target_dir, user_id)
        profile = _load_profile(user_dir)
        if profile is None:
            _error(f"No profile found for '{user_id}'")
        assert profile is not None
        is_local = (target_dir == atcha_dir)
        output = _compact_profile(profile, full=full, space_name=space_config["name"], is_local=is_local)
        print(json.dumps(output, indent=2))
        return

    # Bare name: collect matches across all spaces
    # Tuple: (user_id, space_path, space_name, profile, is_local)
    matches: list[tuple[str, Path, str, UserProfile, bool]] = []

    # Check local space first
    user_id = _resolve_user(atcha_dir, name)
    if user_id:
        user_dir = _get_user_dir(atcha_dir, user_id)
        profile = _load_profile(user_dir)
        if profile:
            matches.append((user_id, atcha_dir, local_name, profile, True))

    # Check federated spaces
    for fed_space in federation["spaces"]:
        space_path = Path(fed_space["path"])
        if not space_path.is_dir():
            continue

        # Refresh handle from remote space.json if available
        remote_config = _load_space_config(space_path)
        if remote_config:
            space_name = remote_config["name"]
        else:
            space_name = fed_space["name"]

        user_id = _resolve_user(space_path, name)
        if user_id:
            user_dir = _get_user_dir(space_path, user_id)
            profile = _load_profile(user_dir)
            if profile:
                matches.append((user_id, space_path, space_name, profile, False))

    if not matches:
        # No matches found anywhere
        users = list(_iter_user_names(atcha_dir))
        _error(
            f"User '{name}' not found",
            available=users if users else None,
        )

    if len(matches) == 1:
        # Single match - show profile with address and scope
        user_id, space_path, space_name, profile, is_local = matches[0]
        output = _compact_profile(profile, full=full, space_name=space_name, is_local=is_local)
        print(json.dumps(output, indent=2))
    else:
        # Multiple matches - show all with address and scope
        profiles_output: list[dict[str, T.Any]] = []
        for user_id, space_path, space_name, profile, is_local in matches:
            profiles_output.append(_compact_profile(profile, full=full, space_name=space_name, is_local=is_local))
        print(json.dumps(profiles_output, indent=2))


def cmd_whoami(auth: AuthContext, args: argparse.Namespace) -> None:
    """Print identity info. Default: address format (name@). --id: user ID. --name: bare name."""
    atcha_dir, user_name = _require_user(auth)
    show_id = T.cast(bool, getattr(args, "show_id", False))
    show_name = T.cast(bool, getattr(args, "show_name", False))

    # Load profile to get the user ID
    user_dir = _get_user_dir(atcha_dir, user_name)
    profile = _load_profile(user_dir)

    if show_id:
        user_id = profile["id"] if profile else user_name
        if auth.json_output:
            print(json.dumps({"id": user_id}))
        else:
            print(user_id)
    elif show_name:
        name = profile["name"] if profile else user_name
        if auth.json_output:
            print(json.dumps({"name": name}))
        else:
            print(name)
    else:
        # Default: address format (name@)
        name = profile["name"] if profile else user_name
        user_id = profile["id"] if profile else user_name
        address = f"{name}@"
        if auth.json_output:
            print(json.dumps({"address": address, "id": user_id, "name": name}))
        else:
            print(address)


def cmd_users_update(auth: AuthContext, args: argparse.Namespace) -> None:
    """Update a user's profile.

    Immutable fields: id, name
    Admin-only fields: role
    User-updatable fields: status, tags, about
    """
    # --as-user on profile update targets the user to update
    identifier = auth.as_user
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
        _, user_id, is_admin = _require_auth(auth)
    else:
        # Updating another user - requires admin
        _, _auth_user, is_admin = _require_auth(auth)
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
# Message commands
# ---------------------------------------------------------------------------


def cmd_profile(auth: AuthContext, args: argparse.Namespace) -> None:
    """Profile command - update user profile."""
    profile_command = T.cast(str | None, getattr(args, "profile_command", None))

    if profile_command == "update":
        cmd_users_update(auth, args)
    else:
        # Default: show own profile
        atcha_dir, user_id = _require_user(auth)
        full = T.cast(bool, getattr(args, "full", False))
        user_dir = _get_user_dir(atcha_dir, user_id)
        profile = _load_profile(user_dir)
        if profile is None:
            _error(f"No profile found for '{user_id}'")
        assert profile is not None
        output = _compact_profile(profile, full=full)
        print(json.dumps(output, indent=2))


def _get_message_content(msg: Message) -> str:
    """Get message content, with fallback for old 'body' field."""
    return T.cast(str, msg.get("content") or msg.get("body", ""))



def cmd_messages_check(auth: AuthContext) -> None:
    """Check inbox summary."""
    atcha_dir, user_name = _require_user(auth)

    user_dir = _get_user_dir(atcha_dir, user_name)
    inbox = user_dir / "messages" / "inbox.jsonl"

    if not inbox.exists() or inbox.stat().st_size == 0:
        if auth.json_output:
            print(json.dumps({"count": 0, "senders": {}}))
        else:
            print("No messages")
        return

    # Get last_read for unread filtering
    state_file = user_dir / "messages" / "state.json"
    last_read: str | None = None
    if state_file.exists():
        state = T.cast(MessagesState, json.loads(state_file.read_text()))
        last_read = state.get("last_read")

    # Load space info for cross-space sender formatting
    local_space = _ensure_space_config(atcha_dir)
    federation = _load_federation(atcha_dir)
    warnings: set[str] = set()

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
        # Format sender with space suffix if cross-space
        formatted_sender, warning = _format_sender(msg, local_space["id"], federation)
        if warning:
            warnings.add(warning)
        sender_counts[formatted_sender] = sender_counts.get(formatted_sender, 0) + 1

    if not messages:
        if auth.json_output:
            print(json.dumps({"count": 0, "senders": {}}))
        else:
            print("No messages")
        return

    count = len(messages)

    if auth.json_output:
        print(json.dumps({"count": count, "senders": sender_counts}))
    else:
        if count == 1:
            formatted_sender, warning = _format_sender(messages[0], local_space["id"], federation)
            if warning:
                warnings.add(warning)
            print(f"1 unread message from {formatted_sender}")
        else:
            breakdown = ", ".join(
                f"{cnt} from {sender}"
                for sender, cnt in sorted(sender_counts.items(), key=lambda x: -x[1])
            )
            print(f"{count} unread messages: {breakdown}")

    # Print warnings for unknown spaces
    for warning in sorted(warnings):
        print(f"WARNING: {warning}", file=sys.stderr)


def cmd_messages_read(auth: AuthContext, args: argparse.Namespace) -> None:
    """Read full messages, mark as read."""
    atcha_dir, user_id, is_admin = _require_auth(auth)

    # Admin must use --as-user to read a user's inbox
    if is_admin:
        if not auth.as_user:
            if auth.password:
                _error(
                    "--password authenticates as admin, not as a user",
                    fix="Use --as-user <user-id> to act as a user, or use a user token",
                )
            _error(
                "Admin token cannot be used for user operations",
                fix="Use --as-user <user-id> to act as a user, or use a user token",
            )
        # Resolve and verify the target user exists
        resolved_id = _resolve_user(atcha_dir, auth.as_user)
        if resolved_id is None:
            users = list(_iter_user_names(atcha_dir))
            _error(
                f"User '{auth.as_user}' not found",
                available=users if users else None,
            )
        assert resolved_id is not None
        user_id = resolved_id
        user_dir = _get_user_dir(atcha_dir, user_id)
    else:
        if auth.as_user:
            _error(
                "--as-user requires admin authentication",
                fix="Use --password with --as-user",
            )
        user_dir = _get_user_dir(atcha_dir, user_id)

    # Include 'to' field when admin is acting as another user (useful for debugging)
    include_to_field = is_admin and auth.as_user is not None

    inbox = user_dir / "messages" / "inbox.jsonl"

    if not inbox.exists() or inbox.stat().st_size == 0:
        if auth.json_output:
            print("[]")
        return  # Silent exit for non-json

    # Load space info for cross-space sender formatting
    local_space = _ensure_space_config(atcha_dir)
    federation = _load_federation(atcha_dir)
    warnings: set[str] = set()

    # Parse filter options
    no_mark = T.cast(bool, getattr(args, "no_mark", False))
    target_ids = T.cast(list[str], getattr(args, "ids", []))
    if not target_ids:
        _error("at least one message ID required")
    target_ids_set = set(target_ids)

    state_file = user_dir / "messages" / "state.json"

    latest_ts: str | None = None
    json_array_msgs: list[dict[str, T.Any]] = []

    for line in inbox.read_text().splitlines():
        if not line.strip():
            continue
        try:
            msg = T.cast(Message, json.loads(line))
        except json.JSONDecodeError:
            continue

        # Filter by requested IDs (always required)
        if msg.get("id") not in target_ids_set:
            continue

        # Track latest timestamp
        if latest_ts is None or msg["ts"] > latest_ts:
            latest_ts = msg["ts"]

        # Prepare output (exclude 'to' field unless admin acting as user)
        if include_to_field:
            output: dict[str, T.Any] = dict(msg)
        else:
            output = {k: v for k, v in msg.items() if k != "to"}

        # Format sender with @space suffix if cross-space
        formatted_sender, warning = _format_sender(msg, local_space["id"], federation)
        if warning:
            warnings.add(warning)
        output["from"] = formatted_sender

        if auth.json_output:
            json_array_msgs.append(output)
        else:
            print(json.dumps(output, separators=(",", ":")))

    if auth.json_output:
        print(json.dumps(json_array_msgs, indent=2))

    # Mark as read (unless --no-mark)
    if latest_ts is not None and not no_mark:
        state_data: MessagesState = {}
        if state_file.exists():
            state_data = T.cast(MessagesState, json.loads(state_file.read_text()))
        state_data["last_read"] = latest_ts
        _ = state_file.write_text(json.dumps(state_data) + "\n")

        # Update user's last_seen timestamp
        _update_last_seen(user_dir)

    # Print warnings for unknown spaces
    for warning in sorted(warnings):
        print(f"WARNING: {warning}", file=sys.stderr)


def cmd_messages_list(auth: AuthContext, args: argparse.Namespace) -> None:
    """List messages as JSON array with previews. No side effects."""
    atcha_dir, user_id, is_admin = _require_auth(auth)

    # Admin must use --as-user to list a user's messages
    if is_admin:
        if not auth.as_user:
            if auth.password:
                _error(
                    "--password authenticates as admin, not as a user",
                    fix="Use --as-user <user-id> to act as a user, or use a user token",
                )
            _error(
                "Admin token cannot be used for user operations",
                fix="Use --as-user <user-id> to act as a user, or use a user token",
            )
        # Resolve and verify the target user exists
        resolved_id = _resolve_user(atcha_dir, auth.as_user)
        if resolved_id is None:
            users = list(_iter_user_names(atcha_dir))
            _error(
                f"User '{auth.as_user}' not found",
                available=users if users else None,
            )
        assert resolved_id is not None
        user_id = resolved_id
        user_dir = _get_user_dir(atcha_dir, user_id)
    else:
        if auth.as_user:
            _error(
                "--as-user requires admin authentication",
                fix="Use --password with --as-user",
            )
        user_dir = _get_user_dir(atcha_dir, user_id)

    # Include 'to' field when admin is acting as another user (useful for debugging)
    include_to_field = is_admin and auth.as_user is not None

    inbox = user_dir / "messages" / "inbox.jsonl"

    if not inbox.exists() or inbox.stat().st_size == 0:
        print("[]")
        return

    # Load space info for cross-space sender formatting
    local_space = _ensure_space_config(atcha_dir)
    federation = _load_federation(atcha_dir)
    warnings: set[str] = set()

    # Parse filter options
    since_filter = T.cast(str | None, getattr(args, "since", None))
    from_filter = T.cast(str | None, getattr(args, "from_user", None))
    thread_filter = T.cast(str | None, getattr(args, "thread", None))
    limit = T.cast(int | None, getattr(args, "limit", None))
    include_read = T.cast(bool, getattr(args, "include_read", False))
    no_preview = T.cast(bool, getattr(args, "no_preview", False))

    # Get last_read for unread filtering
    state_file = user_dir / "messages" / "state.json"
    last_read: str | None = None
    if not include_read and state_file.exists():
        state = T.cast(MessagesState, json.loads(state_file.read_text()))
        last_read = state.get("last_read")

    messages: list[dict[str, T.Any]] = []

    for line in inbox.read_text().splitlines():
        if not line.strip():
            continue
        try:
            msg = T.cast(Message, json.loads(line))
        except json.JSONDecodeError:
            continue

        # Filter by last_read (show only unread, unless --include-read)
        if last_read and msg["ts"] <= last_read:
            continue

        # Filter by --since
        if since_filter and msg["ts"] <= since_filter:
            continue

        # Filter by --from
        if from_filter and not _match_sender_address(msg, from_filter):
            continue

        # Filter by --thread
        if thread_filter and msg.get("thread_id") != thread_filter:
            continue

        # Prepare output
        if include_to_field:
            output: dict[str, T.Any] = dict(msg)
        else:
            output = {k: v for k, v in msg.items() if k != "to"}

        # Format sender with @space suffix if cross-space
        formatted_sender, warning = _format_sender(msg, local_space["id"], federation)
        if warning:
            warnings.add(warning)
        output["from"] = formatted_sender

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

    # Print warnings for unknown spaces
    for warning in sorted(warnings):
        print(f"WARNING: {warning}", file=sys.stderr)


def _find_message_by_id(atcha_dir: Path, user: str, msg_id: str) -> Message | None:
    """Find a message by ID in user's inbox or sent messages."""
    user_dir = _get_user_dir(atcha_dir, user)

    # Check inbox
    inbox_file = user_dir / "messages" / "inbox.jsonl"
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
    sent_file = user_dir / "messages" / "sent.jsonl"
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
    """Get all unique participants in a thread by searching all user inboxes and sent logs."""
    participants: set[str] = set()

    users_dir = atcha_dir / "users"
    if not users_dir.exists():
        return []

    # Search all user directories for messages in this thread
    for user_dir in users_dir.iterdir():
        if not user_dir.is_dir():
            continue

        # Check inbox
        inbox_file = user_dir / "messages" / "inbox.jsonl"
        if inbox_file.exists():
            for line in inbox_file.read_text().splitlines():
                if not line.strip():
                    continue
                try:
                    msg = T.cast(Message, json.loads(line))
                    if msg.get("thread_id") == thread_id:
                        # Add sender
                        if "from" in msg:
                            participants.add(_get_sender_name(msg))
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
        sent_file = user_dir / "messages" / "sent.jsonl"
        if sent_file.exists():
            for line in sent_file.read_text().splitlines():
                if not line.strip():
                    continue
                try:
                    msg = T.cast(Message, json.loads(line))
                    if msg.get("thread_id") == thread_id:
                        # Add sender
                        if "from" in msg:
                            participants.add(_get_sender_name(msg))
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


def cmd_send(auth: AuthContext, args: argparse.Namespace) -> None:
    """Send message (local or cross-space)."""
    atcha_dir, sender = _require_user(auth)
    sender_dir = _get_user_dir(atcha_dir, sender)

    # Get sender's profile for their ID
    sender_profile = _load_profile(sender_dir)
    if sender_profile is None:
        _error(f"Could not load profile for sender '{sender}'")
    assert sender_profile is not None
    sender_id = sender_profile["id"]

    # Get local space config for from field
    local_space = _ensure_space_config(atcha_dir)

    content = T.cast(str, args.content)
    recipient_ids = T.cast(list[str] | None, args.recipients)
    send_broadcast = T.cast(bool, args.broadcast)
    reply_to_id = T.cast(str | None, args.reply_to)

    # Validate recipient combinations
    if send_broadcast and reply_to_id:
        _error(
            "Cannot use --broadcast with --reply-to (ambiguous)",
            fix="Use '--reply-to MSG_ID' to reply to thread participants, or '--broadcast' to broadcast to all contacts",
        )

    if not recipient_ids and not send_broadcast and not reply_to_id:
        _error(
            "No recipients specified",
            fix="Use '--to NAME', '--broadcast', or '--reply-to MSG_ID'",
        )

    # Resolved recipient: (user_id, target_atcha_dir, space_config, is_cross_space)
    resolved_recipients: list[tuple[str, Path, SpaceConfig, bool]] = []
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
        # Note: For now, thread participants are local-only. Cross-space thread support is future work.
        thread_participants = _get_thread_participants(atcha_dir, thread_id)

        if recipient_ids:
            # Explicit recipients with --to: validate they're in the thread
            for recip_id in recipient_ids:
                resolved = _resolve_user(atcha_dir, recip_id)
                if resolved is None:
                    users = list(_iter_user_names(atcha_dir))
                    _error(
                        f"User '{recip_id}' not found",
                        available=users if users else None,
                    )
                if resolved not in thread_participants:
                    _error(
                        f"User '{resolved}' is not in thread '{thread_id}'",
                        fix=f"Thread participants: {', '.join(thread_participants)}. Use '--to' without '--reply-to' to start a new thread.",
                    )
                # For reply-to, we only support local recipients for now
                resolved_recipients.append((resolved, atcha_dir, local_space, False))
        else:
            # No --to: reply to all thread participants (excluding self)
            for p in thread_participants:
                if p != sender:
                    resolved_recipients.append((p, atcha_dir, local_space, False))

    elif send_broadcast:
        # Broadcast to all contacts (excluding self) - local only
        all_users = list(_iter_user_names(atcha_dir))
        for a in all_users:
            if a != sender:
                resolved_recipients.append((a, atcha_dir, local_space, False))

    elif recipient_ids:
        # Explicit recipients: resolve each name/id, potentially cross-space
        for recip_addr in recipient_ids:
            resolved = _resolve_user_cross_space(atcha_dir, recip_addr)
            if resolved is None:
                users = list(_iter_user_names(atcha_dir))
                _error(
                    f"User '{recip_addr}' not found",
                    available=users if users else None,
                )
            user_id, target_dir, space_config = resolved
            is_cross_space = space_config["id"] != local_space["id"]

            # Check if cross-space target is available
            if is_cross_space and not target_dir.is_dir():
                _error(
                    f"space unavailable: {space_config['name']} (path not found: {target_dir})",
                    fix="Re-register the space with correct path using 'admin federated add'",
                )

            resolved_recipients.append((user_id, target_dir, space_config, is_cross_space))

    # Remove duplicates while preserving order (by user_id + space_id)
    seen: set[tuple[str, str]] = set()
    unique_recipients: list[tuple[str, Path, SpaceConfig, bool]] = []
    for r in resolved_recipients:
        key = (r[0], r[2]["id"])  # (user_id, space_id)
        if key not in seen:
            seen.add(key)
            unique_recipients.append(r)
    resolved_recipients = unique_recipients

    if not resolved_recipients:
        _error(
            "No recipients after filtering",
            fix="Ensure you're not the only user, or that thread has other participants",
        )

    # Construct message
    ts = _now_iso()
    msg_id = _generate_message_id(sender, ts)

    # Determine thread_id: inherit from reply-to, or start new thread
    if thread_id is None:
        thread_id = msg_id  # First message in thread: thread_id = id

    # Build recipient names list for the message (just user names, without @space)
    recipient_names = [r[0] for r in resolved_recipients]

    # Build structured sender info (stores both names and IDs for durability)
    sender_address = f"{sender}@{local_space['name']}"
    base_msg: Message = {
        "id": msg_id,
        "thread_id": thread_id,
        "from": {
            "name": sender,
            "id": sender_id,
            "address": sender_address,
            "space": {
                "name": local_space["name"],
                "id": local_space["id"],
            },
        },
        "to": recipient_names,
        "ts": ts,
        "type": "message",
        "content": content,
    }

    # Add reply_to field if replying
    if reply_to_id:
        base_msg["reply_to"] = reply_to_id

    # Write to each recipient's inbox
    for user_id, target_dir, space_config, is_cross_space in resolved_recipients:
        # For cross-space messages, add to_space field
        msg = dict(base_msg)
        if is_cross_space:
            msg["to_space"] = space_config["id"]

        line = json.dumps(msg, separators=(",", ":")) + "\n"

        recipient_user_dir = _get_user_dir(target_dir, user_id)
        recipient_inbox = recipient_user_dir / "messages" / "inbox.jsonl"
        try:
            with open(recipient_inbox, "a") as f:
                _ = f.write(line)
        except OSError as e:
            space_suffix = f"@{space_config['name']}" if is_cross_space else ""
            _error(f"Failed to write to {user_id}{space_suffix}'s inbox: {e}")

    # Write to sender sent log (use base message without to_space for sent log)
    sent_line = json.dumps(base_msg, separators=(",", ":")) + "\n"
    sender_sent = sender_dir / "messages" / "sent.jsonl"
    try:
        with open(sender_sent, "a") as f:
            _ = f.write(sent_line)
    except OSError as e:
        print(f"WARNING: Message delivered but sent log failed: {e}", file=sys.stderr)

    # Update sender's last_seen timestamp
    _update_last_seen(sender_dir)

    print(json.dumps({"status": "delivered", "to": recipient_names, "count": len(resolved_recipients), "ts": base_msg["ts"]}))


# ---------------------------------------------------------------------------
# Env command (for hook discovery)
# ---------------------------------------------------------------------------


def cmd_env(_auth: AuthContext) -> None:
    """Auto-discover .atcha dir and print env exports."""
    atcha_dir = _get_atcha_dir()
    if atcha_dir is None:
        sys.exit(0)  # Silent - plugin inactive

    print(f'export ATCHA_DIR="{atcha_dir}"')


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


class Parsers(T.NamedTuple):
    """Container for parsers needed in dispatch."""

    main: argparse.ArgumentParser
    admin: argparse.ArgumentParser


def _build_parser() -> Parsers:
    """Build the argument parser with the new 'bare plural = list, subcommand = verb' convention.

    Convention: every plural noun lists when invoked bare, verb subcommands for other actions.
    """
    # Base auth: --password, --token, --json (shared by all commands)
    base_auth = argparse.ArgumentParser(add_help=False)
    _ = base_auth.add_argument("--token", help="User token (or set $ATCHA_TOKEN)")
    _ = base_auth.add_argument("--password", help="Admin password (or set ATCHA_ADMIN_PASS)")
    _ = base_auth.add_argument("--json", action="store_true", dest="json_output", help="Output in JSON format")

    # User auth: adds --as-user (only meaningful on user commands like messages, send, profile)
    user_auth = argparse.ArgumentParser(add_help=False, parents=[base_auth])
    _ = user_auth.add_argument("--as-user", dest="as_user", help="Act as USER (requires admin auth). USER is a user ID, e.g. usr-a3k9m")

    parser = argparse.ArgumentParser(
        prog="atcha",
        description="Atcha -- Get in touch with other users on your team\n\nConvention: bare plural = list, subcommand = verb",
        epilog="Run 'atcha <command> --help' for command-specific help.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _ = parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    sub = parser.add_subparsers(dest="command", required=False, metavar="<command>")

    # ---------- contacts (bare = list) ----------
    contacts_parser = sub.add_parser(
        "contacts",
        help="List contacts (bare = list, 'show' = view one)",
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
        help="List messages (bare = list, 'check'/'read' = subcommands)",
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

    messages_sub = messages_parser.add_subparsers(dest="messages_command", metavar="<subcommand>")

    # messages check
    _ = messages_sub.add_parser(
        "check",
        help="Check inbox summary (count + senders)",
        description="Show summary of unread messages without marking as read.",
    )

    # messages read <msg-id> [msg-id...]
    messages_read = messages_sub.add_parser(
        "read",
        help="Read specific messages and mark as read",
        description="Read specified messages and mark them as read.",
        epilog="Examples:\n  atcha messages read msg-abc123\n  atcha messages read msg-abc123 msg-def456",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _ = messages_read.add_argument("ids", nargs="+", help="Message IDs to read (at least one required)")
    _ = messages_read.add_argument("--no-mark", action="store_true", help="Don't mark messages as read")

    # ---------- send ----------
    send_parser = sub.add_parser(
        "send",
        help="Send message to contact(s)",
        description="Send a message to one or more users. Requires user token.",
        epilog="Examples:\n  atcha send --to maya@ \"API is ready\"\n  atcha send --to maya@ --to alex@ \"Changes deployed\"\n  atcha send --broadcast \"Standup at 10am\"",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[user_auth],
    )
    _ = send_parser.add_argument("--to", action="append", dest="recipients", help="Recipient address (can be repeated)")
    _ = send_parser.add_argument("--broadcast", action="store_true", help="Send to all contacts (broadcast)")
    _ = send_parser.add_argument("--reply-to", help="Message ID to reply to (inherits thread context)")
    _ = send_parser.add_argument("content", help="Message content")

    # ---------- profile (bare = show self) ----------
    profile_parser = sub.add_parser(
        "profile",
        help="View or update your profile",
        description="View your own profile, or update profile fields. Requires user token.",
        epilog="Examples:\n  atcha profile\n  atcha profile update --status 'Working on auth'",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[user_auth],
    )
    _ = profile_parser.add_argument("--full", action="store_true", help="Include all fields (dates, empty values)")
    profile_sub = profile_parser.add_subparsers(dest="profile_command", metavar="<subcommand>")

    # profile update (no --role or --name -- those are admin-only via admin users update)
    profile_update = profile_sub.add_parser(
        "update",
        help="Update self-service profile fields",
        description="Update your profile fields (status, about, tags). Admin-only fields (name, role) use 'admin users update'.",
        parents=[user_auth],
    )
    _ = profile_update.add_argument("--status", help="Set status")
    _ = profile_update.add_argument("--tags", help="Set tags (comma-separated)")
    _ = profile_update.add_argument("--about", help="Set about description")
    _ = profile_update.add_argument("--full", action="store_true", help="Include all fields in output")

    # ---------- whoami ----------
    whoami_parser = sub.add_parser(
        "whoami",
        help="Print your identity (default: address format)",
        description="Print your identity. Default: address format (name@). --id: user ID. --name: bare name.",
        parents=[user_auth],
    )
    whoami_group = whoami_parser.add_mutually_exclusive_group()
    _ = whoami_group.add_argument("--id", action="store_true", dest="show_id", help="Print user ID (usr-xxx)")
    _ = whoami_group.add_argument("--name", action="store_true", dest="show_name", help="Print bare name")

    # ---------- admin ----------
    admin_parser = sub.add_parser(
        "admin",
        help="Administrative commands",
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
        help="Create user token (admin only)",
        description="Generate authentication token for a user.",
        parents=[base_auth],
    )
    _ = admin_create_token.add_argument("--user", required=True, help="User address (e.g. maya@)")

    # admin users (bare = list)
    admin_users = admin_sub.add_parser(
        "users",
        help="Manage users (bare = list all)",
        description="List all users, or create/update/delete users.",
        parents=[base_auth],
    )
    admin_users_sub = admin_users.add_subparsers(dest="users_command", required=False, metavar="<subcommand>")

    # admin users create (renamed from 'add')
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

    # admin users update <address>
    admin_users_update = admin_users_sub.add_parser(
        "update",
        help="Update a user (admin-only fields: name, role)",
        description="Update a user's profile including admin-only fields.",
        parents=[base_auth],
    )
    _ = admin_users_update.add_argument("address", help="User address (e.g. maya@)")
    _ = admin_users_update.add_argument("--name", help="New name")
    _ = admin_users_update.add_argument("--role", help="New role")
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

    # admin spaces (bare = list)
    admin_spaces = admin_sub.add_parser(
        "spaces",
        help="Manage spaces (bare = list all)",
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

    return Parsers(main=parser, admin=admin_parser)


def main() -> None:
    parsers = _build_parser()

    # ---------- Parse and dispatch ----------
    args = parsers.main.parse_args()

    # Build auth context from parsed args (replaces globals)
    auth = AuthContext(
        token=T.cast(str | None, getattr(args, "token", None)),
        password=T.cast(str | None, getattr(args, "password", None)),
        as_user=T.cast(str | None, getattr(args, "as_user", None)),
        json_output=T.cast(bool, getattr(args, "json_output", False)),
    )

    if args.command is None:
        parsers.main.print_help()
        sys.exit(0)

    command = T.cast(str, args.command)

    # --- contacts ---
    if command == "contacts":
        contacts_sub = T.cast(str | None, getattr(args, "contacts_command", None))
        if contacts_sub == "show":
            cmd_users_get(auth, args)
        else:
            # bare 'contacts' = list
            cmd_users_list(auth, args)

    # --- messages ---
    elif command == "messages":
        msg_sub = T.cast(str | None, getattr(args, "messages_command", None))
        if msg_sub == "check":
            cmd_messages_check(auth)
        elif msg_sub == "read":
            cmd_messages_read(auth, args)
        else:
            # bare 'messages' = list
            cmd_messages_list(auth, args)

    # --- send ---
    elif command == "send":
        cmd_send(auth, args)

    # --- profile ---
    elif command == "profile":
        cmd_profile(auth, args)

    # --- whoami ---
    elif command == "whoami":
        cmd_whoami(auth, args)

    # --- admin ---
    elif command == "admin":
        admin_command = T.cast(str | None, getattr(args, "admin_command", None))
        if admin_command is None:
            parsers.admin.print_help()
            sys.exit(0)

        if admin_command == "status":
            quiet = T.cast(bool, getattr(args, "quiet", False))
            if quiet:
                # Exit code only — no output
                existing_dir = _get_atcha_dir()
                if existing_dir is not None and (existing_dir / "admin.json").exists():
                    sys.exit(0)
                else:
                    sys.exit(1)
            else:
                cmd_status(auth)
        elif admin_command == "init":
            cmd_init(args, auth)
        elif admin_command == "envs":
            cmd_env(auth)
        elif admin_command == "password":
            cmd_admin_password(auth, args)
        elif admin_command == "create-token":
            cmd_create_token(auth, args)
        elif admin_command == "hints":
            cmd_admin_hints(auth)

        elif admin_command == "users":
            users_sub = T.cast(str | None, getattr(args, "users_command", None))
            if users_sub == "create":
                cmd_users_add(auth, args)
            elif users_sub == "update":
                cmd_admin_users_update(auth, args)
            elif users_sub == "delete":
                cmd_admin_users_delete(auth, args)
            else:
                # bare 'admin users' = list
                cmd_admin_users_list(auth)

        elif admin_command == "spaces":
            spaces_sub = T.cast(str | None, getattr(args, "spaces_command", None))
            if spaces_sub == "update":
                cmd_admin_spaces_update(auth, args)
            elif spaces_sub == "add":
                cmd_admin_federated_add(auth, args)
            elif spaces_sub == "drop":
                cmd_admin_federated_remove(auth, args)
            else:
                # bare 'admin spaces' = list
                cmd_admin_spaces_list(auth)


if __name__ == "__main__":
    main()
