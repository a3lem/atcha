#!/usr/bin/env python
"""team-mail: Token-authenticated messaging between parallel Claude Code sessions.

This CLI provides a hierarchical command structure with token-based authentication.

Commands:
  init                          Initialize workspace (first-time setup)
  create-token --agent <name>   Create agent token (admin only)

  admin password                Change admin password

  team                          List all agents
  profile                       View own profile (requires token)
  profile <name>                View someone's profile (public)
  profile update [options]      Update own profile (requires token)

  inbox                         Check inbox summary
  inbox read                    Read full messages, mark as read
  send <to> <body>              Send message
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
    """Agent profile stored in profile.json.

    - id: Full identifier (e.g., 'maya-backend-engineer'), matches directory name
    - name: Short name (e.g., 'maya'), first component of id, always unique
    """

    id: str
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
            fix="Run 'team-mail init' to initialize",
        )
    assert team_mail_dir is not None
    return team_mail_dir


def _ensure_team_mail_dir() -> Path:
    """Create .team-mail directory structure. Returns the directory path."""
    team_mail_dir = Path.cwd() / TEAM_MAIL_DIR_NAME
    team_mail_dir.mkdir(exist_ok=True)
    (team_mail_dir / "tokens").mkdir(exist_ok=True)
    (team_mail_dir / "agents").mkdir(exist_ok=True)
    return team_mail_dir


def _get_agents_dir(team_mail_dir: Path) -> Path:
    """Get the agents directory."""
    return team_mail_dir / "agents"


def _get_agent_dir(team_mail_dir: Path, agent_id: str) -> Path:
    """Get a specific agent's directory by id."""
    return _get_agents_dir(team_mail_dir) / agent_id


def _extract_name(agent_id: str) -> str:
    """Extract short name from agent id.

    The name is the first component before any dash followed by a role.
    E.g., 'maya-backend-engineer' -> 'maya'
    """
    return agent_id.split("-")[0]


def _resolve_agent(team_mail_dir: Path, identifier: str) -> str | None:
    """Resolve an identifier (id or name) to the full agent id.

    Args:
        team_mail_dir: Path to .team-mail directory
        identifier: Either a full id ('maya-backend-engineer') or short name ('maya')

    Returns:
        The full agent id if found, None otherwise.

    Raises:
        SystemExit if the short name matches multiple agents (ambiguous).
    """
    agents_dir = _get_agents_dir(team_mail_dir)
    if not agents_dir.exists():
        return None

    # First, try exact match on id (directory name)
    if (agents_dir / identifier).is_dir():
        return identifier

    # Otherwise, try to match on name (first component)
    matches: list[str] = []
    for agent_dir in agents_dir.iterdir():
        if agent_dir.is_dir():
            agent_id = agent_dir.name
            if _extract_name(agent_id) == identifier:
                matches.append(agent_id)

    if len(matches) == 1:
        return matches[0]
    elif len(matches) > 1:
        _error(
            f"Name '{identifier}' matches multiple agents: {', '.join(matches)}",
            fix="Agent names must be unique. This indicates a data inconsistency - rename one of the agents",
        )

    return None


def _is_name_unique(team_mail_dir: Path, name: str, exclude_id: str | None = None) -> bool:
    """Check if a short name is unique among all agents.

    Args:
        team_mail_dir: Path to .team-mail directory
        name: The short name to check
        exclude_id: Optional agent id to exclude from the check (for updates)

    Returns:
        True if the name is unique, False otherwise.
    """
    agents_dir = _get_agents_dir(team_mail_dir)
    if not agents_dir.exists():
        return True

    for agent_dir in agents_dir.iterdir():
        if agent_dir.is_dir():
            agent_id = agent_dir.name
            if exclude_id and agent_id == exclude_id:
                continue
            if _extract_name(agent_id) == name:
                return False

    return True


def _find_duplicate_names(team_mail_dir: Path) -> dict[str, list[str]]:
    """Find agent names that are used by multiple agents.

    Names must be unique. This detects data inconsistencies from manual edits.

    Returns:
        Dict mapping name to list of agent ids that share it.
        Only includes names with 2+ agents.
    """
    agents_dir = _get_agents_dir(team_mail_dir)
    if not agents_dir.exists():
        return {}

    name_to_ids: dict[str, list[str]] = {}
    for agent_dir in agents_dir.iterdir():
        if agent_dir.is_dir():
            agent_id = agent_dir.name
            short_name = _extract_name(agent_id)
            if short_name not in name_to_ids:
                name_to_ids[short_name] = []
            name_to_ids[short_name].append(agent_id)

    # Return only duplicates
    return {name: ids for name, ids in name_to_ids.items() if len(ids) > 1}


def _ensure_agent_dir(team_mail_dir: Path, agent_id: str) -> Path:
    """Create agent directory structure."""
    agent_dir = _get_agent_dir(team_mail_dir, agent_id)
    agent_dir.mkdir(parents=True, exist_ok=True)
    mail_dir = agent_dir / "mail"
    mail_dir.mkdir(exist_ok=True)
    for name in ("inbox.jsonl", "sent.jsonl"):
        f = mail_dir / name
        if not f.exists():
            f.touch()
    state = mail_dir / "state.json"
    if not state.exists():
        _ = state.write_text("{}\n")
    return agent_dir


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


def _derive_token(password: str, agent_name: str, salt: str) -> str:
    """Derive a deterministic token from admin password and agent name.

    Uses HMAC-SHA256 with the password as key, then encodes to TOKEN_LENGTH chars.
    Same password + agent + salt always produces the same token.
    """
    key = password.encode()
    message = f"token:{agent_name}:{salt}".encode()
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


def _get_token_file(team_mail_dir: Path, name: str) -> Path:
    """Get path to token file for a user or admin."""
    return team_mail_dir / "tokens" / name


def _store_token_hash(team_mail_dir: Path, name: str, token: str) -> None:
    """Store a hashed token for an agent."""
    token_file = _get_token_file(team_mail_dir, name)
    token_hash = _hash_token(token)
    _ = token_file.write_text(token_hash + "\n")


def _validate_token(team_mail_dir: Path, token: str) -> tuple[str, bool] | None:
    """Validate a token and return (username, is_admin) or None if invalid.

    Hashes the provided token and checks against stored hashes.
    Returns (username, False) for valid user token.
    Admin does not use tokens - use password instead.
    """
    tokens_dir = team_mail_dir / "tokens"
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


def _get_password_from_env() -> str | None:
    """Get admin password from $TEAM_MAIL_ADMIN_PASS environment variable."""
    return os.environ.get("TEAM_MAIL_ADMIN_PASS")


def _get_password() -> str | None:
    """Get password from CLI option (--password) or env var ($TEAM_MAIL_ADMIN_PASS)."""
    if _cli_password:
        return _cli_password
    return _get_password_from_env()


def _require_auth() -> tuple[Path, str, bool]:
    """Validate auth from CLI or env, return (team_mail_dir, user, is_admin). Exits on error.

    Priority: --password/TEAM_MAIL_ADMIN_PASS > --token/TEAM_MAIL_TOKEN
    """
    team_mail_dir = _require_team_mail_dir()

    # Check password first (admin auth)
    password = _get_password()
    if password:
        _require_admin(team_mail_dir, password)
        return team_mail_dir, "_admin", True

    # Then check token (user auth)
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
            fix="Run 'team-mail init' first",
        )

    admin_config = T.cast(AdminConfig, json.loads(admin_file.read_text()))
    if not _verify_password(password, admin_config["password_hash"], admin_config["salt"]):
        _error("Invalid password")


def _require_user() -> tuple[Path, str]:
    """Validate user token from env, return (team_mail_dir, agent_name). Exits on error.

    Supports admin impersonation via --user when authenticated as admin.
    """
    team_mail_dir, agent_name, is_admin = _require_auth()

    if is_admin:
        # Admin can impersonate agents with --user
        if _cli_user:
            # Resolve and verify the target agent exists
            agent_id = _resolve_agent(team_mail_dir, _cli_user)
            if agent_id is None:
                agents = list(_iter_agent_names(team_mail_dir))
                _error(
                    f"Agent '{_cli_user}' not found",
                    available=agents if agents else None,
                )
            assert agent_id is not None
            return team_mail_dir, agent_id

        # Admin without --user cannot use agent commands
        if _cli_password:
            _error(
                "--password authenticates as admin, not as an agent",
                fix="Use --user <id-or-name> to act on behalf of an agent, or use an agent token",
            )
        _error(
            "Admin token cannot be used for agent operations",
            fix="Use --user <id-or-name> to act on behalf of an agent, or use an agent token",
        )

    # Non-admin with --user is an error
    if _cli_user:
        _error(
            "--user requires admin authentication",
            fix="Use --password or admin --token with --user",
        )

    return team_mail_dir, agent_name


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


def _iter_agent_names(team_mail_dir: Path) -> Iterator[str]:
    """Iterate over all agent names."""
    agents_dir = _get_agents_dir(team_mail_dir)
    if not agents_dir.is_dir():
        return
    for agent_dir in agents_dir.iterdir():
        if agent_dir.is_dir():
            yield agent_dir.name


def _load_profile(agent_dir: Path) -> AgentProfile | None:
    """Load an agent's profile.json.

    Handles migration from old format (name=full id) to new format (id + name).
    """
    profile_path = agent_dir / "profile.json"
    if not profile_path.exists():
        return None

    data = json.loads(profile_path.read_text())

    # Migrate old format: if no 'id' field, derive from directory name
    if "id" not in data:
        agent_id = agent_dir.name
        data["id"] = agent_id
        data["name"] = _extract_name(agent_id)
        # Save migrated profile
        _ = profile_path.write_text(json.dumps(data, indent=2) + "\n")

    return T.cast(AgentProfile, data)


def _save_profile(agent_dir: Path, profile: AgentProfile) -> None:
    """Save an agent's profile.json."""
    profile_path = agent_dir / "profile.json"
    _ = profile_path.write_text(json.dumps(profile, indent=2) + "\n")


# ---------------------------------------------------------------------------
# Admin commands (Tasks 2.1-2.4)
# ---------------------------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> None:
    """Initialize workspace (first-time setup)."""
    # Handle --check mode
    if getattr(args, "check", False):
        existing_dir = _get_team_mail_dir()
        if existing_dir is not None and (existing_dir / "admin.json").exists():
            print("Team-mail initialized")
            sys.exit(0)
        else:
            sys.exit(1)

    # Check if already initialized
    existing_dir = _get_team_mail_dir()
    if existing_dir is not None:
        admin_file = existing_dir / "admin.json"
        if admin_file.exists():
            _error(
                "Already initialized",
                fix="Use 'team-mail admin password' to change the password",
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


def cmd_create_token(args: argparse.Namespace) -> None:
    """Create agent token (admin only).

    Derives the token deterministically from password + agent name + salt.
    Same inputs always produce the same token. Stores only the hash.
    """
    team_mail_dir = _require_team_mail_dir()

    # Get password from CLI or env
    password = T.cast(str | None, args.password) or _get_password_from_env()
    if not password:
        _error("Password required", fix="Use --password <password> or set TEAM_MAIL_ADMIN_PASS")

    assert password is not None
    _require_admin(team_mail_dir, password)

    identifier = T.cast(str, args.agent)

    # Resolve identifier (can be id or short name)
    agent_id = _resolve_agent(team_mail_dir, identifier)
    if agent_id is None:
        agents = list(_iter_agent_names(team_mail_dir))
        _error(
            f"Agent '{identifier}' not found",
            fix="Create agent with 'team-mail agents add'",
            available=agents if agents else None,
        )

    assert agent_id is not None

    # Load salt from admin config
    admin_file = team_mail_dir / "admin.json"
    admin_config = T.cast(AdminConfig, json.loads(admin_file.read_text()))
    salt = admin_config["salt"]

    # Derive token deterministically (same password + agent + salt = same token)
    token = _derive_token(password, agent_id, salt)

    # Store hash (idempotent - same token always produces same hash)
    _store_token_hash(team_mail_dir, agent_id, token)

    print(token)


def cmd_agents_add(args: argparse.Namespace) -> None:
    """Create agent account."""
    team_mail_dir, user, is_admin = _require_auth()

    if not is_admin:
        _error("Admin token required", fix="Set TEAM_MAIL_TOKEN to an admin token")

    agent_name = T.cast(str, args.name)
    role = T.cast(str, args.role)

    # Validate agent id
    agent_id = agent_name  # CLI arg is still called --name for now
    valid, err = _validate_username(agent_id)
    if not valid:
        _error(f"Invalid agent id '{agent_id}': {err}")

    # Extract short name and check uniqueness
    short_name = _extract_name(agent_id)
    if not _is_name_unique(team_mail_dir, short_name):
        existing_id = _resolve_agent(team_mail_dir, short_name)
        _error(
            f"Name '{short_name}' is already used by agent '{existing_id}'",
            fix=f"Choose a different name (e.g., '{short_name}2-{role.lower().replace(' ', '-')}')",
        )

    # Check if agent id already exists
    agent_dir = _get_agent_dir(team_mail_dir, agent_id)
    if agent_dir.is_dir():
        _error(f"Agent '{agent_id}' already exists")

    # Create agent directory
    agent_dir = _ensure_agent_dir(team_mail_dir, agent_id)

    # Create profile
    status = T.cast(str | None, args.status) or ""
    about = T.cast(str | None, args.about) or ""
    tags_str = T.cast(str | None, args.tags)
    tags = [t.strip() for t in tags_str.split(",") if t.strip()] if tags_str else []

    profile: AgentProfile = {
        "id": agent_id,
        "name": short_name,
        "role": role,
        "status": status,
        "about": about,
        "tags": tags,
        "joined": _now_iso(),
        "updated": _now_iso(),
    }
    _save_profile(agent_dir, profile)

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


def cmd_agents_list(args: argparse.Namespace) -> None:
    """List team agents."""
    team_mail_dir = _get_team_mail_dir()
    if team_mail_dir is None:
        print("[]")
        return

    # Check for duplicate names and error
    duplicates = _find_duplicate_names(team_mail_dir)
    if duplicates:
        lines = [f"  name '{name}' used by: {', '.join(ids)}" for name, ids in duplicates.items()]
        _error(
            "Duplicate agent names detected:\n" + "\n".join(lines),
            fix="Agent names must be unique. Rename agents so each has a distinct name (first component of id)",
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
        result = _validate_token(team_mail_dir, token)
        if result:
            current_user, is_admin = result

    # Admin sees all; otherwise exclude self unless --include-self
    exclude_self = not is_admin and not include_self

    if names_only:
        # Just agent names
        for agent_name in sorted(_iter_agent_names(team_mail_dir)):
            if exclude_self and agent_name == current_user:
                continue
            if tags_set:
                agent_dir = _get_agent_dir(team_mail_dir, agent_name)
                profile = _load_profile(agent_dir)
                if profile and not tags_set.intersection(profile.get("tags", [])):
                    continue
            print(agent_name)
    else:
        # List all profiles as JSON array
        profiles: list[dict[str, T.Any]] = []
        for agent_name in sorted(_iter_agent_names(team_mail_dir)):
            if exclude_self and agent_name == current_user:
                continue
            agent_dir = _get_agent_dir(team_mail_dir, agent_name)
            profile = _load_profile(agent_dir)
            if profile is None:
                continue
            if tags_set and not tags_set.intersection(profile.get("tags", [])):
                continue
            profiles.append(_compact_profile(profile, full=full))

        print(json.dumps(profiles, indent=2))


def cmd_agents_get(args: argparse.Namespace) -> None:
    """View a specific agent's profile."""
    team_mail_dir = _get_team_mail_dir()
    if team_mail_dir is None:
        _error(".team-mail directory not found")

    assert team_mail_dir is not None
    identifier = T.cast(str, args.name)
    full = T.cast(bool, getattr(args, "full", False))

    # Resolve identifier (can be id or short name)
    agent_id = _resolve_agent(team_mail_dir, identifier)
    if agent_id is None:
        agents = list(_iter_agent_names(team_mail_dir))
        _error(
            f"Agent '{identifier}' not found",
            available=agents if agents else None,
        )

    assert agent_id is not None
    agent_dir = _get_agent_dir(team_mail_dir, agent_id)
    profile = _load_profile(agent_dir)
    if profile is None:
        _error(f"No profile found for '{agent_id}'")

    assert profile is not None
    output = _compact_profile(profile, full=full)
    print(json.dumps(output, indent=2))


def cmd_whoami(_args: argparse.Namespace) -> None:
    """Print your username."""
    _team_mail_dir, agent_name = _require_user()
    print(agent_name)


def cmd_agents_update(args: argparse.Namespace) -> None:
    """Update an agent's profile."""
    identifier = T.cast(str | None, getattr(args, "name", None))
    status = T.cast(str | None, getattr(args, "status", None))
    tags_str = T.cast(str | None, getattr(args, "tags", None))
    about = T.cast(str | None, getattr(args, "about", None))
    role = T.cast(str | None, getattr(args, "role", None))
    full = getattr(args, "full", False)

    team_mail_dir = _require_team_mail_dir()

    # If no identifier provided, use the authenticated user
    if identifier is None:
        _, agent_id = _require_user()
    else:
        # Resolve identifier (can be id or short name)
        agent_id = _resolve_agent(team_mail_dir, identifier)
        if agent_id is None:
            agents = list(_iter_agent_names(team_mail_dir))
            _error(
                f"Agent '{identifier}' not found",
                available=agents if agents else None,
            )
        assert agent_id is not None

    agent_dir = _get_agent_dir(team_mail_dir, agent_id)
    if not agent_dir.exists():
        _error(f"Agent '{agent_id}' does not exist")

    profile = _load_profile(agent_dir)
    if profile is None:
        _error(f"No profile found for '{agent_id}'")

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
    _save_profile(agent_dir, profile)

    output = _compact_profile(profile, full=full)
    print(json.dumps(output, indent=2))


# ---------------------------------------------------------------------------
# Mail commands (Tasks 4.1-4.3)
# ---------------------------------------------------------------------------


def cmd_inbox(args: argparse.Namespace) -> None:
    """Check inbox summary."""
    team_mail_dir, agent_name = _require_user()

    agent_dir = _get_agent_dir(team_mail_dir, agent_name)
    inbox = agent_dir / "mail" / "inbox.jsonl"

    if not inbox.exists() or inbox.stat().st_size == 0:
        print("No messages")
        return

    # Get last_read for unread filtering
    state_file = agent_dir / "mail" / "state.json"
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


def cmd_inbox_read(args: argparse.Namespace) -> None:
    """Read full messages, mark as read."""
    team_mail_dir, agent_id, is_admin = _require_auth()

    # Admin must use --user to read an agent's inbox
    if is_admin:
        if not _cli_user:
            if _cli_password:
                _error(
                    "--password authenticates as admin, not as an agent",
                    fix="Use --user <id-or-name> to act on behalf of an agent, or use an agent token",
                )
            _error(
                "Admin token cannot be used for agent operations",
                fix="Use --user <id-or-name> to act on behalf of an agent, or use an agent token",
            )
        # Resolve and verify the target agent exists
        resolved_id = _resolve_agent(team_mail_dir, _cli_user)
        if resolved_id is None:
            agents = list(_iter_agent_names(team_mail_dir))
            _error(
                f"Agent '{_cli_user}' not found",
                available=agents if agents else None,
            )
        assert resolved_id is not None
        agent_id = resolved_id
        agent_dir = _get_agent_dir(team_mail_dir, agent_id)
    else:
        if _cli_user:
            _error(
                "--user requires admin authentication",
                fix="Use --password or admin --token with --user",
            )
        agent_dir = _get_agent_dir(team_mail_dir, agent_id)

    # Determine if we should include 'to' field (only for admin impersonating)
    include_to_field = is_admin and _cli_user is not None

    inbox = agent_dir / "mail" / "inbox.jsonl"

    if not inbox.exists() or inbox.stat().st_size == 0:
        return  # Silent exit

    # Parse filter options
    since_filter = T.cast(str | None, getattr(args, "since", None))
    from_filter = T.cast(str | None, getattr(args, "from_user", None))
    include_read = T.cast(bool, getattr(args, "include_read", False))

    # Get last_read for unread filtering
    state_file = agent_dir / "mail" / "state.json"
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

    recipient_identifier = T.cast(str, args.to)
    body = T.cast(str, args.body)

    # Resolve recipient (can be id or short name)
    recipient = _resolve_agent(team_mail_dir, recipient_identifier)
    if recipient is None:
        agents = list(_iter_agent_names(team_mail_dir))
        _error(
            f"Agent '{recipient_identifier}' not found",
            available=agents if agents else None,
        )

    assert recipient is not None
    recipient_dir = _get_agent_dir(team_mail_dir, recipient)
    sender_dir = _get_agent_dir(team_mail_dir, sender)

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
    agents: argparse.ArgumentParser


def _build_parser() -> Parsers:
    """Build and return the argument parser with all subparsers."""
    parser = argparse.ArgumentParser(
        prog="team-mail",
        description="Token-authenticated inter-agent messaging.",
        epilog="Run 'team-mail <command> --help' for command-specific help.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    sub = parser.add_subparsers(dest="command", required=False, metavar="<command>")

    # ---------- init (top-level) ----------
    init_parser = sub.add_parser(
        "init",
        help="Initialize workspace (first-time setup)",
        description="Initialize .team-mail/ directory and set admin password. Prompts interactively if --password not provided.",
    )
    _ = init_parser.add_argument("--password", help="Admin password (prompts if not provided)")
    _ = init_parser.add_argument("--check", action="store_true", help="Check if initialized (exit 0 if yes, 1 if no)")

    # ---------- create-token (top-level) ----------
    create_token_parser = sub.add_parser(
        "create-token",
        help="Create agent token (admin only)",
        description="Generate authentication token for an agent. Requires admin password.",
    )
    _ = create_token_parser.add_argument("--password", help="Admin password (or set TEAM_MAIL_ADMIN_PASS)")
    _ = create_token_parser.add_argument("--agent", required=True, help="Agent id or name")

    # ---------- admin ----------
    admin_parser = sub.add_parser(
        "admin",
        help="Administrative commands",
        description="Administrative commands for managing the team-mail system.",
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

    # ---------- agents ----------
    agents_parser = sub.add_parser(
        "agents",
        help="Discover and manage agents",
        description="List agents, view profiles, add new agents, or update profiles.",
        epilog="Examples:\n  team-mail agents list\n  team-mail agents get maya-backend",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    agents_sub = agents_parser.add_subparsers(dest="agents_command", required=False, metavar="<subcommand>")

    # agents list
    agents_list = agents_sub.add_parser(
        "list",
        help="List all agents",
        description="List all agents as JSON array (excludes dates by default).",
        epilog="Examples:\n  team-mail agents list --names-only\n  team-mail agents list --tags=backend,auth",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _ = agents_list.add_argument("--names-only", action="store_true", help="Only output agent ids, one per line")
    _ = agents_list.add_argument("--include-self", action="store_true", help="Include yourself in the list (excluded by default)")
    _ = agents_list.add_argument("--tags", help="Filter by tags (comma-separated)")
    _ = agents_list.add_argument("--full", action="store_true", help="Include all fields (dates, empty values)")

    # agents get
    agents_get = agents_sub.add_parser(
        "get",
        help="View an agent's profile",
        description="View a specific agent's profile as JSON (excludes dates by default).",
    )
    _ = agents_get.add_argument("name", help="Agent id or short name")
    _ = agents_get.add_argument("--full", action="store_true", help="Include all fields (dates, empty values)")

    # agents add (requires admin auth)
    agents_add = agents_sub.add_parser(
        "add",
        help="Add a new agent (admin only)",
        description="Create a new agent account. Requires admin auth via --password, --token, or $TEAM_MAIL_TOKEN.",
    )
    _ = agents_add.add_argument("--name", required=True, help="Agent id (3-40 chars, lowercase, letters/numbers/dashes)")
    _ = agents_add.add_argument("--role", required=True, help="Agent role (e.g. 'Backend Engineer')")
    _ = agents_add.add_argument("--token", help="Admin token")
    _ = agents_add.add_argument("--password", help="Admin password (alternative to --token)")
    _ = agents_add.add_argument("--status", help="Initial status")
    _ = agents_add.add_argument("--tags", help="Comma-separated tags")
    _ = agents_add.add_argument("--about", help="About description")

    # agents update
    agents_update = agents_sub.add_parser(
        "update",
        help="Update an agent's profile",
        description="Update profile fields of an existing agent. Without --name, updates your own profile (requires token).",
        epilog="Examples:\n  team-mail agents update --status 'Working on auth'\n  team-mail agents update --name maya-backend --role 'Senior Engineer' --password secret",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _ = agents_update.add_argument("--name", help="Agent id or name to update (default: self)")
    _ = agents_update.add_argument("--token", help="User token (or set $TEAM_MAIL_TOKEN)")
    _ = agents_update.add_argument("--password", help="Admin password (for updating other agents)")
    _ = agents_update.add_argument("--status", help="Set status")
    _ = agents_update.add_argument("--role", help="Set role")
    _ = agents_update.add_argument("--tags", help="Set tags (comma-separated)")
    _ = agents_update.add_argument("--about", help="Set about description")
    _ = agents_update.add_argument("--full", action="store_true", help="Include all fields in output")

    # ---------- inbox ----------
    inbox_parser = sub.add_parser(
        "inbox",
        help="Check inbox",
        description="Check inbox summary or read full messages. Requires user token.",
        epilog="Examples:\n  team-mail inbox              # Summary\n  team-mail inbox read         # Read and mark as read",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _ = inbox_parser.add_argument("--token", help="User token (or set $TEAM_MAIL_TOKEN)")
    _ = inbox_parser.add_argument("--password", help="Admin password (requires --user)")
    _ = inbox_parser.add_argument("--user", help="Agent id or name to act as (requires admin auth)")

    inbox_sub = inbox_parser.add_subparsers(dest="inbox_command", metavar="<subcommand>")

    # inbox read
    inbox_read = inbox_sub.add_parser(
        "read",
        help="Read full messages, mark as read",
        description="Read all unread messages as JSONL and mark them as read. Requires user token.",
        epilog="Examples:\n  team-mail inbox read --from alice\n  team-mail inbox read --since 2026-01-30T12:00:00Z",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _ = inbox_read.add_argument("--token", help="User token (or set $TEAM_MAIL_TOKEN)")
    _ = inbox_read.add_argument("--password", help="Admin password (requires --user)")
    _ = inbox_read.add_argument("--user", help="Agent id or name to act as (requires admin auth)")
    _ = inbox_read.add_argument("--since", help="Only messages after this ISO timestamp")
    _ = inbox_read.add_argument("--from", dest="from_user", help="Only messages from this user")
    _ = inbox_read.add_argument("--include-read", action="store_true", help="Include already-read messages")

    # ---------- send ----------
    send_parser = sub.add_parser(
        "send",
        help="Send message",
        description="Send a message to another agent. Requires user token.",
        epilog="Example: team-mail send alex-frontend \"API is ready\"",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _ = send_parser.add_argument("--token", help="User token (or set $TEAM_MAIL_TOKEN)")
    _ = send_parser.add_argument("--password", help="Admin password (requires --user)")
    _ = send_parser.add_argument("--user", help="Agent id or name to send as (requires admin auth)")
    _ = send_parser.add_argument("to", help="Recipient id or name")
    _ = send_parser.add_argument("body", help="Message body")

    # ---------- whoami ----------
    whoami_parser = sub.add_parser(
        "whoami",
        help="Print your username",
        description="Print your username. Requires user token.",
    )
    _ = whoami_parser.add_argument("--token", help="User token (or set $TEAM_MAIL_TOKEN)")
    _ = whoami_parser.add_argument("--password", help="Admin password (requires --user)")
    _ = whoami_parser.add_argument("--user", help="Agent id or name to act as (requires admin auth)")

    # ---------- env (for hooks) ----------
    _ = sub.add_parser(
        "env",
        help="Print env exports for hooks",
        description="Auto-discover .team-mail directory and print shell export statements.",
    )

    return Parsers(main=parser, admin=admin_parser, agents=agents_parser)


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
        }
        admin_cmd_map[admin_command](args)

    elif command == "agents":
        agents_command = T.cast(str | None, getattr(args, "agents_command", None))
        if agents_command == "list":
            cmd_agents_list(args)
        elif agents_command == "get":
            cmd_agents_get(args)
        elif agents_command == "add":
            cmd_agents_add(args)
        elif agents_command == "update":
            cmd_agents_update(args)
        else:
            parsers.agents.print_help()
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
            "whoami": cmd_whoami,
            "env": cmd_env,
        }
        cmd_map[command](args)


if __name__ == "__main__":
    main()
