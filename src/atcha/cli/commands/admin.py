"""Administrative commands."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
import typing as T
from pathlib import Path

from atcha.cli.auth import (
    _derive_token,
    _generate_salt,
    _generate_user_id,
    _get_password,
    _get_token_file,
    _hash_password,
    _require_admin,
    _require_auth,
    _store_token_hash,
)
from atcha.cli.errors import _error
from atcha.cli.federation import (
    _ensure_space_config,
    _find_space,
    _is_space_available,
    _load_federation,
    _load_space_config,
    _parse_address,
    _save_federation,
    _save_space_config,
)
from atcha.cli.store import (
    _ensure_atcha_dir,
    _ensure_user_dir,
    _get_atcha_dir,
    _get_user_dir,
    _get_users_dir,
    _iter_user_names,
    _load_profile,
    _resolve_user,
    _save_profile,
)
from atcha.cli._types import (
    ATCHA_DIR_NAME,
    TOKEN_LENGTH,
    SPACE_ID_PREFIX,
    AdminConfig,
    AuthContext,
    FederatedSpace,
    SpaceConfig,
    UserProfile,
)
from atcha.cli.utils import _generate_space_id, _now_iso
from atcha.cli.validation import _slugify_name, _validate_address_format, _validate_username


# ---------------------------------------------------------------------------
# Admin auth helper
# ---------------------------------------------------------------------------


def _require_admin_context(auth: AuthContext) -> Path:
    """Validate admin credentials and return the atcha directory.

    Centralizes the repeated pattern of: find .atcha dir, get password, verify admin.
    """
    atcha_dir = _get_atcha_dir()
    if atcha_dir is None:
        _error(".atcha directory not found", fix="Run 'atcha admin init' first")
    password = _get_password(auth)
    if not password:
        _error("Admin password required", fix="Use --password or set ATCHA_ADMIN_PASS")
    _require_admin(atcha_dir, password)
    return atcha_dir


# ---------------------------------------------------------------------------
# Status and init
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


# ---------------------------------------------------------------------------
# Password management
# ---------------------------------------------------------------------------


def cmd_admin_password(auth: AuthContext, args: argparse.Namespace) -> None:
    """Change admin password. Uses standard auth (--password or env) for old password."""
    atcha_dir = _require_admin_context(auth)

    new_password = T.cast(str | None, args.new)
    if not new_password:
        _error("New password required", fix="Use --new <password>")

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


# ---------------------------------------------------------------------------
# Token management
# ---------------------------------------------------------------------------


def cmd_create_token(auth: AuthContext, args: argparse.Namespace) -> None:
    """Create user token (admin only).

    Derives the token deterministically from password + user name + salt.
    Same inputs always produce the same token. Stores only the hash.
    """
    atcha_dir = _require_admin_context(auth)
    # Re-fetch password for token derivation (already validated by _require_admin_context)
    password = _get_password(auth)
    assert password is not None

    raw_identifier = T.cast(str, args.user)

    # Parse address form (e.g. "maya@") — strip space ref, reject cross-space
    name_part, space_ref = _parse_address(raw_identifier)
    if space_ref:
        _error(
            "create-token only works for local users",
            fix="Omit the space qualifier (e.g. 'maya' or 'maya@')",
        )
    identifier = name_part

    # Resolve identifier (can be id or short name)
    user_id = _resolve_user(atcha_dir, identifier)
    if user_id is None:
        users = list(_iter_user_names(atcha_dir))
        _error(
            f"User '{identifier}' not found",
            fix="Create user with 'atcha admin users create'",
            available=users if users else None,
        )

    # Load salt from admin config
    admin_file = atcha_dir / "admin.json"
    admin_config = T.cast(AdminConfig, json.loads(admin_file.read_text()))
    salt = admin_config["salt"]

    # Derive token deterministically (same password + user + salt = same token)
    token = _derive_token(password, user_id, salt)

    # Store hash (idempotent — same token always produces same hash)
    _store_token_hash(atcha_dir, user_id, token)

    print(token)


# ---------------------------------------------------------------------------
# User management
# ---------------------------------------------------------------------------


def cmd_users_add(auth: AuthContext, args: argparse.Namespace) -> None:
    """Create user account.

    The user ID is derived from name + role: {name}-{slugify(role)}.
    Name and role are immutable — to change identity, create a new user.
    """
    atcha_dir, user, is_admin = _require_auth(auth)

    if not is_admin:
        _error("Admin token required", fix="Set ATCHA_TOKEN to an admin token")

    user_name = T.cast(str, args.name)
    role = T.cast(str, args.role)

    # Validate user name
    valid, err = _validate_username(user_name)
    if not valid:
        _error(f"Invalid user name '{user_name}': {err}")

    # Check if name already exists (scan profiles)
    existing = _resolve_user(atcha_dir, user_name)
    if existing is not None:
        _error(f"User '{user_name}' already exists")

    # Generate deterministic user ID from name + role
    user_id = _generate_user_id(user_name, role)

    # Check if directory already exists (e.g., same name + same role)
    user_dir = _get_user_dir(atcha_dir, user_id)
    if user_dir.is_dir():
        _error(f"User '{user_id}' already exists")

    # Create user directory
    user_dir = _ensure_user_dir(atcha_dir, user_id)

    # Create profile
    status = T.cast(str | None, args.status) or ""
    about = T.cast(str | None, args.about) or ""
    tags_str = T.cast(str | None, args.tags)
    tags = [t.strip() for t in tags_str.split(",") if t.strip()] if tags_str else []

    now = _now_iso()
    profile: UserProfile = {
        "id": user_id,        # Deterministic: {name}-{role_slug} (immutable, = directory name)
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


def cmd_admin_users_list(auth: AuthContext) -> None:
    """List all users as JSON array (admin only)."""
    atcha_dir = _require_admin_context(auth)

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
    """Update user profile with admin-only fields (status, about, tags).

    Name and role are immutable — they are baked into the user ID.
    """
    atcha_dir = _require_admin_context(auth)

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

    user_dir = _get_user_dir(atcha_dir, user_id)
    profile = _load_profile(user_dir)
    if profile is None:
        _error(f"No profile found for '{user_id}'")

    # Apply updates (name and role are immutable — not accepted here)
    status = T.cast(str | None, getattr(args, "status", None))
    about = T.cast(str | None, getattr(args, "about", None))
    tags_str = T.cast(str | None, getattr(args, "tags", None))

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

    This is irreversible — the user's messages and profile are permanently lost.
    """
    import shutil

    atcha_dir = _require_admin_context(auth)

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


# ---------------------------------------------------------------------------
# Hints
# ---------------------------------------------------------------------------


def cmd_admin_prime(auth: AuthContext) -> None:
    """Print session-start primer for AI agent sessions.

    Adapts output based on available auth:
    - User token: identity + essential messaging commands
    - Admin password: identity + admin-focused guidance
    - No auth: general intro + how to authenticate

    Exits silently only if .atcha/ doesn't exist (system not set up).
    """
    atcha_dir = _get_atcha_dir()
    if atcha_dir is None:
        # atcha not initialized — nothing to prime with
        sys.exit(0)

    from atcha.cli.auth import _get_password, _get_token, _validate_token

    # Try user token first, then admin password
    token = _get_token(auth)
    password = _get_password(auth)

    if token:
        result = _validate_token(atcha_dir, token)
        if result is not None:
            user_id, _is_admin = result
            profile = _load_profile(_get_user_dir(atcha_dir, user_id))
            if profile is not None:
                _print_user_prime(profile)
                return

    if password:
        # Verify admin password before printing admin primer
        admin_file = atcha_dir / "admin.json"
        if admin_file.exists():
            from atcha.cli.auth import _verify_password
            admin_config = T.cast(AdminConfig, json.loads(admin_file.read_text()))
            if _verify_password(password, admin_config["password_hash"], admin_config["salt"]):
                _print_admin_prime()
                return

    # No valid auth — print general intro
    _print_unauthenticated_prime()


def _print_user_prime(profile: UserProfile) -> None:
    parts: list[str] = []

    # --- Overview ---
    parts.append("# atcha (Agent Team Chat)")
    parts.append("")
    parts.append("You are **{name}** — an AI agent with your own atcha identity.".format(name=profile["name"]))
    parts.append("Messages sent to you are yours to read and respond to (not your human operator's).")
    parts.append("You are part of a team of AI agents working in parallel on this project.")

    # --- Your identity ---
    parts.append("")
    parts.append("## Your identity")
    parts.append("")
    parts.append(f"- **Name:** {profile['name']}")
    parts.append(f"- **Address:** {profile['name']}@")
    if profile.get("role"):
        parts.append(f"- **Role:** {profile['role']}")
    if profile.get("status"):
        parts.append(f"- **Status:** {profile['status']}")
    if profile.get("about"):
        parts.append(f"- **About:** {profile['about']}")
    tags = profile.get("tags", [])
    if tags:
        parts.append(f"- **Tags:** {', '.join(tags)}")

    # Hint if status or about are missing
    missing: list[str] = []
    if not profile.get("status"):
        missing.append("status")
    if not profile.get("about"):
        missing.append("about")
    if missing:
        fields = " and ".join(missing)
        parts.append("")
        parts.append(f"Hint: Set your {fields} so teammates know what you're working on:")
        parts.append(f"  `atcha profile update --{missing[0]} \"...\"`")

    # --- Quick commands ---
    parts.append("")
    parts.append("## Commands")
    parts.append("")
    parts.append("```")
    parts.append("atcha send --to <name>@ \"message\"   Send a message")
    parts.append("atcha send --broadcast \"message\"     Send to all contacts")
    parts.append("atcha send --reply-to <id> \"msg\"     Reply to a thread")
    parts.append("atcha messages check                 Inbox summary")
    parts.append("atcha messages                       List unread")
    parts.append("atcha messages read --all             Read all + mark as read")
    parts.append("atcha messages read <id>             Read specific message")
    parts.append("atcha contacts                       List teammates")
    parts.append("```")
    parts.append("")
    parts.append("## Tips")
    parts.append("")
    parts.append("- Messages in your inbox are for **you** (the AI agent), not your human operator.")
    parts.append("- Read new messages promptly — teammates may be blocked waiting for your reply.")

    parts.append("")
    parts.append("More options (filter, profile): `atcha --help`")

    print("\n".join(parts))


def _print_admin_prime() -> None:
    print("""\
# atcha (Agent Team Chat)

A messaging system for AI agents working in parallel on this project.
You have **admin** access. You can create users, mint tokens, and manage the space.

## User management

```
atcha admin users                                     List all users
atcha admin users create --name <n> --role "<r>"      Create a user
atcha admin users update <name>@ --status "..."       Update a user
atcha admin users delete <name>@                      Remove a user
atcha admin create-token --user <name>@               Mint a token
```

## Acting as a user

Use `--as-user <user-id>` on any user command to act on their behalf:
```
atcha send --as-user <user-id> --to <name>@ "msg"     Send as a user
atcha messages --as-user <user-id> check               Check their inbox
```

## Other admin commands

```
atcha admin password --new <pw>                        Change password (invalidates all tokens)
atcha admin spaces update --name "..." --description "..."
atcha admin spaces add <dir>                           Federate a space
```

Full reference: `atcha --help`""")


def _print_unauthenticated_prime() -> None:
    print("""\
# atcha (Agent Team Chat)

A messaging system for AI agents working in parallel on this project.
You are not logged in. You will not be able to send or read messages.\
""")


def cmd_admin_onboard(_auth: AuthContext) -> None:
    """Print a CLAUDE.md snippet for onboarding agents to atcha.

    The output is a static markdown block designed to be appended to CLAUDE.md.
    It tells agents that this project uses atcha and points to `atcha admin prime`
    and `atcha --help` for dynamic context.
    """
    print("""\
## atcha (Agent Team Chat)

This project uses **atcha** for messaging between parallel AI agent sessions.
You are an atcha user — messages addressed to you are yours to read and act on.
You may be working alongside other agents — use atcha to coordinate.

At session start, `atcha admin prime` shows your identity and key commands.
Run `atcha --help` for the full CLI reference.""")





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

## Token Security

- Tokens are **deterministic**: Same password + user always produces the same token
- Only **hashes** are stored in `.atcha/tokens/`
- **Never** share your admin password; share individual user tokens instead
- **Token format**: 5-character alphanumeric (e.g., `a3k9m`)
"""
    print(hints)


# ---------------------------------------------------------------------------
# Space management
# ---------------------------------------------------------------------------


def cmd_admin_spaces_update(auth: AuthContext, args: argparse.Namespace) -> None:
    """Update the current space's name and/or description."""
    atcha_dir = _require_admin_context(auth)

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
        space_config["description"] = description
        result["description"] = description

    _save_space_config(atcha_dir, space_config)
    result["status"] = "updated"
    print(json.dumps(result, indent=2))


def cmd_admin_federated_add(auth: AuthContext, args: argparse.Namespace) -> None:
    """Register a federated space."""
    atcha_dir = _require_admin_context(auth)

    path_arg = T.cast(str, args.path)
    force = T.cast(bool, getattr(args, "force", False))

    # Resolve path
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
    atcha_dir = _require_admin_context(auth)

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

    # Remove from federation
    federation["spaces"] = [s for s in federation["spaces"] if s["id"] != space["id"]]
    _save_federation(atcha_dir, federation)

    result = {
        "status": "removed",
        "id": space["id"],
        "name": space["name"],
    }
    print(json.dumps(result, indent=2))


def cmd_admin_spaces_list(auth: AuthContext) -> None:
    """List local space + federated spaces."""
    atcha_dir = _require_admin_context(auth)

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
