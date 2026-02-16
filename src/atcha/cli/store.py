"""Data store operations on the .atcha/ directory."""

from __future__ import annotations

import json
import os
import typing as T
from collections.abc import Iterator
from pathlib import Path

from atcha.cli.errors import _error
from atcha.cli._types import ATCHA_DIR_NAME, UserProfile
from atcha.cli.utils import _format_time_ago, _now_iso


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
    """Get a specific user's directory by id (directory name = user id)."""
    return _get_users_dir(atcha_dir) / user_id


def _get_display_name(atcha_dir: Path, user_id: str) -> str:
    """Get the display name for a user from their profile.

    Falls back to user_id if profile can't be loaded.
    """
    profile = _load_profile(_get_user_dir(atcha_dir, user_id))
    if profile is not None:
        return profile["name"]
    return user_id


# ---------------------------------------------------------------------------
# User resolution
# ---------------------------------------------------------------------------


def _resolve_user(atcha_dir: Path, identifier: str) -> str | None:
    """Resolve an identifier (directory name or short name) to the directory name.

    Resolution strategy:
    1. Exact match on directory name (e.g., 'maya-backend-engineer')
    2. Match on name field in profile.json (e.g., 'maya')

    Args:
        atcha_dir: Path to .atcha directory
        identifier: A directory name or short name

    Returns:
        The directory name (= user id) if found, None otherwise.

    Raises:
        SystemExit if the name matches multiple users (ambiguous).
    """
    users_dir = _get_users_dir(atcha_dir)
    if not users_dir.exists():
        return None

    # Try exact match on directory name (= user id)
    if (users_dir / identifier).is_dir():
        return identifier

    # Scan profiles to find by name field
    matches: list[str] = []
    for user_dir in users_dir.iterdir():
        if not user_dir.is_dir():
            continue
        profile_path = user_dir / "profile.json"
        if profile_path.exists():
            try:
                profile = json.loads(profile_path.read_text())
            except (json.JSONDecodeError, OSError):
                continue
            if profile.get("name") == identifier:
                matches.append(user_dir.name)

    if len(matches) == 1:
        return matches[0]
    elif len(matches) > 1:
        _error(
            f"Name '{identifier}' matches multiple users: {', '.join(matches)}",
            fix="User names must be unique. This indicates a data inconsistency.",
        )

    return None


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
        if not user_dir.is_dir():
            continue
        profile_path = user_dir / "profile.json"
        if not profile_path.exists():
            continue
        try:
            profile = json.loads(profile_path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        name = profile.get("name")
        if name is None:
            continue
        if name not in name_to_ids:
            name_to_ids[name] = []
        name_to_ids[name].append(user_dir.name)

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
    return user_dir


# ---------------------------------------------------------------------------
# Profile I/O
# ---------------------------------------------------------------------------


def _load_profile(user_dir: Path) -> UserProfile | None:
    """Load a user's profile.json.

    Handles migration from old format (missing last_seen field).
    """
    profile_path = user_dir / "profile.json"
    if not profile_path.exists():
        return None

    data = json.loads(profile_path.read_text())
    needs_save = False

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
# User iteration and activity tracking
# ---------------------------------------------------------------------------


def _iter_user_names(atcha_dir: Path) -> Iterator[str]:
    """Iterate over all user directory names (= user IDs)."""
    users_dir = _get_users_dir(atcha_dir)
    if not users_dir.is_dir():
        return
    for user_dir in users_dir.iterdir():
        if user_dir.is_dir():
            yield user_dir.name


def _update_last_seen(user_dir: Path) -> None:
    """Update the last_seen timestamp for a user."""
    profile = _load_profile(user_dir)
    if profile:
        profile["last_seen"] = _now_iso()
        _save_profile(user_dir, profile)


# ---------------------------------------------------------------------------
# Profile display helpers
# ---------------------------------------------------------------------------


def _compact_profile(
    profile: UserProfile,
    full: bool = False,
    show_last_seen_ago: bool = True,
    space_name: str | None = None,
    is_local: bool | None = None,
) -> dict[str, T.Any]:
    """Return profile dict, optionally compacted for display.

    When full=False (default): excludes dates and empty fields, but includes last_seen.
    When full=True: includes all fields.
    When show_last_seen_ago=True: adds last_seen_ago field with human-readable format.
    When space_name and is_local are provided: adds address and scope fields.
    """
    if full:
        result = dict(profile.items())
    else:
        # Hide raw timestamps and last_seen in compact mode; last_seen_ago replaces it
        skip = {"joined", "updated", "last_seen"}
        result = {
            k: v for k, v in profile.items()
            if k not in skip and v not in ("", [], None)
        }

    # Add human-readable last_seen_ago field (read from profile, not result,
    # so it's available even when raw last_seen is hidden in compact mode)
    if show_last_seen_ago:
        last_seen = profile.get("last_seen")
        if isinstance(last_seen, str):
            result["last_seen_ago"] = _format_time_ago(last_seen)

    # Add address and scope fields when space info is provided.
    # Local users get abbreviated form (name@) matching what users type in commands.
    if space_name is not None and is_local is not None:
        name = profile["name"]
        if is_local:
            result["address"] = f"{name}@"
        else:
            result["address"] = f"{name}@{space_name}"
        if is_local:
            result["scope"] = "local"
        else:
            result["scope"] = "federated"

    return result
