"""Contact listing and viewing commands."""

from __future__ import annotations

import argparse
import json
import sys
import typing as T
from pathlib import Path

from atcha.cli.auth import _require_user
from atcha.cli.errors import _error
from atcha.cli.federation import (
    _ensure_space_config,
    _load_federation,
    _load_space_config,
    _parse_address,
    _resolve_space,
)
from atcha.cli.store import (
    _compact_profile,
    _find_duplicate_names,
    _get_atcha_dir,
    _get_user_dir,
    _iter_user_names,
    _load_profile,
    _resolve_user,
)
from atcha.cli._types import AuthContext, UserProfile


def cmd_users_list(auth: AuthContext, args: argparse.Namespace) -> None:
    """List team users from local and federated spaces."""
    # Auth required — contacts is not a public endpoint
    atcha_dir, current_user = _require_user(auth)

    # Check for duplicate names and error (only for local space)
    duplicates = _find_duplicate_names(atcha_dir)
    if duplicates:
        lines = [f"  name '{name}' used by: {', '.join(ids)}" for name, ids in duplicates.items()]
        _error(
            "Duplicate user names detected:\n" + "\n".join(lines),
            fix="User names must be unique. Rename users so each has a distinct name.",
        )

    include_self = T.cast(bool, getattr(args, "include_self", False))
    full = T.cast(bool, getattr(args, "full", False))
    tags_filter = T.cast(str | None, getattr(args, "tags", None))
    tags_set = {t.strip() for t in tags_filter.split(",") if t.strip()} if tags_filter else None
    space_filter = T.cast(str | None, getattr(args, "space", None))

    # Exclude self unless --include-self
    exclude_self = not include_self

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
        user_dir = _get_user_dir(target_dir, user_id)
        profile = _load_profile(user_dir)
        if profile is None:
            _error(f"No profile found for '{user_id}'")
        is_local = (target_dir == atcha_dir)
        output = _compact_profile(profile, full=full, space_name=space_config["name"], is_local=is_local)
        print(json.dumps(output, indent=2))
        return

    # Bare name: collect matches across all spaces
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
        # Single match — show profile with address and scope
        user_id, space_path, space_name, profile, is_local = matches[0]
        output = _compact_profile(profile, full=full, space_name=space_name, is_local=is_local)
        print(json.dumps(output, indent=2))
    else:
        # Multiple matches — show all with address and scope
        profiles_output: list[dict[str, T.Any]] = []
        for user_id, space_path, space_name, profile, is_local in matches:
            profiles_output.append(_compact_profile(profile, full=full, space_name=space_name, is_local=is_local))
        print(json.dumps(profiles_output, indent=2))
