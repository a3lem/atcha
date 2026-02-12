"""Profile and identity commands."""

from __future__ import annotations

import argparse
import json
import typing as T

from atcha.cli.auth import _require_auth, _require_user
from atcha.cli.errors import _error
from atcha.cli.store import (
    _compact_profile,
    _get_user_dir,
    _iter_user_names,
    _load_profile,
    _resolve_user,
    _save_profile,
    _update_last_seen,
)
from atcha.cli._types import AuthContext
from atcha.cli.utils import _now_iso


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

    Immutable fields: id, name, role (baked into user ID)
    User-updatable fields: status, tags, about
    """
    # --as-user on profile update targets the user to update
    identifier = auth.as_user
    status = T.cast(str | None, getattr(args, "status", None))
    tags_str = T.cast(str | None, getattr(args, "tags", None))
    about = T.cast(str | None, getattr(args, "about", None))
    full = T.cast(bool, getattr(args, "full", False))

    atcha_dir, user_id, is_admin = _require_auth(auth)

    if identifier is None:
        # Updating self — no special checks needed
        pass
    else:
        # Updating another user — requires admin
        if not is_admin:
            _error(
                "Admin authentication required to update other users",
                fix="Use --password or set ATCHA_ADMIN_PASS",
            )
        # Resolve identifier
        resolved = _resolve_user(atcha_dir, identifier)
        if resolved is None:
            users = list(_iter_user_names(atcha_dir))
            _error(
                f"User '{identifier}' not found",
                available=users if users else None,
            )
        user_id = resolved

    user_dir = _get_user_dir(atcha_dir, user_id)
    if not user_dir.exists():
        _error(f"User '{user_id}' does not exist")

    profile = _load_profile(user_dir)
    if profile is None:
        _error(f"No profile found for '{user_id}'")

    if status is not None:
        profile["status"] = status
    if tags_str is not None:
        profile["tags"] = [t.strip() for t in tags_str.split(",") if t.strip()]
    if about is not None:
        profile["about"] = about

    profile["updated"] = _now_iso()
    _save_profile(user_dir, profile)

    # Track activity after profile update
    _update_last_seen(user_dir)

    output = _compact_profile(profile, full=full)
    print(json.dumps(output, indent=2))


def cmd_profile(auth: AuthContext, args: argparse.Namespace) -> None:
    """Profile command — view or update user profile."""
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
        output = _compact_profile(profile, full=full)
        print(json.dumps(output, indent=2))

        # Track activity when viewing own profile
        _update_last_seen(user_dir)
