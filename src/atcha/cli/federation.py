"""Space identity, federation registry, and cross-space address resolution."""

from __future__ import annotations

import json
import typing as T
from pathlib import Path

from atcha.cli.errors import _error
from atcha.cli.store import _resolve_user
from atcha.cli._types import (
    TOKEN_LENGTH,
    SPACE_ID_PREFIX,
    FederatedSpace,
    FederationConfig,
    Message,
    SpaceConfig,
)
from atcha.cli.utils import _now_iso
from atcha.cli.validation import _slugify_name


# ---------------------------------------------------------------------------
# Space identity helpers
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
    from atcha.cli.utils import _generate_space_id

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
# Cross-space address resolution
# ---------------------------------------------------------------------------


def _parse_address(address: str) -> tuple[str, str | None]:
    """Parse 'name' or 'name@space' into (name, space_ref).

    Returns (name, None) for bare names (no @ present).
    Returns (name, "") for explicitly local addresses (trailing @, e.g., 'maya@').
    Returns (name, space_ref) for cross-space addresses (e.g., 'maya@engineering').

    The None vs "" distinction matters: None means the caller did not specify
    locality, while "" explicitly signals "local space" via the trailing @.
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


# ---------------------------------------------------------------------------
# Sender formatting helpers
# ---------------------------------------------------------------------------


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
