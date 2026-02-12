"""Name validation, slugification, and address format checks."""

from __future__ import annotations

import re

from atcha.cli.errors import _error


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
    """Convert a string to a valid slug.

    Slug format: [a-z0-9][a-z0-9-]{0,38}[a-z0-9] (2-40 chars, no leading/trailing dashes)

    Examples:
        'my-project' -> 'my-project'
        'My Project' -> 'my-project'
        'agent_team_mail' -> 'agent-team-mail'
        'Backend Engineer' -> 'backend-engineer'
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


def _validate_address_format(value: str) -> str:
    """Validate that a user reference is an address (name@, name@space), not a bare name.

    Bare names are rejected because they're ambiguous — could be local or cross-space.
    Returns the value unchanged if valid. Calls _error() if bare name.
    """
    if "@" in value:
        return value  # name@ or name@space
    _error(
        f"bare name '{value}' is ambiguous",
        fix=f"use '{value}@' for local or '{value}@<space>' for cross-space",
    )
