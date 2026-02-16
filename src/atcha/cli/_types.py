"""Core constants and type definitions for the atcha CLI."""

from __future__ import annotations

import dataclasses
import typing as T


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = "0.1.0"
ATCHA_DIR_NAME: T.Final[str] = ".atcha"
TOKEN_LENGTH: T.Final[int] = 5  # 5-char random token
SPACE_ID_PREFIX: T.Final[str] = "spc-"


# ---------------------------------------------------------------------------
# Type definitions
# ---------------------------------------------------------------------------


class AdminConfig(T.TypedDict):
    """Admin configuration stored in admin.json."""

    password_hash: str
    salt: str


class UserProfile(T.TypedDict):
    """User profile stored in profile.json.

    - id: Unique identifier derived from name + role slug (e.g., 'maya-backend-engineer'),
          immutable, also the directory name
    - name: Short name (e.g., 'maya'), immutable, always unique
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


# Message type — using dict to avoid TypedDict complexity with reserved keywords
# Fields: id, thread_id, reply_to (optional), from, from_space (optional),
#         to, to_space (optional), ts, type, content
Message = dict[str, T.Any]


class SpaceConfig(T.TypedDict, total=False):
    """Space identity stored in space.json.

    - id: Unique immutable identifier (format: spc-{5-char}), required
    - name: Human-readable name, mutable, derived from directory at init, required
    - created: ISO timestamp of space creation, required
    - description: Optional human-readable description
    """

    id: T.Required[str]
    name: T.Required[str]
    created: T.Required[str]
    description: str


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
    as_user: str | None  # --as-user <user-id>: act as this user (admin only)
    json_output: bool  # whether --json was passed
