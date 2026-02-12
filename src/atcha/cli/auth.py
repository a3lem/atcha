"""Crypto, token management, and authentication."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import typing as T
from pathlib import Path

from atcha.cli.errors import _error
from atcha.cli.store import (
    _iter_user_names,
    _require_atcha_dir,
    _resolve_user,
)
from atcha.cli._types import (
    TOKEN_LENGTH,
    AdminConfig,
    AuthContext,
)
from atcha.cli.validation import _slugify_name


# ---------------------------------------------------------------------------
# Password hashing
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
# Token management
# ---------------------------------------------------------------------------

from atcha.cli.utils import TOKEN_ALPHABET


def _generate_user_id(name: str, role: str) -> str:
    """Generate a deterministic user ID from name and role.

    The user ID is the directory name: {name}-{slugify(role)}.
    This replaces the old random usr-xxxxx format.

    Examples:
        ('maya', 'Backend Engineer') -> 'maya-backend-engineer'
        ('alex', 'Frontend Dev')     -> 'alex-frontend-dev'
    """
    role_slug = _slugify_name(role)
    return f"{name}-{role_slug}"


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
    Admin does not use tokens — use password instead.
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

    result = _validate_token(atcha_dir, token)
    if result is None:
        _error("Invalid token", fix="Check your ATCHA_TOKEN value")

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
            # Resolve and verify the target user exists
            user_id = _resolve_user(atcha_dir, auth.as_user)
            if user_id is None:
                users = list(_iter_user_names(atcha_dir))
                _error(
                    f"User '{auth.as_user}' not found",
                    available=users if users else None,
                )
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
