"""Pure utilities with no internal dependencies."""

from __future__ import annotations

import hashlib
import secrets
import typing as T
from datetime import datetime, timezone

from atcha.cli._types import TOKEN_LENGTH, SPACE_ID_PREFIX


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _generate_message_id(sender: str, timestamp: str) -> str:
    """Generate a short unique message ID from sender, timestamp, and random salt."""
    salt = secrets.token_hex(4)  # 4 bytes = 8 hex chars of randomness
    data = f"{sender}:{timestamp}:{salt}".encode()
    hash_digest = hashlib.sha256(data).hexdigest()
    return f"msg-{hash_digest[:8]}"  # 8 char hex = ~4 billion possibilities


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
    except ValueError:
        return "unknown"


# Alphabet for token encoding (no ambiguous chars like 0/O, 1/l)
TOKEN_ALPHABET: T.Final[str] = "23456789abcdefghjkmnpqrstuvwxyz"


def _generate_space_id() -> str:
    """Generate a random space ID with spc- prefix.

    Format: spc-{5-char}, e.g., spc-a3k9m
    """
    chars = "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(TOKEN_LENGTH))
    return f"{SPACE_ID_PREFIX}{chars}"
