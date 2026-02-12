"""Structured error formatting and exit."""

from __future__ import annotations

import sys
import typing as T


def _error(msg: str, fix: str | None = None, available: list[str] | None = None) -> T.NoReturn:
    """Print structured error and exit."""
    print(f"ERROR: {msg}", file=sys.stderr)
    if available:
        print(f"AVAILABLE: {', '.join(available)}", file=sys.stderr)
    if fix:
        print(f"FIX: {fix}", file=sys.stderr)
    sys.exit(1)
