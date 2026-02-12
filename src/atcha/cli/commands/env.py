"""Env command (for hook discovery)."""

from __future__ import annotations

import sys

from atcha.cli.store import _get_atcha_dir
from atcha.cli._types import AuthContext


def cmd_env(_auth: AuthContext) -> None:
    """Auto-discover .atcha dir and print env exports."""
    atcha_dir = _get_atcha_dir()
    if atcha_dir is None:
        sys.exit(0)  # Silent — plugin inactive

    print(f'export ATCHA_DIR="{atcha_dir}"')
