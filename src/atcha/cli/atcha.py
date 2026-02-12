#!/usr/bin/env python
"""Backward-compatibility shim — delegates to the split modules.

Kept so that:
- ``python atcha.py`` still works (``__main__`` guard)
- Existing tests that ``import atcha.cli.atcha`` keep importing
- ``test_help.py`` can import ``_build_parser`` from here
"""

from __future__ import annotations

import sys
from pathlib import Path

# When run as a standalone script (python atcha.py), Python adds the script's
# directory (src/atcha/cli/) to sys.path[0].  That causes ``import atcha`` to
# find this file instead of the ``atcha`` package.  Fix by removing the script
# directory and inserting the src/ directory so package imports resolve correctly.
_cli_dir = str(Path(__file__).resolve().parent)
_src_dir = str(Path(__file__).resolve().parent.parent.parent)
if _cli_dir in sys.path:
    sys.path.remove(_cli_dir)
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

from atcha.cli.main import main  # noqa: F401, E402
from atcha.cli.parser import _build_parser  # noqa: F401, E402  # pyright: ignore[reportPrivateUsage]

if __name__ == "__main__":
    main()
