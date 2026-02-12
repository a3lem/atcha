"""Custom help for the atcha CLI.

Replaces argparse's default help output with a clean, indented command
list showing the full hierarchy.  Generated from the actual parser
structure so it stays in sync automatically.

Why a separate module: atcha.py is already ~3k lines and the help
formatter is a self-contained concern with a clear interface.
"""

from __future__ import annotations

import argparse
import dataclasses
import os
import shutil
import sys
import typing as T


# ---------------------------------------------------------------------------
# Auth flag destinations — excluded from per-command flag display when
# the parser inherited them from base_auth / user_auth.  Detected via
# the presence of a --token action (sentinel).
# ---------------------------------------------------------------------------

_AUTH_DESTS: frozenset[str] = frozenset({
    "token", "password", "json_output", "as_user",
})


# ---------------------------------------------------------------------------
# Color theme — matches the Python 3.14 argparse palette so that custom
# and standard help pages look consistent.
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class _Theme:
    """ANSI color codes for help output."""

    prog: str       # program name
    heading: str    # section headers (Commands:, Options:, …)
    action: str     # command names in the tree
    label: str      # positional args / metavars
    option: str     # --flags
    reset: str


_COLOR = _Theme(
    prog="\x1b[1;35m",       # bold magenta
    heading="\x1b[1;34m",    # bold blue
    action="\x1b[32m",       # green
    label="\x1b[33m",        # yellow
    option="\x1b[36m",       # cyan
    reset="\x1b[0m",
)

_NO_COLOR = _Theme(prog="", heading="", action="", label="", option="", reset="")


def _get_theme() -> _Theme:
    """Return a colored theme when stdout is a color-capable TTY, else no-op.

    Delegates to CPython's ``_colorize.can_colorize`` when available (3.13+),
    falling back to a manual ``isatty`` / ``NO_COLOR`` check otherwise.
    """
    try:
        from _colorize import can_colorize  # type: ignore[import-not-found]  # CPython internal
        return _COLOR if can_colorize() else _NO_COLOR
    except ImportError:
        if os.environ.get("NO_COLOR"):
            return _NO_COLOR
        if hasattr(sys.stdout, "isatty") and sys.stdout.isatty():
            return _COLOR
        return _NO_COLOR


def _color_flag(flag: str, t: _Theme) -> str:
    """Colorize a single key-flag string (e.g. ``'<name>'`` or ``'--to ADDR'``)."""
    if not t.reset:  # no-color fast path
        return flag
    if flag.startswith("<"):
        return f"{t.label}{flag}{t.reset}"
    if flag.startswith("-"):
        parts = flag.split(" ", 1)
        colored = f"{t.option}{parts[0]}{t.reset}"
        if len(parts) > 1:
            colored += f" {t.label}{parts[1]}{t.reset}"
        return colored
    return flag


# ---------------------------------------------------------------------------
# Intermediate representation
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class CommandNode:
    """A node in the command tree, extracted from an argparse parser."""

    name: str
    help_text: str
    parser: argparse.ArgumentParser
    # Minimal flags for tree display: positionals + required flags only.
    key_flags: list[str]
    children: list[CommandNode]


# ---------------------------------------------------------------------------
# Tree building — walks argparse internals
# ---------------------------------------------------------------------------

# We access argparse private attributes (_actions, _SubParsersAction, etc.)
# because there is no public API for parser introspection.  These have been
# stable across Python 3.8–3.13.


def _has_action_dest(parser: argparse.ArgumentParser, dest: str) -> bool:
    """Return True if *parser* has an action with the given dest."""
    return any(a.dest == dest for a in parser._actions)


def _extract_key_flags(parser: argparse.ArgumentParser) -> list[str]:
    """Extract positional args and required flags for tree display.

    Optional flags are omitted from the tree view — they belong in
    per-command descriptions or ``--help`` output.
    """
    skip_dests: frozenset[str] = (
        _AUTH_DESTS if _has_action_dest(parser, "token") else frozenset[str]()
    )

    flags: list[str] = []
    for action in parser._actions:
        # Skip meta-actions
        if isinstance(action, (
            argparse._HelpAction,       # pyright: ignore[reportPrivateUsage]
            argparse._VersionAction,    # pyright: ignore[reportPrivateUsage]
            argparse._SubParsersAction,  # pyright: ignore[reportPrivateUsage]
        )):
            continue
        if action.dest in skip_dests:
            continue

        # Positional arguments
        if not action.option_strings:
            label = f"<{action.dest}>"
            if action.nargs in ("+", "*", argparse.REMAINDER):
                label += " ..."
            flags.append(label)
            continue

        # Required flags only — optional flags stay out of the tree
        if not action.required:
            continue

        long = action.option_strings[-1]  # prefer --long over -s
        if isinstance(action, argparse._StoreTrueAction):  # pyright: ignore[reportPrivateUsage]
            flags.append(long)
        else:
            metavar = str(action.metavar) if action.metavar else f"<{action.dest}>"
            flags.append(f"{long} {metavar}")

    return flags


def build_command_tree(
    parser: argparse.ArgumentParser,
    name: str = "",
) -> CommandNode:
    """Recursively walk an argparse parser and build a CommandNode tree."""
    sub_action: argparse._SubParsersAction[argparse.ArgumentParser] | None = None  # pyright: ignore[reportPrivateUsage]
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):  # pyright: ignore[reportPrivateUsage]
            sub_action = T.cast("argparse._SubParsersAction[argparse.ArgumentParser]", action)  # pyright: ignore[reportPrivateUsage]
            break

    children: list[CommandNode] = []
    if sub_action is not None:
        # Help-text lookup from _choices_actions — the one-liner set via
        # add_parser(help=...).
        help_lookup: dict[str, str] = {}
        for choice_action in sub_action._choices_actions:
            key = choice_action.metavar
            if isinstance(key, str):
                help_lookup[key] = choice_action.help or ""

        for child_name, child_parser in sub_action.choices.items():
            child_node = build_command_tree(child_parser, name=str(child_name))
            if str(child_name) in help_lookup:
                child_node.help_text = help_lookup[str(child_name)]
            children.append(child_node)

    return CommandNode(
        name=name,
        help_text=parser.description or "",
        parser=parser,
        key_flags=_extract_key_flags(parser),
        children=children,
    )


# ---------------------------------------------------------------------------
# Rendering — clean indentation, no tree-drawing characters
# ---------------------------------------------------------------------------

_INDENT = "  "
_GAP = 4  # minimum spaces between command column and help text


def _compute_max_left(
    nodes: list[CommandNode],
    depth: int,
    collapse: frozenset[str],
) -> int:
    """Compute the maximum left-column width across all visible nodes."""
    max_w = 0
    for node in nodes:
        prefix = _INDENT * depth
        flag_str = " ".join(node.key_flags)
        left = f"{prefix}{node.name} {flag_str}" if flag_str else f"{prefix}{node.name}"
        max_w = max(max_w, len(left))

        if node.children and node.name not in collapse:
            child_max = _compute_max_left(node.children, depth + 1, collapse)
            max_w = max(max_w, child_max)

    return max_w


def _render_lines(
    nodes: list[CommandNode],
    depth: int,
    max_left: int,
    width: int,
    collapse: frozenset[str],
    t: _Theme,
) -> list[str]:
    """Render command nodes as indented lines with aligned descriptions."""
    lines: list[str] = []

    for node in nodes:
        prefix = _INDENT * depth
        flag_str = " ".join(node.key_flags)
        # Plain-text left column — used for width/padding calculations.
        plain_left = f"{prefix}{node.name} {flag_str}" if flag_str else f"{prefix}{node.name}"

        # Colored variant — ANSI codes don't affect alignment because
        # padding is derived from the plain-text width above.
        colored_name = f"{t.action}{node.name}{t.reset}"
        colored_flags = " ".join(_color_flag(f, t) for f in node.key_flags)
        colored_left = (
            f"{prefix}{colored_name} {colored_flags}" if colored_flags
            else f"{prefix}{colored_name}"
        )

        padding = max_left - len(plain_left) + _GAP

        # Truncate the help text (never the colored left column) to fit.
        help_text = node.help_text
        avail = width - len(plain_left) - padding
        if avail > 3 and len(help_text) > avail:
            help_text = help_text[: avail - 3] + "..."

        lines.append(f"{colored_left}{' ' * padding}{help_text}")

        # Recurse unless this command is collapsed
        if node.children and node.name not in collapse:
            lines.extend(
                _render_lines(node.children, depth + 1, max_left, width, collapse, t)
            )

    return lines


def format_tree_help(
    root: CommandNode,
    prog: str,
    description: str,
    version: str,
    width: int | None = None,
    *,
    collapse: frozenset[str] | None = None,
) -> str:
    """Render the full command list for ``atcha --help``.

    Commands named in *collapse* show only their own line — children
    are deferred to ``atcha <command> --help``.  Defaults to collapsing
    ``admin`` since most users are regular users, not admins.
    """
    term_width = width or shutil.get_terminal_size().columns
    _collapse = collapse if collapse is not None else frozenset({"admin"})
    t = _get_theme()

    parts: list[str] = []

    # Header
    parts.append(f"{t.prog}{prog}{t.reset} v{version} -- {description}")
    parts.append("")
    parts.append(f"{t.heading}Usage:{t.reset} {t.prog}{prog}{t.reset} <command> [options]")
    parts.append("")
    parts.append(f"{t.heading}Commands:{t.reset}")

    max_left = min(
        _compute_max_left(root.children, 1, _collapse), 50
    )
    lines = _render_lines(root.children, 1, max_left, term_width, _collapse, t)
    parts.extend(lines)

    # Footer
    parts.append("")
    parts.append(f"{t.heading}Auth:{t.reset} --token TOKEN (user) | --password PW (admin) [--json]")
    parts.append("Structured output: Need JSON? All commands provide a --json option")
    parts.append(f"Run '{t.prog}{prog}{t.reset} <command> --help' for command-specific help.")

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Subtree help — for branch commands like ``atcha admin --help``
# ---------------------------------------------------------------------------


def _extract_all_flags(
    parser: argparse.ArgumentParser,
) -> list[tuple[str, str]]:
    """Extract all non-auth flags with help text for the Options section.

    Returns (flag_display, help_text) pairs.
    """
    skip_dests: frozenset[str] = (
        _AUTH_DESTS if _has_action_dest(parser, "token") else frozenset[str]()
    )

    results: list[tuple[str, str]] = []
    for action in parser._actions:
        if isinstance(action, (
            argparse._HelpAction,       # pyright: ignore[reportPrivateUsage]
            argparse._VersionAction,    # pyright: ignore[reportPrivateUsage]
            argparse._SubParsersAction,  # pyright: ignore[reportPrivateUsage]
        )):
            continue
        if action.dest in skip_dests:
            continue

        help_text = action.help or ""

        # Positional
        if not action.option_strings:
            label = f"<{action.dest}>"
            if action.nargs in ("+", "*", argparse.REMAINDER):
                label += " ..."
            results.append((label, help_text))
            continue

        # Optional / required flag
        long = action.option_strings[-1]
        if isinstance(action, argparse._StoreTrueAction):  # pyright: ignore[reportPrivateUsage]
            results.append((long, help_text))
        else:
            metavar = str(action.metavar) if action.metavar else action.dest.upper()
            results.append((f"{long} {metavar}", help_text))

    return results


def format_subtree_help(
    node: CommandNode,
    prog: str,
    width: int | None = None,
) -> str:
    """Render help for a branch command (e.g. ``atcha admin --help``).

    Shows the subtree with indentation (no collapse — the user
    explicitly asked for this command's help).
    """
    term_width = width or shutil.get_terminal_size().columns
    t = _get_theme()

    parts: list[str] = []

    # Header — prefer the parser's description (longer) over
    # help_text (the one-liner from the parent's add_parser).
    header_text = node.parser.description or node.help_text
    parts.append(f"{t.prog}{prog} {node.name}{t.reset} -- {header_text}")
    parts.append("")

    # Subcommands — never collapsed within subtree help
    if node.children:
        parts.append(f"{t.heading}Subcommands:{t.reset}")
        no_collapse: frozenset[str] = frozenset()
        max_left = min(
            _compute_max_left(node.children, 1, no_collapse), 50
        )
        lines = _render_lines(
            node.children, 1, max_left, term_width, no_collapse, t,
        )
        parts.extend(lines)

    # Options — all non-auth flags from this branch parser itself
    own_options = _extract_all_flags(node.parser)
    if own_options:
        parts.append("")
        parts.append(f"{t.heading}Options:{t.reset}")
        opt_max = max(len(flag) for flag, _ in own_options)
        for flag, help_text in own_options:
            padding = opt_max - len(flag) + _GAP
            colored = _color_flag(flag, t)
            parts.append(f"  {colored}{' ' * padding}{help_text}")

    # Auth footer — detect which auth parent was inherited
    has_as_user = _has_action_dest(node.parser, "as_user")
    has_token = _has_action_dest(node.parser, "token")
    if has_token and has_as_user:
        parts.append("")
        parts.append(f"{t.heading}Auth:{t.reset} --token TOKEN | --password PW [--as-user USR-ID] [--json]")
    elif has_token:
        parts.append("")
        parts.append(f"{t.heading}Auth:{t.reset} --password PW | --token TOKEN [--json]")

    parts.append("")
    parts.append(f"Run '{t.prog}{prog} {node.name}{t.reset} <subcommand> --help' for details.")

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Installation — patches print_help() on branch parsers
# ---------------------------------------------------------------------------


def install_tree_help(
    root_parser: argparse.ArgumentParser,
    prog: str,
    description: str,
    version: str,
    *,
    collapse: frozenset[str] | None = None,
) -> None:
    """Walk the parser tree and replace print_help() on all branch parsers.

    Branch parsers (those with subcommand children) get custom help.
    Leaf parsers keep argparse's default help unchanged.
    """
    root = build_command_tree(root_parser, name=prog)
    _collapse = collapse if collapse is not None else frozenset({"admin"})

    def _root_help(file: T.IO[str] | None = None) -> None:
        output = format_tree_help(
            root, prog, description, version, collapse=_collapse,
        )
        print(output, file=file or sys.stdout)

    root_parser.print_help = _root_help  # type: ignore[assignment]  # pyright: ignore[reportAttributeAccessIssue]

    # Recursively patch branch parsers
    _patch_branches(root, prog)


def _patch_branches(node: CommandNode, prog_prefix: str) -> None:
    """Recursively patch print_help on branch (non-leaf) child nodes."""
    for child in node.children:
        if child.children:
            # Factory to capture loop variable in the closure.
            def _make_help(
                n: CommandNode, p: str,
            ) -> T.Callable[[T.IO[str] | None], None]:
                def _help(file: T.IO[str] | None = None) -> None:
                    output = format_subtree_help(n, p)
                    print(output, file=file or sys.stdout)
                return _help

            child.parser.print_help = _make_help(child, prog_prefix)  # type: ignore[assignment]  # pyright: ignore[reportAttributeAccessIssue]

            child_prog = f"{prog_prefix} {child.name}"
            _patch_branches(child, child_prog)
