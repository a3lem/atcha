"""Tests for the custom tree-formatted CLI help."""

from __future__ import annotations

from atcha.cli.atcha import _build_parser  # pyright: ignore[reportPrivateUsage]
from atcha.cli.help import (
    CommandNode,
    build_command_tree,
    format_subtree_help,
    format_tree_help,
)

# ---------------------------------------------------------------------------
# Fixtures — build the real parser once and reuse across tests
# ---------------------------------------------------------------------------

_parsers = _build_parser()
_tree = build_command_tree(_parsers.main, name="atcha")


# ---------------------------------------------------------------------------
# Tree structure tests
# ---------------------------------------------------------------------------


def test_top_level_commands() -> None:
    """Top-level commands match the expected set."""
    names = [c.name for c in _tree.children]
    assert "contacts" in names
    assert "messages" in names
    assert "send" in names
    assert "profile" in names
    assert "whoami" in names
    assert "admin" in names


def test_contacts_has_show_child() -> None:
    contacts = _find_child(_tree, "contacts")
    assert contacts is not None
    child_names = [c.name for c in contacts.children]
    assert child_names == ["show"]


def test_messages_has_check_and_read() -> None:
    messages = _find_child(_tree, "messages")
    assert messages is not None
    child_names = [c.name for c in messages.children]
    assert "check" in child_names
    assert "read" in child_names


def test_admin_subcommand_tree() -> None:
    """Admin has the expected subcommands including nested users/spaces."""
    admin = _find_child(_tree, "admin")
    assert admin is not None
    admin_names = [c.name for c in admin.children]
    assert "init" in admin_names
    assert "status" in admin_names
    assert "users" in admin_names
    assert "spaces" in admin_names

    # Check nested users subcommands
    users = _find_child(admin, "users")
    assert users is not None
    users_names = [c.name for c in users.children]
    assert "create" in users_names
    assert "update" in users_names
    assert "delete" in users_names

    # Check nested spaces subcommands
    spaces = _find_child(admin, "spaces")
    assert spaces is not None
    spaces_names = [c.name for c in spaces.children]
    assert "update" in spaces_names
    assert "add" in spaces_names
    assert "drop" in spaces_names


def test_send_is_leaf() -> None:
    """send has no subcommands."""
    send = _find_child(_tree, "send")
    assert send is not None
    assert send.children == []


def test_whoami_is_leaf() -> None:
    whoami = _find_child(_tree, "whoami")
    assert whoami is not None
    assert whoami.children == []


# ---------------------------------------------------------------------------
# Key flag extraction tests
# ---------------------------------------------------------------------------


def test_auth_flags_excluded_from_user_commands() -> None:
    """User commands should NOT show inherited auth flags."""
    contacts = _find_child(_tree, "contacts")
    assert contacts is not None
    flag_str = " ".join(contacts.key_flags)
    assert "--token" not in flag_str
    assert "--password" not in flag_str
    assert "--as-user" not in flag_str


def test_optional_flags_excluded_from_tree() -> None:
    """Optional flags should NOT appear in key_flags (tree view)."""
    contacts = _find_child(_tree, "contacts")
    assert contacts is not None
    flag_str = " ".join(contacts.key_flags)
    # These are optional flags — should be absent from the tree
    assert "--include-self" not in flag_str
    assert "--full" not in flag_str
    assert "--tags" not in flag_str


def test_positional_shown_in_key_flags() -> None:
    """Positional arguments appear in key_flags."""
    send = _find_child(_tree, "send")
    assert send is not None
    assert "<content>" in send.key_flags


def test_positional_with_nargs_plus() -> None:
    """messages read should show <ids> ... for nargs='+'."""
    messages = _find_child(_tree, "messages")
    assert messages is not None
    read = _find_child(messages, "read")
    assert read is not None
    assert "<ids> ..." in read.key_flags


def test_required_flags_shown() -> None:
    """Required flags like --new on admin password should appear."""
    admin = _find_child(_tree, "admin")
    assert admin is not None
    pw = _find_child(admin, "password")
    assert pw is not None
    flag_str = " ".join(pw.key_flags)
    assert "--new" in flag_str


def test_whoami_mutex_flags_not_in_key_flags() -> None:
    """Mutually exclusive optional flags are omitted from tree view."""
    whoami = _find_child(_tree, "whoami")
    assert whoami is not None
    # --id and --name are optional mutex flags — should not appear
    assert whoami.key_flags == []


# ---------------------------------------------------------------------------
# Rendering tests
# ---------------------------------------------------------------------------


def test_full_tree_output_contains_user_commands() -> None:
    """format_tree_help should contain all user-facing command names."""
    output = format_tree_help(_tree, "atcha", "Test description", "0.1.0", width=120)
    for cmd in ("contacts", "messages", "send", "profile", "whoami", "admin"):
        assert cmd in output, f"Missing top-level command: {cmd}"
    # Nested user commands should be visible
    for cmd in ("show", "check", "read", "update"):
        assert cmd in output, f"Missing nested command: {cmd}"


def test_admin_children_collapsed_by_default() -> None:
    """Admin subcommands should NOT appear in top-level help (collapsed)."""
    output = format_tree_help(_tree, "atcha", "Test", "0.1.0", width=120)
    assert "admin" in output
    # These are admin subcommands — should be hidden in top-level
    lines = output.split("\n")
    # Find admin line and check that no admin children follow it
    admin_idx = next(i for i, l in enumerate(lines) if "admin" in l)
    # Lines after admin should be footer, not admin subcommands
    for line in lines[admin_idx + 1 :]:
        if line.strip() == "":
            break  # reached footer separator
        # If we hit an indented line, it should NOT be an admin subcommand
        assert "init" not in line, "admin init should be collapsed"
        assert "users" not in line, "admin users should be collapsed"


def test_admin_expanded_when_not_collapsed() -> None:
    """Passing collapse=frozenset() should show admin children."""
    output = format_tree_help(
        _tree, "atcha", "Test", "0.1.0", width=120, collapse=frozenset()
    )
    assert "init" in output
    assert "users" in output
    assert "spaces" in output


def test_no_tree_drawing_characters() -> None:
    """Output should use plain indentation, no tree-drawing characters."""
    output = format_tree_help(_tree, "atcha", "Test", "0.1.0", width=120)
    assert "\u251c" not in output  # ├
    assert "\u2514" not in output  # └
    assert "\u2502" not in output  # │


def test_indentation_based_hierarchy() -> None:
    """Child commands should be indented relative to their parent."""
    output = format_tree_help(
        _tree, "atcha", "Test", "0.1.0", width=120, collapse=frozenset()
    )
    lines = output.split("\n")

    # Find 'contacts' and 'show' lines
    contacts_line = next(l for l in lines if l.strip().startswith("contacts"))
    show_line = next(l for l in lines if l.strip().startswith("show"))

    contacts_indent = len(contacts_line) - len(contacts_line.lstrip())
    show_indent = len(show_line) - len(show_line.lstrip())

    # show should be indented 2 more spaces than contacts
    assert show_indent == contacts_indent + 2


def test_full_tree_has_header_and_footer() -> None:
    output = format_tree_help(_tree, "atcha", "Test description", "0.1.0", width=120)
    assert "atcha v0.1.0 -- Test description" in output
    assert "Usage: atcha <command> [options]" in output
    assert "Auth:" in output
    assert "Run 'atcha <command> --help'" in output


def test_subtree_output_admin() -> None:
    admin = _find_child(_tree, "admin")
    assert admin is not None
    output = format_subtree_help(admin, "atcha", width=120)
    assert "atcha admin --" in output
    assert "Subcommands:" in output
    assert "init" in output
    assert "users" in output
    assert "spaces" in output
    # Auth should show password-first (base_auth, no --as-user)
    assert "--password PW | --token TOKEN" in output
    assert "--as-user" not in output


def test_subtree_output_messages() -> None:
    messages = _find_child(_tree, "messages")
    assert messages is not None
    output = format_subtree_help(messages, "atcha", width=120)
    assert "check" in output
    assert "read" in output
    # Messages has user_auth, so should show --as-user
    assert "--as-user" in output
    # Options section should list own flags
    assert "Options:" in output
    assert "--from" in output
    assert "--since" in output


def test_width_truncation() -> None:
    """Command tree lines should be truncated when width is narrow."""
    output = format_tree_help(_tree, "atcha", "Test", "0.1.0", width=60)
    # Check only the command tree lines (indented with 2+ spaces)
    tree_lines = [line for line in output.split("\n") if line.startswith("  ")]
    assert len(tree_lines) > 0, "Expected indented tree lines"
    for line in tree_lines:
        assert len(line) <= 60, f"Tree line exceeds width: {line!r}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_child(node: CommandNode, name: str) -> CommandNode | None:
    """Find a direct child node by name."""
    for child in node.children:
        if child.name == name:
            return child
    return None
