"""Message check, read, and list commands."""

from __future__ import annotations

import argparse
import json
import sys
import typing as T

from atcha.cli.auth import _get_password, _get_token, _require_user
from atcha.cli.errors import _error
from atcha.cli.federation import (
    _ensure_space_config,
    _format_sender,
    _load_federation,
    _match_sender_address,
)
from atcha.cli.store import (
    _get_atcha_dir,
    _get_user_dir,
    _update_last_seen,
)
from atcha.cli._types import AuthContext, Message



def cmd_messages_check(auth: AuthContext, args: argparse.Namespace) -> None:
    """Check inbox summary."""
    hook_mode = T.cast(bool, getattr(args, "hook", False))

    # In hook mode, exit silently if atcha is not initialized or no
    # credentials are available — avoids noisy errors on every tool call.
    if hook_mode:
        if _get_atcha_dir() is None:
            return
        if not _get_password(auth) and not _get_token(auth):
            return

    atcha_dir, user_name = _require_user(auth)

    user_dir = _get_user_dir(atcha_dir, user_name)
    inbox = user_dir / "messages" / "inbox.jsonl"

    if not inbox.exists() or inbox.stat().st_size == 0:
        if hook_mode:
            return  # Silent — no output saves context tokens
        if auth.json_output:
            print(json.dumps({"count": 0, "senders": {}}))
        else:
            print("No messages")
        return

    # Load space info for cross-space sender formatting
    local_space = _ensure_space_config(atcha_dir)
    federation = _load_federation(atcha_dir)
    warnings: set[str] = set()

    # Collect and count unread messages
    messages: list[Message] = []
    sender_counts: dict[str, int] = {}

    for line in inbox.read_text().splitlines():
        if not line.strip():
            continue
        try:
            msg = T.cast(Message, json.loads(line))
        except json.JSONDecodeError:
            continue

        if msg["read"]:
            continue

        messages.append(msg)
        # Format sender with space suffix if cross-space
        formatted_sender, warning = _format_sender(msg, local_space["id"], federation)
        if warning:
            warnings.add(warning)
        sender_counts[formatted_sender] = sender_counts.get(formatted_sender, 0) + 1

    if not messages:
        if hook_mode:
            return  # Silent — no output saves context tokens
        if auth.json_output:
            print(json.dumps({"count": 0, "senders": {}}))
        else:
            print("No messages")
        return

    count = len(messages)

    if auth.json_output:
        print(json.dumps({"count": count, "senders": sender_counts}))
    else:
        if count == 1:
            formatted_sender, warning = _format_sender(messages[0], local_space["id"], federation)
            if warning:
                warnings.add(warning)
            print(f"1 unread message from {formatted_sender}")
        else:
            breakdown = ", ".join(
                f"{cnt} from {sender}"
                for sender, cnt in sorted(sender_counts.items(), key=lambda x: -x[1])
            )
            print(f"{count} unread messages: {breakdown}")

    # Print warnings for unknown spaces
    for warning in sorted(warnings):
        print(f"WARNING: {warning}", file=sys.stderr)

    # Track activity
    _update_last_seen(user_dir)


def cmd_messages_read(auth: AuthContext, args: argparse.Namespace) -> None:
    """Read full messages, mark as read."""
    atcha_dir, user_id = _require_user(auth)
    user_dir = _get_user_dir(atcha_dir, user_id)

    # Include 'to' field when admin is acting as another user (useful for debugging)
    include_to_field = auth.as_user is not None

    inbox = user_dir / "messages" / "inbox.jsonl"

    if not inbox.exists() or inbox.stat().st_size == 0:
        if auth.json_output:
            print("[]")
        return  # Silent exit for non-json

    # Load space info for cross-space sender formatting
    local_space = _ensure_space_config(atcha_dir)
    federation = _load_federation(atcha_dir)
    warnings: set[str] = set()

    # Parse filter options
    no_mark = T.cast(bool, getattr(args, "no_mark", False))
    quiet = T.cast(bool, getattr(args, "quiet", False))
    target_ids = T.cast(list[str], getattr(args, "ids", []))
    if not target_ids:
        _error("at least one message ID required")
    target_ids_set = set(target_ids)

    # Read all lines from inbox — we may need to rewrite with updated read flags
    all_lines = inbox.read_text().splitlines()
    matched_any = False
    json_array_msgs: list[dict[str, T.Any]] = []

    for i, line in enumerate(all_lines):
        if not line.strip():
            continue
        try:
            msg = T.cast(Message, json.loads(line))
        except json.JSONDecodeError:
            continue

        # Filter by requested IDs (always required)
        if msg.get("id") not in target_ids_set:
            continue

        matched_any = True

        # Mark as read in-place for later rewrite (unless --no-mark)
        if not no_mark:
            msg["read"] = True
            all_lines[i] = json.dumps(msg, separators=(",", ":"))

        # In quiet mode, skip output but still mark as read
        if quiet:
            continue

        # Prepare output (exclude 'to' field unless admin acting as user)
        if include_to_field:
            output: dict[str, T.Any] = dict(msg)
        else:
            output = {k: v for k, v in msg.items() if k != "to"}

        # Format sender with @space suffix if cross-space
        formatted_sender, warning = _format_sender(msg, local_space["id"], federation)
        if warning:
            warnings.add(warning)
        output["from"] = formatted_sender

        if auth.json_output:
            json_array_msgs.append(output)
        else:
            print(json.dumps(output, separators=(",", ":")))

    if not quiet and auth.json_output:
        print(json.dumps(json_array_msgs, indent=2))

    # Rewrite inbox with updated read flags
    if matched_any and not no_mark:
        _ = inbox.write_text("\n".join(all_lines) + "\n")
        _update_last_seen(user_dir)

    # Print warnings for unknown spaces
    for warning in sorted(warnings):
        print(f"WARNING: {warning}", file=sys.stderr)


def cmd_messages_list(auth: AuthContext, args: argparse.Namespace) -> None:
    """List messages as JSON array with previews. No side effects."""
    atcha_dir, user_id = _require_user(auth)
    user_dir = _get_user_dir(atcha_dir, user_id)

    # Include 'to' field when admin is acting as another user (useful for debugging)
    include_to_field = auth.as_user is not None

    inbox = user_dir / "messages" / "inbox.jsonl"

    if not inbox.exists() or inbox.stat().st_size == 0:
        print("[]")
        return

    # Load space info for cross-space sender formatting
    local_space = _ensure_space_config(atcha_dir)
    federation = _load_federation(atcha_dir)
    warnings: set[str] = set()

    # Parse filter options
    since_filter = T.cast(str | None, getattr(args, "since", None))
    from_filter = T.cast(str | None, getattr(args, "from_user", None))
    thread_filter = T.cast(str | None, getattr(args, "thread", None))
    limit = T.cast(int | None, getattr(args, "limit", None))
    include_read = T.cast(bool, getattr(args, "include_read", False))
    no_preview = T.cast(bool, getattr(args, "no_preview", False))
    ids_filter_raw = T.cast(list[str] | None, getattr(args, "ids", None))
    ids_filter = set(ids_filter_raw) if ids_filter_raw else None

    messages: list[dict[str, T.Any]] = []

    for line in inbox.read_text().splitlines():
        if not line.strip():
            continue
        try:
            msg = T.cast(Message, json.loads(line))
        except json.JSONDecodeError:
            continue

        if not include_read and msg["read"]:
            continue

        # Filter by --id (explicit message IDs)
        if ids_filter and msg.get("id") not in ids_filter:
            continue

        # Filter by --since
        if since_filter and msg["ts"] <= since_filter:
            continue

        # Filter by --from
        if from_filter and not _match_sender_address(msg, from_filter):
            continue

        # Filter by --thread
        if thread_filter and msg.get("thread_id") != thread_filter:
            continue

        # Prepare output
        if include_to_field:
            output: dict[str, T.Any] = dict(msg)
        else:
            output = {k: v for k, v in msg.items() if k != "to"}

        # Format sender with @space suffix if cross-space
        formatted_sender, warning = _format_sender(msg, local_space["id"], federation)
        if warning:
            warnings.add(warning)
        output["from"] = formatted_sender

        content = T.cast(str, msg["content"])

        # Add preview or full content
        if no_preview:
            output["content"] = content
        else:
            # Truncate to 50 chars with ellipsis
            if len(content) > 50:
                output["preview"] = content[:50] + "..."
            else:
                output["preview"] = content

        if not no_preview:
            output.pop("content", None)

        messages.append(output)

        # Check limit
        if limit and len(messages) >= limit:
            break

    print(json.dumps(messages, indent=2))

    # Print warnings for unknown spaces
    for warning in sorted(warnings):
        print(f"WARNING: {warning}", file=sys.stderr)

    # Track activity
    _update_last_seen(user_dir)
