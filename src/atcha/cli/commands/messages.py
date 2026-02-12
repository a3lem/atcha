"""Message check, read, and list commands."""

from __future__ import annotations

import argparse
import json
import sys
import typing as T

from atcha.cli.auth import _require_user
from atcha.cli.errors import _error
from atcha.cli.federation import (
    _ensure_space_config,
    _format_sender,
    _load_federation,
    _match_sender_address,
)
from atcha.cli.store import (
    _get_user_dir,
    _update_last_seen,
)
from atcha.cli._types import AuthContext, Message, MessagesState


def _get_message_content(msg: Message) -> str:
    """Get message content, with fallback for old 'body' field."""
    return T.cast(str, msg.get("content") or msg.get("body", ""))


def cmd_messages_check(auth: AuthContext) -> None:
    """Check inbox summary."""
    atcha_dir, user_name = _require_user(auth)

    user_dir = _get_user_dir(atcha_dir, user_name)
    inbox = user_dir / "messages" / "inbox.jsonl"

    if not inbox.exists() or inbox.stat().st_size == 0:
        if auth.json_output:
            print(json.dumps({"count": 0, "senders": {}}))
        else:
            print("No messages")
        return

    # Get last_read for unread filtering
    state_file = user_dir / "messages" / "state.json"
    last_read: str | None = None
    if state_file.exists():
        state = T.cast(MessagesState, json.loads(state_file.read_text()))
        last_read = state.get("last_read")

    # Load space info for cross-space sender formatting
    local_space = _ensure_space_config(atcha_dir)
    federation = _load_federation(atcha_dir)
    warnings: set[str] = set()

    # Collect and count messages
    messages: list[Message] = []
    sender_counts: dict[str, int] = {}

    for line in inbox.read_text().splitlines():
        if not line.strip():
            continue
        try:
            msg = T.cast(Message, json.loads(line))
        except json.JSONDecodeError:
            continue

        # Filter by last_read (show only unread)
        if last_read and msg["ts"] <= last_read:
            continue

        messages.append(msg)
        # Format sender with space suffix if cross-space
        formatted_sender, warning = _format_sender(msg, local_space["id"], federation)
        if warning:
            warnings.add(warning)
        sender_counts[formatted_sender] = sender_counts.get(formatted_sender, 0) + 1

    if not messages:
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

    state_file = user_dir / "messages" / "state.json"

    latest_ts: str | None = None
    json_array_msgs: list[dict[str, T.Any]] = []

    for line in inbox.read_text().splitlines():
        if not line.strip():
            continue
        try:
            msg = T.cast(Message, json.loads(line))
        except json.JSONDecodeError:
            continue

        # Filter by requested IDs (always required)
        if msg.get("id") not in target_ids_set:
            continue

        # Track latest timestamp
        if latest_ts is None or msg["ts"] > latest_ts:
            latest_ts = msg["ts"]

        # In quiet mode, skip output but still track timestamps for mark-as-read
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

    # Mark as read (unless --no-mark)
    if latest_ts is not None and not no_mark:
        state_data: MessagesState = {}
        if state_file.exists():
            state_data = T.cast(MessagesState, json.loads(state_file.read_text()))
        state_data["last_read"] = latest_ts
        _ = state_file.write_text(json.dumps(state_data) + "\n")

        # Update user's last_seen timestamp
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

    # Get last_read for unread filtering
    state_file = user_dir / "messages" / "state.json"
    last_read: str | None = None
    if not include_read and state_file.exists():
        state = T.cast(MessagesState, json.loads(state_file.read_text()))
        last_read = state.get("last_read")

    messages: list[dict[str, T.Any]] = []

    for line in inbox.read_text().splitlines():
        if not line.strip():
            continue
        try:
            msg = T.cast(Message, json.loads(line))
        except json.JSONDecodeError:
            continue

        # Filter by last_read (show only unread, unless --include-read)
        if last_read and msg["ts"] <= last_read:
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

        # Handle content/body field
        content = _get_message_content(msg)

        # Add preview or full content
        if no_preview:
            output["content"] = content
        else:
            # Truncate to 50 chars with ellipsis
            if len(content) > 50:
                output["preview"] = content[:50] + "..."
            else:
                output["preview"] = content

        # Remove old body field from output, we've handled it
        output.pop("body", None)
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
