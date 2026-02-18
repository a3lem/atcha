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


_PREVIEW_LENGTH = 60


def _truncate(text: str, max_len: int = _PREVIEW_LENGTH) -> str:
    """Truncate text with ellipsis if longer than max_len."""
    if len(text) > max_len:
        return text[:max_len] + "..."
    return text


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
    elif hook_mode:
        # Hook mode: directive output with <atcha> tags so agents can identify
        # the source and act on it immediately.
        noun = "message" if count == 1 else "messages"
        msg_ids = " ".join(m["id"] for m in messages)
        lines: list[str] = [
            "<atcha>",
            f"You have {count} unread {noun} in your inbox.",
            "These are for you — read and respond directly.",
            "",
        ]
        for m in messages:
            formatted_sender, warning = _format_sender(m, local_space["id"], federation)
            if warning:
                warnings.add(warning)
            preview = _truncate(T.cast(str, m["content"]))
            lines.append(f"- **{formatted_sender}** ({m['id']}): {preview}")
        lines.append("")
        # Cap shown IDs to avoid an infinitely long command line
        max_ids = 3
        if count <= max_ids:
            lines.append(f"Next: `atcha messages read {msg_ids}`")
        else:
            shown_ids = " ".join(m["id"] for m in messages[:max_ids])
            elided = count - max_ids
            lines.append(f"Next: `atcha messages read {shown_ids} ...` ({elided} IDs elided)")
        lines.append("</atcha>")
        print("\n".join(lines))
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
    read_all = T.cast(bool, getattr(args, "read_all", False))
    target_ids = T.cast(list[str], getattr(args, "ids", []))

    # Must provide either --all or at least one message ID
    if not read_all and not target_ids:
        _error("at least one message ID required (or use --all)")
    target_ids_set = set(target_ids) if target_ids else None

    # Read all lines from inbox — we may need to rewrite with updated read flags
    all_lines = inbox.read_text().splitlines()
    matched_any = False
    json_array_msgs: list[dict[str, T.Any]] = []
    md_parts: list[str] = []

    for i, line in enumerate(all_lines):
        if not line.strip():
            continue
        try:
            msg = T.cast(Message, json.loads(line))
        except json.JSONDecodeError:
            continue

        # Filter: by explicit IDs, or by --all (match all unread)
        if target_ids_set is not None:
            if msg.get("id") not in target_ids_set:
                continue
        elif read_all:
            # --all mode: skip already-read messages
            if msg["read"]:
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
            # Compact markdown output: header line + content
            reply_suffix = ""
            reply_to = msg.get("reply_to")
            if reply_to is not None:
                reply_suffix = f" ↩ {reply_to}"
            md_parts.append(f"---\n**From:** {formatted_sender} · {msg['id']} · {msg['ts']}{reply_suffix}\n{msg['content']}")

    if not quiet:
        if auth.json_output:
            print(json.dumps(json_array_msgs, indent=2))
        elif md_parts:
            # Join with newline between blocks, bookend with separator
            print("\n".join(md_parts))
            print("---")

    # Rewrite inbox with updated read flags
    if matched_any and not no_mark:
        _ = inbox.write_text("\n".join(all_lines) + "\n")
        _update_last_seen(user_dir)

    # Print warnings for unknown spaces
    for warning in sorted(warnings):
        print(f"WARNING: {warning}", file=sys.stderr)


def cmd_messages_list(auth: AuthContext, args: argparse.Namespace) -> None:
    """List messages with previews. No side effects."""
    atcha_dir, user_id = _require_user(auth)
    user_dir = _get_user_dir(atcha_dir, user_id)

    # Include 'to' field when admin is acting as another user (useful for debugging)
    include_to_field = auth.as_user is not None

    inbox = user_dir / "messages" / "inbox.jsonl"

    if not inbox.exists() or inbox.stat().st_size == 0:
        if auth.json_output:
            print("[]")
        else:
            print("No messages")
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
    md_lines: list[str] = []

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

        # Format sender with @space suffix if cross-space
        formatted_sender, warning = _format_sender(msg, local_space["id"], federation)
        if warning:
            warnings.add(warning)

        content = T.cast(str, msg["content"])

        if auth.json_output:
            # JSON mode: build dict with preview or full content (unchanged behavior)
            if include_to_field:
                output: dict[str, T.Any] = dict(msg)
            else:
                output = {k: v for k, v in msg.items() if k != "to"}
            output["from"] = formatted_sender

            if no_preview:
                output["content"] = content
            else:
                if len(content) > 50:
                    output["preview"] = content[:50] + "..."
                else:
                    output["preview"] = content
            if not no_preview:
                output.pop("content", None)

            messages.append(output)
        else:
            # Markdown mode
            if no_preview:
                # Full content in block format (like read output)
                reply_suffix = ""
                reply_to = msg.get("reply_to")
                if reply_to is not None:
                    reply_suffix = f" ↩ {reply_to}"
                md_lines.append(f"---\n**From:** {formatted_sender} · {msg['id']} · {msg['ts']}{reply_suffix}\n{content}")
            else:
                # Compact one-liner with preview
                ts = T.cast(str, msg["ts"])
                # Extract time portion (HH:MM) from ISO timestamp
                time_part = ts[11:16] if len(ts) > 16 else ts
                preview = _truncate(content)
                md_lines.append(f"- **{formatted_sender}** ({msg['id']}, {time_part}): {preview}")

        # Check limit
        if limit and len(messages if auth.json_output else md_lines) >= limit:
            break

    if auth.json_output:
        print(json.dumps(messages, indent=2))
    elif md_lines:
        if no_preview:
            # Block format with trailing separator
            print("\n".join(md_lines))
            print("---")
        else:
            print("\n".join(md_lines))
    else:
        print("No messages")

    # Print warnings for unknown spaces
    for warning in sorted(warnings):
        print(f"WARNING: {warning}", file=sys.stderr)

    # Track activity
    _update_last_seen(user_dir)
