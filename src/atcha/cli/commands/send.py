"""Send message command."""

from __future__ import annotations

import argparse
import json
import sys
import typing as T
from pathlib import Path

from atcha.cli.auth import _require_user
from atcha.cli.errors import _error
from atcha.cli.federation import (
    _ensure_space_config,
    _get_sender_name,
    _resolve_user_cross_space,
)
from atcha.cli.store import (
    _get_display_name,
    _get_user_dir,
    _iter_user_names,
    _load_profile,
    _resolve_user,
    _update_last_seen,
)
from atcha.cli._types import AuthContext, Message, SpaceConfig
from atcha.cli.utils import _generate_message_id, _now_iso


def _find_message_by_id(atcha_dir: Path, user: str, msg_id: str) -> Message | None:
    """Find a message by ID in user's inbox or sent messages."""
    user_dir = _get_user_dir(atcha_dir, user)

    # Check inbox
    inbox_file = user_dir / "messages" / "inbox.jsonl"
    if inbox_file.exists():
        for line in inbox_file.read_text().splitlines():
            if not line.strip():
                continue
            try:
                msg = T.cast(Message, json.loads(line))
                if msg.get("id") == msg_id:
                    return msg
            except json.JSONDecodeError:
                continue

    # Check sent
    sent_file = user_dir / "messages" / "sent.jsonl"
    if sent_file.exists():
        for line in sent_file.read_text().splitlines():
            if not line.strip():
                continue
            try:
                msg = T.cast(Message, json.loads(line))
                if msg.get("id") == msg_id:
                    return msg
            except json.JSONDecodeError:
                continue

    return None


def _get_thread_participants(atcha_dir: Path, thread_id: str) -> list[str]:
    """Get all unique participants in a thread by searching all user inboxes and sent logs."""
    participants: set[str] = set()

    users_dir = atcha_dir / "users"
    if not users_dir.exists():
        return []

    # Search all user directories for messages in this thread
    for user_dir in users_dir.iterdir():
        if not user_dir.is_dir():
            continue

        for jsonl_name in ("inbox.jsonl", "sent.jsonl"):
            jsonl_file = user_dir / "messages" / jsonl_name
            if not jsonl_file.exists():
                continue
            for line in jsonl_file.read_text().splitlines():
                if not line.strip():
                    continue
                try:
                    msg = T.cast(Message, json.loads(line))
                    if msg.get("thread_id") != thread_id:
                        continue
                    # Add sender
                    if "from" in msg:
                        participants.add(_get_sender_name(msg))
                    # Add recipients
                    if "to" in msg:
                        to_field = msg["to"]
                        if isinstance(to_field, list):
                            participants.update(to_field)
                        else:
                            participants.add(to_field)
                except json.JSONDecodeError:
                    continue

    return sorted(participants)


def cmd_send(auth: AuthContext, args: argparse.Namespace) -> None:
    """Send message (local or cross-space)."""
    atcha_dir, sender = _require_user(auth)
    sender_dir = _get_user_dir(atcha_dir, sender)

    # Get sender's profile for their ID
    sender_profile = _load_profile(sender_dir)
    if sender_profile is None:
        _error(f"Could not load profile for sender '{sender}'")
    assert sender_profile is not None
    sender_id = sender_profile["id"]
    sender_name = sender_profile["name"]  # Display name for messages

    # Get local space config for from field
    local_space = _ensure_space_config(atcha_dir)

    content = T.cast(str, args.content)
    recipient_ids = T.cast(list[str] | None, args.recipients)
    send_broadcast = T.cast(bool, args.broadcast)
    reply_to_id = T.cast(str | None, args.reply_to)

    # Validate recipient combinations
    if send_broadcast and reply_to_id:
        _error(
            "Cannot use --broadcast with --reply-to (ambiguous)",
            fix="Use '--reply-to MSG_ID' to reply to thread participants, or '--broadcast' to broadcast to all contacts",
        )

    if recipient_ids and reply_to_id:
        _error(
            "Cannot use --to with --reply-to (reply always goes to all thread participants)",
            fix="Use '--reply-to MSG_ID' alone to reply to the thread, or '--to ADDRESS' without '--reply-to' to start a new conversation",
        )

    if not recipient_ids and not send_broadcast and not reply_to_id:
        _error(
            "No recipients specified",
            fix="Use '--to NAME', '--broadcast', or '--reply-to MSG_ID'",
        )

    # Resolved recipient: (user_id, target_atcha_dir, space_config, is_cross_space)
    resolved_recipients: list[tuple[str, Path, SpaceConfig, bool]] = []
    thread_id: str | None = None
    reply_to_msg: Message | None = None

    if reply_to_id:
        # Load the message we're replying to
        reply_to_msg = _find_message_by_id(atcha_dir, sender, reply_to_id)
        if reply_to_msg is None:
            _error(
                f"Message '{reply_to_id}' not found",
                fix="Check your inbox and sent messages for valid message IDs",
            )

        assert reply_to_msg is not None
        # Inherit thread_id from the message we're replying to
        thread_id = T.cast(str, reply_to_msg.get("thread_id") or reply_to_msg["id"])

        # Get thread participants
        thread_participants = _get_thread_participants(atcha_dir, thread_id)

        # Reply to all thread participants (excluding self).
        # Thread participants are display names (from message from.name and to fields).
        for p in thread_participants:
            if p != sender_name:
                resolved = _resolve_user(atcha_dir, p)
                if resolved is not None:
                    resolved_recipients.append((resolved, atcha_dir, local_space, False))

    elif send_broadcast:
        # Broadcast to all contacts (excluding self) — local only
        all_users = list(_iter_user_names(atcha_dir))
        for a in all_users:
            if a != sender:
                resolved_recipients.append((a, atcha_dir, local_space, False))

    elif recipient_ids:
        # Explicit recipients: resolve each name/id, potentially cross-space
        for recip_addr in recipient_ids:
            resolved = _resolve_user_cross_space(atcha_dir, recip_addr)
            if resolved is None:
                users = list(_iter_user_names(atcha_dir))
                _error(
                    f"User '{recip_addr}' not found",
                    available=users if users else None,
                )
            user_id, target_dir, space_config = resolved
            is_cross_space = space_config["id"] != local_space["id"]

            # Check if cross-space target is available
            if is_cross_space and not target_dir.is_dir():
                _error(
                    f"space unavailable: {space_config['name']} (path not found: {target_dir})",
                    fix="Re-register the space with correct path using 'admin federated add'",
                )

            resolved_recipients.append((user_id, target_dir, space_config, is_cross_space))

    # Remove duplicates while preserving order (by user_id + space_id)
    seen: set[tuple[str, str]] = set()
    unique_recipients: list[tuple[str, Path, SpaceConfig, bool]] = []
    for r in resolved_recipients:
        key = (r[0], r[2]["id"])  # (user_id, space_id)
        if key not in seen:
            seen.add(key)
            unique_recipients.append(r)
    resolved_recipients = unique_recipients

    if not resolved_recipients:
        _error(
            "No recipients after filtering",
            fix="Ensure you're not the only user, or that thread has other participants",
        )

    # Construct message
    ts = _now_iso()
    msg_id = _generate_message_id(sender, ts)

    # Determine thread_id: inherit from reply-to, or start new thread
    if thread_id is None:
        thread_id = msg_id  # First message in thread: thread_id = id

    # Build recipient display names list for the message (human-readable)
    recipient_names = [
        _get_display_name(target_dir, uid)
        for uid, target_dir, _sc, _xspace in resolved_recipients
    ]

    # Build structured sender info (stores both names and IDs for durability)
    sender_address = f"{sender_name}@{local_space['name']}"
    base_msg: Message = {
        "id": msg_id,
        "thread_id": thread_id,
        "from": {
            "name": sender_name,
            "id": sender_id,
            "address": sender_address,
            "space": {
                "name": local_space["name"],
                "id": local_space["id"],
            },
        },
        "to": recipient_names,
        "ts": ts,
        "type": "message",
        "content": content,
    }

    # Add reply_to field if replying
    if reply_to_id:
        base_msg["reply_to"] = reply_to_id

    # Write to each recipient's inbox
    for user_id, target_dir, space_config, is_cross_space in resolved_recipients:
        # For cross-space messages, add to_space field
        msg = dict(base_msg)
        if is_cross_space:
            msg["to_space"] = space_config["id"]

        line = json.dumps(msg, separators=(",", ":")) + "\n"

        recipient_user_dir = _get_user_dir(target_dir, user_id)
        recipient_inbox = recipient_user_dir / "messages" / "inbox.jsonl"
        try:
            with open(recipient_inbox, "a") as f:
                _ = f.write(line)
        except OSError as e:
            space_suffix = f"@{space_config['name']}" if is_cross_space else ""
            _error(f"Failed to write to {user_id}{space_suffix}'s inbox: {e}")

    # Write to sender sent log (use base message without to_space for sent log)
    sent_line = json.dumps(base_msg, separators=(",", ":")) + "\n"
    sender_sent = sender_dir / "messages" / "sent.jsonl"
    try:
        with open(sender_sent, "a") as f:
            _ = f.write(sent_line)
    except OSError as e:
        print(f"WARNING: Message delivered but sent log failed: {e}", file=sys.stderr)

    # Update sender's last_seen timestamp
    _update_last_seen(sender_dir)

    print(json.dumps({"status": "delivered", "to": recipient_names, "count": len(resolved_recipients), "ts": base_msg["ts"]}))
