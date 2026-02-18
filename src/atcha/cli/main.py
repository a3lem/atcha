"""CLI entry point and dispatch."""

from __future__ import annotations

import os
import sys
import typing as T

from atcha.cli.commands.admin import (
    cmd_admin_federated_add,
    cmd_admin_federated_remove,
    cmd_admin_hints,
    cmd_admin_onboard,
    cmd_admin_password,
    cmd_admin_prime,
    cmd_admin_spaces_list,
    cmd_admin_spaces_update,
    cmd_admin_users_delete,
    cmd_admin_users_list,
    cmd_admin_users_update,
    cmd_create_token,
    cmd_init,
    cmd_status,
    cmd_users_add,
)
from atcha.cli.commands.contacts import cmd_users_get, cmd_users_list
from atcha.cli.commands.env import cmd_env
from atcha.cli.commands.messages import (
    cmd_messages_check,
    cmd_messages_list,
    cmd_messages_read,
)
from atcha.cli.commands.profile import cmd_profile, cmd_whoami
from atcha.cli.commands.send import cmd_send
from atcha.cli.parser import _build_parser
from atcha.cli.store import _get_atcha_dir
from atcha.cli._types import AuthContext


def main() -> None:
    # Allow users to silence atcha entirely (e.g. when hooks are installed
    # globally but the current session shouldn't use atcha).
    if os.environ.get("ATCHA_DISABLED") == "1":
        sys.exit(0)

    parsers = _build_parser()

    # ---------- Parse and dispatch ----------
    args = parsers.main.parse_args()

    # Build auth context from parsed args (replaces globals)
    auth = AuthContext(
        token=T.cast(str | None, getattr(args, "token", None)),
        password=T.cast(str | None, getattr(args, "password", None)),
        as_user=T.cast(str | None, getattr(args, "as_user", None)),
        json_output=T.cast(bool, getattr(args, "json_output", False)),
    )

    if args.command is None:
        parsers.main.print_help()
        sys.exit(0)

    command = T.cast(str, args.command)

    # --- contacts ---
    if command == "contacts":
        contacts_sub = T.cast(str | None, getattr(args, "contacts_command", None))
        if contacts_sub == "show":
            cmd_users_get(auth, args)
        else:
            # bare 'contacts' = list
            cmd_users_list(auth, args)

    # --- messages ---
    elif command == "messages":
        msg_sub = T.cast(str | None, getattr(args, "messages_command", None))
        if msg_sub == "check":
            cmd_messages_check(auth, args)
        elif msg_sub == "read":
            cmd_messages_read(auth, args)
        else:
            # bare 'messages' = list
            cmd_messages_list(auth, args)

    # --- send ---
    elif command == "send":
        cmd_send(auth, args)

    # --- profile ---
    elif command == "profile":
        cmd_profile(auth, args)

    # --- whoami ---
    elif command == "whoami":
        cmd_whoami(auth, args)

    # --- admin ---
    elif command == "admin":
        admin_command = T.cast(str | None, getattr(args, "admin_command", None))
        if admin_command is None:
            parsers.admin.print_help()
            sys.exit(0)

        if admin_command == "status":
            quiet = T.cast(bool, getattr(args, "quiet", False))
            if quiet:
                # Exit code only — no output
                existing_dir = _get_atcha_dir()
                if existing_dir is not None and (existing_dir / "admin.json").exists():
                    sys.exit(0)
                else:
                    sys.exit(1)
            else:
                cmd_status(auth)
        elif admin_command == "init":
            cmd_init(args, auth)
        elif admin_command == "envs":
            cmd_env(auth)
        elif admin_command == "password":
            cmd_admin_password(auth, args)
        elif admin_command == "create-token":
            cmd_create_token(auth, args)
        elif admin_command == "hints":
            cmd_admin_hints(auth)
        elif admin_command == "prime":
            cmd_admin_prime(auth)
        elif admin_command == "onboard":
            cmd_admin_onboard(auth)
        elif admin_command == "users":
            users_sub = T.cast(str | None, getattr(args, "users_command", None))
            if users_sub == "create":
                cmd_users_add(auth, args)
            elif users_sub == "update":
                cmd_admin_users_update(auth, args)
            elif users_sub == "delete":
                cmd_admin_users_delete(auth, args)
            else:
                # bare 'admin users' = list
                cmd_admin_users_list(auth)

        elif admin_command == "spaces":
            spaces_sub = T.cast(str | None, getattr(args, "spaces_command", None))
            if spaces_sub == "update":
                cmd_admin_spaces_update(auth, args)
            elif spaces_sub == "add":
                cmd_admin_federated_add(auth, args)
            elif spaces_sub == "drop":
                cmd_admin_federated_remove(auth, args)
            else:
                # bare 'admin spaces' = list
                cmd_admin_spaces_list(auth)


if __name__ == "__main__":
    main()
