#!/usr/bin/env python3
"""PreToolUse hook: check for new atcha messages and surface them in Claude's context.

Claude Code hooks require hookSpecificOutput with hookEventName to be recognized.
For PreToolUse hooks, the available fields are hookEventName, permissionDecision,
and additionalContext.
"""

from __future__ import annotations

import json
import subprocess
import sys


def main() -> None:
    # Extract event name from hook input JSON on stdin.
    hook_input = json.loads(sys.stdin.read())
    event: str = hook_input["hook_event_name"]

    # Run atcha messages check --hook; silent on failure or no output.
    result = subprocess.run(
        ["atcha", "messages", "check", "--hook"],
        capture_output=True,
        text=True,
    )
    output = result.stdout.strip()

    if not output:
        return

    # Wrap in the JSON envelope Claude Code expects.
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": event,
            "permissionDecision": "allow",
            "additionalContext": output,
        },
    }))


if __name__ == "__main__":
    main()
