#!/bin/bash
# sync-skill.sh - Extract CLI help for comparison with SKILL.md
#
# Run this after CLI changes to see what documentation might need updating.
# The output is a reference to compare against SKILL.md, not a replacement.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_FILE="/tmp/team-mail-cli-reference.md"

echo "Extracting CLI help..."
echo ""

{
    echo "# CLI Reference (auto-generated)"
    echo ""
    echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo ""
    echo "## Main Help"
    echo ""
    echo '```'
    team-mail --help 2>/dev/null || uv run team-mail --help
    echo '```'
    echo ""

    echo "## Key Commands"
    echo ""

    for cmd in "agents" "agents list" "agents get" "send" "inbox" "inbox read" "profile" "profile update" "whoami"; do
        echo "### team-mail $cmd"
        echo ""
        echo '```'
        team-mail $cmd --help 2>/dev/null || uv run team-mail $cmd --help 2>/dev/null || echo "(help unavailable)"
        echo '```'
        echo ""
    done
} > "$OUTPUT_FILE"

echo "CLI reference extracted to: $OUTPUT_FILE"
echo ""
echo "Compare with: $PROJECT_ROOT/extras/claude-plugin/skills/team-mail/SKILL.md"
echo ""
echo "To view the reference:"
echo "  cat $OUTPUT_FILE"
echo ""
echo "Note: This is a reference for comparison, not a direct replacement."
echo "      SKILL.md contains hand-crafted examples and progressive disclosure structure."
