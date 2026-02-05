"""Tests for atcha.py CLI with token-based authentication."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import typing as T
from pathlib import Path

import pytest

CLI: T.Final[str] = str(Path(__file__).resolve().parent.parent / "src" / "atcha" / "cli" / "atcha.py")
PASSWORD: T.Final[str] = "testpass123"


def run_cli(
    *args: str,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run the atcha CLI with the given arguments."""
    full_env = {**os.environ, **(env if env is not None else {})}
    return subprocess.run(
        [sys.executable, CLI, *args],
        capture_output=True,
        text=True,
        env=full_env,
        cwd=cwd,
    )


@pytest.fixture
def atcha_dir(tmp_path: Path) -> Path:
    """Create and initialize a .atcha directory."""
    # Initialize the directory
    result = run_cli("init", f"--password={PASSWORD}", cwd=str(tmp_path))
    assert result.returncode == 0, result.stderr
    return tmp_path / ".atcha"


def _admin_env(atcha_dir: Path) -> dict[str, str]:
    """Return env dict for admin operations."""
    return {"ATCHA_ADMIN_PASS": PASSWORD, "ATCHA_DIR": str(atcha_dir)}


def _create_user(
    atcha_dir: Path,
    name: str,
    role: str = "Test Agent",
) -> str:
    """Create a user and return their token."""
    cwd = atcha_dir.parent
    env = _admin_env(atcha_dir)

    # Create user (returns profile with generated id)
    result = run_cli("admin", "users", "add", f"--name={name}", f"--role={role}", env=env, cwd=str(cwd))
    assert result.returncode == 0, result.stderr

    # Extract the user name from the profile (directory name for token lookup)
    profile = json.loads(result.stdout)
    user_name = profile["name"]  # This is the directory name / token name

    # Get user token using the name (which is the token file name)
    result = run_cli("create-token", "--user", user_name, env=env, cwd=str(cwd))
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


# ---------- init ----------


class TestInit:
    def test_creates_structure(self, tmp_path: Path) -> None:
        result = run_cli("init", f"--password={PASSWORD}", cwd=str(tmp_path))
        assert result.returncode == 0
        assert "Initialized" in result.stdout

        atcha_dir = tmp_path / ".atcha"
        assert atcha_dir.is_dir()
        assert (atcha_dir / "admin.json").exists()
        assert (atcha_dir / "tokens").is_dir()
        assert (atcha_dir / "users").is_dir()

    def test_fails_if_already_initialized(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent
        result = run_cli("init", f"--password={PASSWORD}", cwd=str(cwd))
        assert result.returncode != 0
        assert "Already initialized" in result.stderr

    def test_prompts_for_password(self, tmp_path: Path) -> None:
        # Without --password, it should attempt interactive prompt
        # In non-interactive mode (CI), this will fail with EOF
        result = run_cli("init", cwd=str(tmp_path))
        # Should either prompt or fail gracefully
        # Since tests run non-interactively, expect failure
        assert result.returncode != 0

    def test_check_returns_0_when_initialized(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent
        result = run_cli("init", "--check", cwd=str(cwd))
        assert result.returncode == 0
        assert "Atcha initialized" in result.stdout

    def test_check_returns_1_when_not_initialized(self, tmp_path: Path) -> None:
        result = run_cli("init", "--check", cwd=str(tmp_path))
        assert result.returncode == 1
        assert result.stdout == ""


# ---------- admin password ----------


class TestAdminPassword:
    def test_changes_password(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent
        result = run_cli(
            "admin", "password",
            f"--old={PASSWORD}",
            "--new=newpass123",
            cwd=str(cwd),
        )
        assert result.returncode == 0
        assert "Password updated" in result.stdout

        # Old password should fail
        old_env = {"ATCHA_DIR": str(atcha_dir), "ATCHA_ADMIN_PASS": PASSWORD}
        result = run_cli(
            "admin", "users", "add", "--name=test-user", "--role=Test",
            env=old_env, cwd=str(cwd),
        )
        assert result.returncode != 0

        # New password should work
        new_env = {"ATCHA_DIR": str(atcha_dir), "ATCHA_ADMIN_PASS": "newpass123"}
        result = run_cli(
            "admin", "users", "add", "--name=test-user", "--role=Test",
            env=new_env, cwd=str(cwd),
        )
        assert result.returncode == 0

    def test_rejects_wrong_password(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent
        result = run_cli(
            "admin", "password",
            "--old=wrongpass",
            "--new=newpass123",
            cwd=str(cwd),
        )
        assert result.returncode != 0
        assert "Invalid password" in result.stderr


# ---------- create-token ----------


class TestCreateToken:
    def test_creates_agent_token(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)

        # Create user first
        result = run_cli("admin", "users", "add", "--name=test-user", "--role=Test", env=env, cwd=str(cwd))
        assert result.returncode == 0

        # Create token using --password
        result = run_cli("create-token", "--user", "test-user", f"--password={PASSWORD}", cwd=str(cwd))
        assert result.returncode == 0
        token = result.stdout.strip()
        assert len(token) == 5

    def test_creates_agent_token_via_env(self, atcha_dir: Path) -> None:
        """ATCHA_ADMIN_PASS env var works for create-token."""
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)

        # Create user first
        result = run_cli("admin", "users", "add", "--name=test-user", "--role=Test", env=env, cwd=str(cwd))
        assert result.returncode == 0

        # Create token using env var (no --password)
        result = run_cli("create-token", "--user", "test-user", env=env, cwd=str(cwd))
        assert result.returncode == 0
        token = result.stdout.strip()
        assert len(token) == 5

    def test_rejects_nonexistent_user(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent
        result = run_cli("create-token", "--user", "nobody", f"--password={PASSWORD}", cwd=str(cwd))
        assert result.returncode != 0
        assert "not found" in result.stderr

    def test_token_is_deterministic(self, atcha_dir: Path) -> None:
        """Same password + agent always produces the same token."""
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)

        # Create user
        result = run_cli("admin", "users", "add", "--name=test-user", "--role=Test", env=env, cwd=str(cwd))
        assert result.returncode == 0

        # Create token twice - should get same result
        result1 = run_cli("create-token", "--user", "test-user", f"--password={PASSWORD}", cwd=str(cwd))
        assert result1.returncode == 0
        token1 = result1.stdout.strip()

        result2 = run_cli("create-token", "--user", "test-user", f"--password={PASSWORD}", cwd=str(cwd))
        assert result2.returncode == 0
        token2 = result2.stdout.strip()

        assert token1 == token2

    def test_token_stored_as_hash(self, atcha_dir: Path) -> None:
        """Token file contains hash, not plaintext token."""
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)

        # Create user and token
        result = run_cli("admin", "users", "add", "--name=test-user", "--role=Test", env=env, cwd=str(cwd))
        assert result.returncode == 0

        result = run_cli("create-token", "--user", "test-user", f"--password={PASSWORD}", cwd=str(cwd))
        assert result.returncode == 0
        token = result.stdout.strip()

        # Read token file - should be a hash, not the token itself
        token_file = atcha_dir / "tokens" / "test-user"
        stored = token_file.read_text().strip()

        # The stored value should NOT be the token (it should be a hash)
        assert stored != token
        # SHA-256 hash is 64 hex characters
        assert len(stored) == 64


# ---------- agents add ----------


class TestAgentsAdd:
    def test_creates_agent(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)

        result = run_cli(
            "admin", "users", "add", "--name=maya", "--role=Backend Engineer",
            "--status=Working on auth",
            "--tags=backend,auth",
            env=env, cwd=str(cwd),
        )
        assert result.returncode == 0

        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert len(profile["id"]) == 5  # Random 5-char id
        assert profile["name"] == "maya"
        assert profile["role"] == "Backend Engineer"
        assert profile["status"] == "Working on auth"
        assert profile["tags"] == ["backend", "auth"]

        # Check directory structure (uses name as directory, not id)
        user_dir = atcha_dir / "users" / "maya"
        assert user_dir.is_dir()
        assert (user_dir / "profile.json").exists()
        assert (user_dir / "mail" / "inbox.jsonl").exists()

    def test_requires_admin_token(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent
        # No token
        result = run_cli("admin", "users", "add", "--name=test-user", "--role=Test", cwd=str(cwd))
        assert result.returncode != 0
        assert "ATCHA_TOKEN" in result.stderr

    def test_rejects_user_token(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent
        admin_env = _admin_env(atcha_dir)

        # Create user and get their token
        _ = run_cli("admin", "users", "add", "--name=testuser", "--role=Test", env=admin_env, cwd=str(cwd))
        result = run_cli("create-token", "--user", "testuser", env=admin_env, cwd=str(cwd))
        user_token = result.stdout.strip()

        # Try to create with user token (no admin password in env)
        user_env = {"ATCHA_TOKEN": user_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("admin", "users", "add", "--name=another", "--role=Test", env=user_env, cwd=str(cwd))
        assert result.returncode != 0
        assert ("Admin" in result.stderr or "token required" in result.stderr)  # Error about auth

    def test_validates_username(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)

        # Too short
        result = run_cli("admin", "users", "add", "--name=ab", "--role=Test", env=env, cwd=str(cwd))
        assert result.returncode != 0
        assert "at least 3" in result.stderr

        # Invalid chars
        result = run_cli("admin", "users", "add", "--name=User-Name", "--role=Test", env=env, cwd=str(cwd))
        assert result.returncode != 0
        assert "lowercase" in result.stderr

    def test_fails_if_id_exists(self, atcha_dir: Path) -> None:
        """Cannot create a user with the same id."""
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)

        _ = run_cli("admin", "users", "add", "--name=testuser", "--role=Test", env=env, cwd=str(cwd))
        result = run_cli("admin", "users", "add", "--name=testuser", "--role=Test", env=env, cwd=str(cwd))
        assert result.returncode != 0
        # Could fail because name already taken or id already exists
        assert "already" in result.stderr

    def test_fails_if_name_taken(self, atcha_dir: Path) -> None:
        """Cannot create users with the same name."""
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)

        _ = run_cli("admin", "users", "add", "--name=alice", "--role=Backend", env=env, cwd=str(cwd))
        # Different role but same name 'alice'
        result = run_cli("admin", "users", "add", "--name=alice", "--role=Frontend", env=env, cwd=str(cwd))
        assert result.returncode != 0
        assert "already exists" in result.stderr

    def test_password_option(self, atcha_dir: Path) -> None:
        """admin create: ATCHA_ADMIN_PASS env var works."""
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)  # Uses ATCHA_ADMIN_PASS

        # No token, password from env
        result = run_cli(
            "admin", "users", "add", "--name=pwtest", "--role=Password User",
            env=env, cwd=str(cwd),
        )
        assert result.returncode == 0
        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert len(profile["id"]) == 5  # Random 5-char id
        assert profile["name"] == "pwtest"


# ---------- agents ----------


class TestAgents:
    def test_lists_agents(self, atcha_dir: Path) -> None:
        """agents list: returns JSON array of profiles (without dates by default)."""
        cwd = atcha_dir.parent
        env = {"ATCHA_DIR": str(atcha_dir)}

        # Create some users (using unique short names)
        admin_env = _admin_env(atcha_dir)
        _ = run_cli("admin", "users", "add", "--name=alice", "--role=Title A", env=admin_env, cwd=str(cwd))
        _ = run_cli("admin", "users", "add", "--name=bob", "--role=Title B", env=admin_env, cwd=str(cwd))

        result = run_cli("contacts", "--include-self", env=env, cwd=str(cwd))
        assert result.returncode == 0
        profiles = json.loads(result.stdout)
        assert len(profiles) == 2
        assert len(profiles[0]["id"]) == 5  # Random 5-char id
        assert profiles[0]["name"] == "alice"
        assert profiles[0]["role"] == "Title A"
        assert "joined" not in profiles[0]  # No dates by default
        assert profiles[1]["name"] == "bob"

    def test_names_only(self, atcha_dir: Path) -> None:
        """agents list --names-only outputs agent ids."""
        cwd = atcha_dir.parent
        env = {"ATCHA_DIR": str(atcha_dir)}
        admin_env = _admin_env(atcha_dir)
        _ = run_cli("admin", "users", "add", "--name=alice-dev", "--role=A", env=admin_env, cwd=str(cwd))
        _ = run_cli("admin", "users", "add", "--name=bob-dev", "--role=B", env=admin_env, cwd=str(cwd))

        result = run_cli("contacts", "--include-self", "--names-only", env=env, cwd=str(cwd))
        assert result.returncode == 0
        lines = result.stdout.strip().split("\n")
        assert lines == ["alice-dev", "bob-dev"]

    def test_exclude_self_by_default(self, atcha_dir: Path) -> None:
        """contacts excludes current user by default."""
        cwd = atcha_dir.parent
        alice_token = _create_user(atcha_dir, "alice-dev", "A")
        _ = _create_user(atcha_dir, "bob-dev", "B")

        env = {"ATCHA_TOKEN": alice_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("contacts", "--names-only", env=env, cwd=str(cwd))
        assert result.returncode == 0
        lines = result.stdout.strip().split("\n")
        assert "alice-dev" not in lines
        assert "bob-dev" in lines

    def test_include_self(self, atcha_dir: Path) -> None:
        """agents list --include-self includes current user."""
        cwd = atcha_dir.parent
        alice_token = _create_user(atcha_dir, "alice-dev", "A")
        _ = _create_user(atcha_dir, "bob-dev", "B")

        env = {"ATCHA_TOKEN": alice_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("contacts", "--include-self", "--names-only", "--include-self", env=env, cwd=str(cwd))
        assert result.returncode == 0
        lines = result.stdout.strip().split("\n")
        assert "alice-dev" in lines
        assert "bob-dev" in lines

    def test_admin_sees_all(self, atcha_dir: Path) -> None:
        """Admin sees all agents without exclusion."""
        cwd = atcha_dir.parent
        _ = _create_user(atcha_dir, "alice-dev", "A")
        _ = _create_user(atcha_dir, "bob-dev", "B")

        env = _admin_env(atcha_dir)
        result = run_cli("contacts", "--include-self", "--names-only", env=env, cwd=str(cwd))
        assert result.returncode == 0
        lines = result.stdout.strip().split("\n")
        assert "alice-dev" in lines
        assert "bob-dev" in lines

    def test_filter_by_tags(self, atcha_dir: Path) -> None:
        """agents list --tags filters agents by tag."""
        cwd = atcha_dir.parent
        env = {"ATCHA_DIR": str(atcha_dir)}
        admin_env = _admin_env(atcha_dir)
        _ = run_cli("admin", "users", "add", "--name=backend-dev", "--role=Backend", "--tags=backend,api", env=admin_env, cwd=str(cwd))
        _ = run_cli("admin", "users", "add", "--name=frontend-dev", "--role=Frontend", "--tags=frontend,ui", env=admin_env, cwd=str(cwd))

        result = run_cli("contacts", "--include-self", "--names-only", "--tags=backend", env=env, cwd=str(cwd))
        assert result.returncode == 0
        lines = result.stdout.strip().split("\n")
        assert "backend-dev" in lines
        assert "frontend-dev" not in lines

    def test_get_user(self, atcha_dir: Path) -> None:
        """agents get <id or name> returns profile JSON (without dates by default)."""
        cwd = atcha_dir.parent
        env = {"ATCHA_DIR": str(atcha_dir)}
        admin_env = _admin_env(atcha_dir)
        _ = run_cli("admin", "users", "add", "--name=test-user", "--role=Test Title", env=admin_env, cwd=str(cwd))

        # Can get by name
        result = run_cli("contacts", "test-user", env=env, cwd=str(cwd))
        assert result.returncode == 0
        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert len(profile["id"]) == 5  # Random 5-char id
        assert profile["name"] == "test-user"
        assert profile["role"] == "Test Title"
        assert "joined" not in profile  # No dates by default

    def test_full_flag(self, atcha_dir: Path) -> None:
        """--full includes joined/updated dates."""
        cwd = atcha_dir.parent
        env = {"ATCHA_DIR": str(atcha_dir)}
        admin_env = _admin_env(atcha_dir)
        _ = run_cli("admin", "users", "add", "--name=test-user", "--role=Test", env=admin_env, cwd=str(cwd))

        # agents get --full
        result = run_cli("contacts", "test-user", "--full", env=env, cwd=str(cwd))
        assert result.returncode == 0
        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert "joined" in profile
        assert "updated" in profile

        # agents list --full
        result = run_cli("contacts", "--include-self", "--full", env=env, cwd=str(cwd))
        profiles = json.loads(result.stdout)
        assert "joined" in profiles[0]

    def test_empty_when_no_agents(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent
        env = {"ATCHA_DIR": str(atcha_dir)}
        result = run_cli("contacts", "--include-self", env=env, cwd=str(cwd))
        assert result.returncode == 0
        profiles = json.loads(result.stdout)
        assert profiles == []


# ---------- profile ----------


class TestProfile:
    def test_view_own_profile(self, atcha_dir: Path) -> None:
        """View own profile via 'agents get $(whoami)'."""
        cwd = atcha_dir.parent
        user_token = _create_user(atcha_dir, "test-user", "Test User")
        env = {"ATCHA_TOKEN": user_token, "ATCHA_DIR": str(atcha_dir)}

        # Get username via whoami, then fetch profile
        whoami_result = run_cli("whoami", env=env, cwd=str(cwd))
        assert whoami_result.returncode == 0
        username = whoami_result.stdout.strip()

        result = run_cli("contacts", username, env=env, cwd=str(cwd))
        assert result.returncode == 0
        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert len(profile["id"]) == 5  # Random 5-char id
        assert profile["name"] == "test-user"
        assert profile["role"] == "Test User"

    def test_view_other_profile(self, atcha_dir: Path) -> None:
        """View another user's profile via 'agents get <id or name>' (public, no auth required)."""
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)
        _ = run_cli("admin", "users", "add", "--name=other-user", "--role=Other", env=env, cwd=str(cwd))

        # View without auth (public) - uses 'agents get <name>'
        env_no_token = {"ATCHA_DIR": str(atcha_dir)}
        result = run_cli("contacts", "other-user", env=env_no_token, cwd=str(cwd))
        assert result.returncode == 0
        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert len(profile["id"]) == 5  # Random 5-char id
        assert profile["name"] == "other-user"

    def test_whoami_returns_username(self, atcha_dir: Path) -> None:
        """whoami returns just the username (directory name)."""
        cwd = atcha_dir.parent
        user_token = _create_user(atcha_dir, "maya-backend", "Backend Engineer")
        env = {"ATCHA_TOKEN": user_token, "ATCHA_DIR": str(atcha_dir)}

        result = run_cli("whoami", env=env, cwd=str(cwd))
        assert result.returncode == 0
        assert result.stdout.strip() == "maya-backend"

    def test_whoami_requires_token(self, atcha_dir: Path) -> None:
        """whoami requires authentication."""
        cwd = atcha_dir.parent
        env = {"ATCHA_DIR": str(atcha_dir)}
        result = run_cli("whoami", env=env, cwd=str(cwd))
        assert result.returncode != 0
        assert "token" in result.stderr.lower()


# ---------- agents update ----------


class TestAgentsUpdate:
    def test_updates_own_profile(self, atcha_dir: Path) -> None:
        """Update own profile without specifying --name."""
        cwd = atcha_dir.parent
        user_token = _create_user(atcha_dir, "test-user")
        env = {"ATCHA_TOKEN": user_token, "ATCHA_DIR": str(atcha_dir)}

        result = run_cli(
            "profile", "update",
            "--status=Working on tests",
            "--tags=testing,qa",
            "--about=I write tests",
            env=env, cwd=str(cwd),
        )
        assert result.returncode == 0
        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert profile["status"] == "Working on tests"
        assert profile["tags"] == ["testing", "qa"]
        assert profile["about"] == "I write tests"

    def test_updates_role_requires_admin(self, atcha_dir: Path) -> None:
        """Role updates require admin auth."""
        cwd = atcha_dir.parent
        user_token = _create_user(atcha_dir, "test-user", "Junior Dev")
        env = {"ATCHA_TOKEN": user_token, "ATCHA_DIR": str(atcha_dir)}

        # Users cannot update their own role
        result = run_cli("profile", "update", "--role=Senior Dev", env=env, cwd=str(cwd))
        assert result.returncode != 0
        assert "Only admins can update roles" in result.stderr

        # Admin can update role
        admin_env = _admin_env(atcha_dir)
        result = run_cli("profile", "update", "--name=test-user", "--role=Senior Dev", env=admin_env, cwd=str(cwd))
        assert result.returncode == 0
        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert profile["role"] == "Senior Dev"

    def test_get_after_update(self, atcha_dir: Path) -> None:
        """Verify agents get reflects updates."""
        cwd = atcha_dir.parent
        user_token = _create_user(atcha_dir, "test-user")
        env = {"ATCHA_TOKEN": user_token, "ATCHA_DIR": str(atcha_dir)}

        # Update then get
        _ = run_cli("profile", "update", "--status=Updated", env=env, cwd=str(cwd))
        result = run_cli("contacts", "test-user", env=env, cwd=str(cwd))
        assert result.returncode == 0
        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert len(profile["id"]) == 5  # Random 5-char id
        assert profile["status"] == "Updated"

    def test_admin_updates_other_agent(self, atcha_dir: Path) -> None:
        """Admin can update another agent's profile with --name."""
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)
        _ = _create_user(atcha_dir, "target-agent", "Original Role")

        result = run_cli(
            "profile", "update",
            "--name=target-agent",
            "--role=New Role",
            "--status=Busy",
            env=env, cwd=str(cwd),
        )
        assert result.returncode == 0
        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert profile["role"] == "New Role"
        assert profile["status"] == "Busy"


# ---------- messages check ----------


class TestMessagesCheck:
    def test_shows_summary(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent

        # Create sender and recipient
        sender_token = _create_user(atcha_dir, "sender")
        recipient_token = _create_user(atcha_dir, "recipient")

        # Send a message
        sender_env = {"ATCHA_TOKEN": sender_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("send", "--to", "recipient", "Hello!", env=sender_env, cwd=str(cwd))
        assert result.returncode == 0

        # Check inbox
        recipient_env = {"ATCHA_TOKEN": recipient_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("messages", "check", env=recipient_env, cwd=str(cwd))
        assert result.returncode == 0
        assert "1 unread message from sender" in result.stdout

    def test_empty_inbox(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent
        user_token = _create_user(atcha_dir, "test-user")
        env = {"ATCHA_TOKEN": user_token, "ATCHA_DIR": str(atcha_dir)}

        result = run_cli("messages", "check", env=env, cwd=str(cwd))
        assert result.returncode == 0
        assert "No messages" in result.stdout

    def test_password_rejects_admin(self, atcha_dir: Path) -> None:
        """messages check: --password authenticates as admin but fails without --user."""
        cwd = atcha_dir.parent
        env = {"ATCHA_DIR": str(atcha_dir)}

        # Arguments must come before subcommand for argparse
        result = run_cli("messages", f"--password={PASSWORD}", "check", env=env, cwd=str(cwd))
        assert result.returncode != 0
        assert "--password authenticates as admin" in result.stderr

    def test_admin_impersonation(self, atcha_dir: Path) -> None:
        """messages check: admin can use --user to check another user's inbox."""
        cwd = atcha_dir.parent
        env = {"ATCHA_DIR": str(atcha_dir)}

        # Create users
        sender_token = _create_user(atcha_dir, "sender")
        _ = _create_user(atcha_dir, "recipient")

        # Send a message as sender
        sender_env = {"ATCHA_TOKEN": sender_token, "ATCHA_DIR": str(atcha_dir)}
        _ = run_cli("send", "--to", "recipient", "Hello from sender!", env=sender_env, cwd=str(cwd))

        # Admin checks recipient's inbox using --password and --user (before subcommand)
        result = run_cli(
            "messages", f"--password={PASSWORD}", "--user=recipient", "check",
            env=env, cwd=str(cwd),
        )
        assert result.returncode == 0
        assert "1 unread message from sender" in result.stdout


# ---------- messages read ----------


class TestMessagesRead:
    def test_reads_and_marks(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent

        # Create sender and recipient
        sender_token = _create_user(atcha_dir, "sender")
        recipient_token = _create_user(atcha_dir, "recipient")

        # Send a message
        sender_env = {"ATCHA_TOKEN": sender_token, "ATCHA_DIR": str(atcha_dir)}
        _ = run_cli("send", "--to", "recipient", "Hello!", env=sender_env, cwd=str(cwd))

        # Read inbox
        recipient_env = {"ATCHA_TOKEN": recipient_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("messages", "read", env=recipient_env, cwd=str(cwd))
        assert result.returncode == 0
        msg: dict[str, str] = json.loads(result.stdout.strip())
        assert msg["from"] == "sender"
        assert msg["content"] == "Hello!"

        # Should be marked as read now
        result = run_cli("messages", "check", env=recipient_env, cwd=str(cwd))
        assert "No messages" in result.stdout

    def test_silent_on_empty(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent
        user_token = _create_user(atcha_dir, "test-user")
        env = {"ATCHA_TOKEN": user_token, "ATCHA_DIR": str(atcha_dir)}

        result = run_cli("messages", "read", env=env, cwd=str(cwd))
        assert result.returncode == 0
        assert result.stdout == ""

    def test_excludes_to_field_by_default(self, atcha_dir: Path) -> None:
        """messages read excludes 'to' field for regular agents (it's redundant)."""
        cwd = atcha_dir.parent
        sender_token = _create_user(atcha_dir, "sender")
        recipient_token = _create_user(atcha_dir, "recipient")

        # Send a message
        sender_env = {"ATCHA_TOKEN": sender_token, "ATCHA_DIR": str(atcha_dir)}
        _ = run_cli("send", "--to", "recipient", "Hello!", env=sender_env, cwd=str(cwd))

        # Read inbox - 'to' should NOT be in output
        recipient_env = {"ATCHA_TOKEN": recipient_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("messages", "read", env=recipient_env, cwd=str(cwd))
        assert result.returncode == 0
        msg: dict[str, str] = json.loads(result.stdout.strip())
        assert "to" not in msg
        assert msg["from"] == "sender"

    def test_includes_to_field_for_admin(self, atcha_dir: Path) -> None:
        """messages read includes 'to' field when admin is impersonating."""
        cwd = atcha_dir.parent
        sender_token = _create_user(atcha_dir, "sender")
        _ = _create_user(atcha_dir, "recipient")

        # Send a message
        sender_env = {"ATCHA_TOKEN": sender_token, "ATCHA_DIR": str(atcha_dir)}
        _ = run_cli("send", "--to", "recipient", "Hello!", env=sender_env, cwd=str(cwd))

        # Read inbox as admin - 'to' should be included (args before subcommand)
        admin_env = _admin_env(atcha_dir)
        result = run_cli("messages", "--user=recipient", "read", env=admin_env, cwd=str(cwd))
        assert result.returncode == 0
        msg: dict[str, T.Any] = json.loads(result.stdout.strip())
        assert msg["to"] == ["recipient"]

    def test_include_read_filter(self, atcha_dir: Path) -> None:
        """--include-read shows already-read messages."""
        cwd = atcha_dir.parent
        sender_token = _create_user(atcha_dir, "sender")
        recipient_token = _create_user(atcha_dir, "recipient")

        # Send a message
        sender_env = {"ATCHA_TOKEN": sender_token, "ATCHA_DIR": str(atcha_dir)}
        _ = run_cli("send", "--to", "recipient", "Message 1", env=sender_env, cwd=str(cwd))

        # Read inbox (marks as read)
        recipient_env = {"ATCHA_TOKEN": recipient_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("messages", "read", env=recipient_env, cwd=str(cwd))
        assert result.returncode == 0
        assert "Message 1" in result.stdout

        # Normal read shows nothing (already read)
        result = run_cli("messages", "read", env=recipient_env, cwd=str(cwd))
        assert result.returncode == 0
        assert result.stdout == ""

        # With --include-read, message is shown again
        result = run_cli("messages", "read", "--include-read", env=recipient_env, cwd=str(cwd))
        assert result.returncode == 0
        assert "Message 1" in result.stdout

    def test_from_filter(self, atcha_dir: Path) -> None:
        """--from filters messages by sender."""
        cwd = atcha_dir.parent
        alice_token = _create_user(atcha_dir, "alice-sender")
        bob_token = _create_user(atcha_dir, "bob-sender")
        recipient_token = _create_user(atcha_dir, "recipient")

        # Send messages from two senders
        env1 = {"ATCHA_TOKEN": alice_token, "ATCHA_DIR": str(atcha_dir)}
        env2 = {"ATCHA_TOKEN": bob_token, "ATCHA_DIR": str(atcha_dir)}
        _ = run_cli("send", "--to", "recipient", "From alice", env=env1, cwd=str(cwd))
        _ = run_cli("send", "--to", "recipient", "From bob", env=env2, cwd=str(cwd))

        # Filter by alice-sender
        recipient_env = {"ATCHA_TOKEN": recipient_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("messages", "read", "--from=alice-sender", env=recipient_env, cwd=str(cwd))
        assert result.returncode == 0
        assert "From alice" in result.stdout
        assert "From bob" not in result.stdout

    def test_no_mark_flag(self, atcha_dir: Path) -> None:
        """--no-mark prevents marking messages as read."""
        cwd = atcha_dir.parent
        sender_token = _create_user(atcha_dir, "sender")
        recipient_token = _create_user(atcha_dir, "recipient")

        # Send a message
        sender_env = {"ATCHA_TOKEN": sender_token, "ATCHA_DIR": str(atcha_dir)}
        _ = run_cli("send", "--to", "recipient", "Hello!", env=sender_env, cwd=str(cwd))

        # Read with --no-mark
        recipient_env = {"ATCHA_TOKEN": recipient_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("messages", "read", "--no-mark", env=recipient_env, cwd=str(cwd))
        assert result.returncode == 0
        assert "Hello!" in result.stdout

        # Should still show as unread
        result = run_cli("messages", "check", env=recipient_env, cwd=str(cwd))
        assert "1 unread message" in result.stdout

    def test_read_by_ids(self, atcha_dir: Path) -> None:
        """Can read specific messages by ID - only prints specified messages."""
        cwd = atcha_dir.parent
        sender_token = _create_user(atcha_dir, "sender")
        recipient_token = _create_user(atcha_dir, "recipient")

        # Send two messages
        sender_env = {"ATCHA_TOKEN": sender_token, "ATCHA_DIR": str(atcha_dir)}
        _ = run_cli("send", "--to", "recipient", "First message", env=sender_env, cwd=str(cwd))
        _ = run_cli("send", "--to", "recipient", "Second message", env=sender_env, cwd=str(cwd))

        # Get message IDs from inbox
        inbox = atcha_dir / "users" / "recipient" / "mail" / "inbox.jsonl"
        lines = inbox.read_text().strip().split("\n")
        msg1: dict[str, T.Any] = json.loads(lines[0])

        # Read only first message by ID (output should only contain first message)
        recipient_env = {"ATCHA_TOKEN": recipient_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("messages", "read", msg1["id"], env=recipient_env, cwd=str(cwd))
        assert result.returncode == 0
        # Should have exactly 1 line of output
        output_lines = [l for l in result.stdout.strip().split("\n") if l]
        assert len(output_lines) == 1
        assert "First message" in result.stdout


# ---------- messages list ----------


class TestMessagesList:
    def test_returns_json_array(self, atcha_dir: Path) -> None:
        """messages list returns JSON array."""
        cwd = atcha_dir.parent
        sender_token = _create_user(atcha_dir, "sender")
        recipient_token = _create_user(atcha_dir, "recipient")

        # Send messages
        sender_env = {"ATCHA_TOKEN": sender_token, "ATCHA_DIR": str(atcha_dir)}
        _ = run_cli("send", "--to", "recipient", "First message", env=sender_env, cwd=str(cwd))
        _ = run_cli("send", "--to", "recipient", "Second message", env=sender_env, cwd=str(cwd))

        # List messages
        recipient_env = {"ATCHA_TOKEN": recipient_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("messages", "list", env=recipient_env, cwd=str(cwd))
        assert result.returncode == 0

        messages: list[dict[str, T.Any]] = json.loads(result.stdout)
        assert isinstance(messages, list)
        assert len(messages) == 2

    def test_preview_truncation(self, atcha_dir: Path) -> None:
        """messages list truncates content to preview."""
        cwd = atcha_dir.parent
        sender_token = _create_user(atcha_dir, "sender")
        recipient_token = _create_user(atcha_dir, "recipient")

        # Send a long message
        long_message = "A" * 100
        sender_env = {"ATCHA_TOKEN": sender_token, "ATCHA_DIR": str(atcha_dir)}
        _ = run_cli("send", "--to", "recipient", long_message, env=sender_env, cwd=str(cwd))

        # List messages
        recipient_env = {"ATCHA_TOKEN": recipient_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("messages", "list", env=recipient_env, cwd=str(cwd))
        assert result.returncode == 0

        messages: list[dict[str, T.Any]] = json.loads(result.stdout)
        assert len(messages) == 1
        assert "preview" in messages[0]
        assert messages[0]["preview"] == "A" * 50 + "..."
        assert "content" not in messages[0]

    def test_no_preview_flag(self, atcha_dir: Path) -> None:
        """--no-preview shows full content."""
        cwd = atcha_dir.parent
        sender_token = _create_user(atcha_dir, "sender")
        recipient_token = _create_user(atcha_dir, "recipient")

        # Send a message
        sender_env = {"ATCHA_TOKEN": sender_token, "ATCHA_DIR": str(atcha_dir)}
        _ = run_cli("send", "--to", "recipient", "Hello world", env=sender_env, cwd=str(cwd))

        # List with --no-preview
        recipient_env = {"ATCHA_TOKEN": recipient_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("messages", "list", "--no-preview", env=recipient_env, cwd=str(cwd))
        assert result.returncode == 0

        messages: list[dict[str, T.Any]] = json.loads(result.stdout)
        assert len(messages) == 1
        assert "content" in messages[0]
        assert messages[0]["content"] == "Hello world"
        assert "preview" not in messages[0]

    def test_no_side_effect(self, atcha_dir: Path) -> None:
        """messages list does NOT mark messages as read."""
        cwd = atcha_dir.parent
        sender_token = _create_user(atcha_dir, "sender")
        recipient_token = _create_user(atcha_dir, "recipient")

        # Send a message
        sender_env = {"ATCHA_TOKEN": sender_token, "ATCHA_DIR": str(atcha_dir)}
        _ = run_cli("send", "--to", "recipient", "Hello!", env=sender_env, cwd=str(cwd))

        # List messages (should NOT mark as read)
        recipient_env = {"ATCHA_TOKEN": recipient_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("messages", "list", env=recipient_env, cwd=str(cwd))
        assert result.returncode == 0
        messages: list[dict[str, T.Any]] = json.loads(result.stdout)
        assert len(messages) == 1

        # Check should still show unread
        result = run_cli("messages", "check", env=recipient_env, cwd=str(cwd))
        assert "1 unread message" in result.stdout

    def test_limit_filter(self, atcha_dir: Path) -> None:
        """--limit restricts number of messages."""
        cwd = atcha_dir.parent
        sender_token = _create_user(atcha_dir, "sender")
        recipient_token = _create_user(atcha_dir, "recipient")

        # Send multiple messages
        sender_env = {"ATCHA_TOKEN": sender_token, "ATCHA_DIR": str(atcha_dir)}
        for i in range(5):
            _ = run_cli("send", "--to", "recipient", f"Message {i}", env=sender_env, cwd=str(cwd))

        # List with limit
        recipient_env = {"ATCHA_TOKEN": recipient_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("messages", "list", "--limit=2", env=recipient_env, cwd=str(cwd))
        assert result.returncode == 0

        messages: list[dict[str, T.Any]] = json.loads(result.stdout)
        assert len(messages) == 2

    def test_from_filter(self, atcha_dir: Path) -> None:
        """--from filters by sender."""
        cwd = atcha_dir.parent
        alice_token = _create_user(atcha_dir, "alice")
        bob_token = _create_user(atcha_dir, "bob")
        recipient_token = _create_user(atcha_dir, "recipient")

        # Send messages from different senders
        alice_env = {"ATCHA_TOKEN": alice_token, "ATCHA_DIR": str(atcha_dir)}
        bob_env = {"ATCHA_TOKEN": bob_token, "ATCHA_DIR": str(atcha_dir)}
        _ = run_cli("send", "--to", "recipient", "From alice", env=alice_env, cwd=str(cwd))
        _ = run_cli("send", "--to", "recipient", "From bob", env=bob_env, cwd=str(cwd))

        # Filter by alice
        recipient_env = {"ATCHA_TOKEN": recipient_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("messages", "list", "--from=alice", env=recipient_env, cwd=str(cwd))
        assert result.returncode == 0

        messages: list[dict[str, T.Any]] = json.loads(result.stdout)
        assert len(messages) == 1
        assert messages[0]["from"] == "alice"

    def test_backward_compat_body(self, atcha_dir: Path) -> None:
        """Can read old messages with 'body' field."""
        cwd = atcha_dir.parent
        _ = _create_user(atcha_dir, "sender")
        recipient_token = _create_user(atcha_dir, "recipient")

        # Manually write old-format message with 'body' field
        inbox = atcha_dir / "users" / "recipient" / "mail" / "inbox.jsonl"
        old_msg = {"id": "msg-old123", "thread_id": "msg-old123", "from": "sender", "to": ["recipient"], "ts": "2026-01-01T00:00:00Z", "type": "message", "body": "Old format message"}
        inbox.write_text(json.dumps(old_msg) + "\n")

        # List should work and show preview from 'body' field
        recipient_env = {"ATCHA_TOKEN": recipient_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("messages", "list", env=recipient_env, cwd=str(cwd))
        assert result.returncode == 0

        messages: list[dict[str, T.Any]] = json.loads(result.stdout)
        assert len(messages) == 1
        assert messages[0]["preview"] == "Old format message"


# ---------- send ----------


class TestSend:
    def test_sends_message(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent

        # Create sender and recipient
        sender_token = _create_user(atcha_dir, "sender")
        _ = _create_user(atcha_dir, "recipient")

        sender_env = {"ATCHA_TOKEN": sender_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("send", "--to", "recipient", "Test message", env=sender_env, cwd=str(cwd))
        assert result.returncode == 0

        response: dict[str, T.Any] = json.loads(result.stdout)
        assert response["status"] == "delivered"
        assert response["to"] == ["recipient"]

        # Verify message in recipient inbox
        inbox = atcha_dir / "users" / "recipient" / "mail" / "inbox.jsonl"
        msg: dict[str, T.Any] = json.loads(inbox.read_text().strip())
        assert msg["from"] == "sender"
        assert msg["content"] == "Test message"

        # Verify message in sender sent
        sent = atcha_dir / "users" / "sender" / "mail" / "sent.jsonl"
        msg = json.loads(sent.read_text().strip())
        assert msg["to"] == ["recipient"]

    def test_unknown_recipient(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent
        sender_token = _create_user(atcha_dir, "sender")
        sender_env = {"ATCHA_TOKEN": sender_token, "ATCHA_DIR": str(atcha_dir)}

        result = run_cli("send", "--to", "nobody", "Test", env=sender_env, cwd=str(cwd))
        assert result.returncode != 0
        assert "not found" in result.stderr

    def test_special_characters(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent
        sender_token = _create_user(atcha_dir, "sender")
        _ = _create_user(atcha_dir, "recipient")

        sender_env = {"ATCHA_TOKEN": sender_token, "ATCHA_DIR": str(atcha_dir)}
        body = 'Changed "auth" exports & fixed <types>'
        result = run_cli("send", "--to", "recipient", body, env=sender_env, cwd=str(cwd))
        assert result.returncode == 0

        inbox = atcha_dir / "users" / "recipient" / "mail" / "inbox.jsonl"
        msg: dict[str, T.Any] = json.loads(inbox.read_text().strip())
        assert msg["content"] == body

    def test_admin_send_on_behalf(self, atcha_dir: Path) -> None:
        """send: admin can use --user to send on behalf of another user."""
        cwd = atcha_dir.parent
        env = {"ATCHA_DIR": str(atcha_dir)}

        # Create users
        _ = _create_user(atcha_dir, "alice")
        _ = _create_user(atcha_dir, "bob")

        # Admin sends from alice to bob
        result = run_cli(
            "send", "--user=alice", f"--password={PASSWORD}",
            "--to", "bob", "Hello from alice (sent by admin)",
            env=env, cwd=str(cwd),
        )
        assert result.returncode == 0

        # Verify message in bob's inbox shows alice as sender
        inbox = atcha_dir / "users" / "bob" / "mail" / "inbox.jsonl"
        msg: dict[str, T.Any] = json.loads(inbox.read_text().strip())
        assert msg["from"] == "alice"
        assert msg["content"] == "Hello from alice (sent by admin)"

        # Verify message in alice's sent log
        sent = atcha_dir / "users" / "alice" / "mail" / "sent.jsonl"
        msg = json.loads(sent.read_text().strip())
        assert msg["to"] == ["bob"]

    def test_multiple_recipients(self, atcha_dir: Path) -> None:
        """send: can send to multiple recipients with repeated --to."""
        cwd = atcha_dir.parent
        sender_token = _create_user(atcha_dir, "sender")
        _ = _create_user(atcha_dir, "alice")
        _ = _create_user(atcha_dir, "bob")

        sender_env = {"ATCHA_TOKEN": sender_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("send", "--to", "alice", "--to", "bob", "Team update", env=sender_env, cwd=str(cwd))
        assert result.returncode == 0

        response: dict[str, T.Any] = json.loads(result.stdout)
        assert response["status"] == "delivered"
        assert set(response["to"]) == {"alice", "bob"}
        assert response["count"] == 2

        # Verify both recipients got the message
        alice_inbox = atcha_dir / "users" / "alice" / "mail" / "inbox.jsonl"
        alice_msg: dict[str, T.Any] = json.loads(alice_inbox.read_text().strip())
        assert alice_msg["content"] == "Team update"
        assert set(alice_msg["to"]) == {"alice", "bob"}

        bob_inbox = atcha_dir / "users" / "bob" / "mail" / "inbox.jsonl"
        bob_msg: dict[str, T.Any] = json.loads(bob_inbox.read_text().strip())
        assert bob_msg["content"] == "Team update"
        assert set(bob_msg["to"]) == {"alice", "bob"}

    def test_broadcast_all(self, atcha_dir: Path) -> None:
        """send: --all broadcasts to all contacts (excluding self)."""
        cwd = atcha_dir.parent
        sender_token = _create_user(atcha_dir, "sender")
        _ = _create_user(atcha_dir, "alice")
        _ = _create_user(atcha_dir, "bob")

        sender_env = {"ATCHA_TOKEN": sender_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("send", "--all", "Broadcast message", env=sender_env, cwd=str(cwd))
        assert result.returncode == 0

        response: dict[str, T.Any] = json.loads(result.stdout)
        assert response["status"] == "delivered"
        assert set(response["to"]) == {"alice", "bob"}  # Excludes sender
        assert response["count"] == 2

    def test_reply_to_message(self, atcha_dir: Path) -> None:
        """send: --reply-to creates threaded reply."""
        cwd = atcha_dir.parent
        alice_token = _create_user(atcha_dir, "alice")
        bob_token = _create_user(atcha_dir, "bob")

        # Alice sends original message to Bob
        alice_env = {"ATCHA_TOKEN": alice_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("send", "--to", "bob", "Original message", env=alice_env, cwd=str(cwd))
        assert result.returncode == 0

        # Get the message ID from Bob's inbox
        bob_inbox = atcha_dir / "users" / "bob" / "mail" / "inbox.jsonl"
        original_msg: dict[str, T.Any] = json.loads(bob_inbox.read_text().strip())
        msg_id = original_msg["id"]
        thread_id = original_msg["thread_id"]

        # Bob replies
        bob_env = {"ATCHA_TOKEN": bob_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("send", "--reply-to", msg_id, "Thanks for the update", env=bob_env, cwd=str(cwd))
        assert result.returncode == 0

        # Verify reply has correct threading
        alice_inbox = atcha_dir / "users" / "alice" / "mail" / "inbox.jsonl"
        reply_msg: dict[str, T.Any] = json.loads(alice_inbox.read_text().strip())
        assert reply_msg["thread_id"] == thread_id
        assert reply_msg["reply_to"] == msg_id
        assert reply_msg["content"] == "Thanks for the update"

    def test_reply_to_specific_person_in_thread(self, atcha_dir: Path) -> None:
        """send: --to with --reply-to replies to specific person in thread."""
        cwd = atcha_dir.parent
        alice_token = _create_user(atcha_dir, "alice")
        bob_token = _create_user(atcha_dir, "bob")
        charlie_token = _create_user(atcha_dir, "charlie")

        # Alice sends to Bob and Charlie
        alice_env = {"ATCHA_TOKEN": alice_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("send", "--to", "bob", "--to", "charlie", "Team question", env=alice_env, cwd=str(cwd))
        assert result.returncode == 0

        # Get message ID
        bob_inbox = atcha_dir / "users" / "bob" / "mail" / "inbox.jsonl"
        original_msg: dict[str, T.Any] = json.loads(bob_inbox.read_text().strip())
        msg_id = original_msg["id"]

        # Charlie replies only to Alice (not Bob)
        charlie_env = {"ATCHA_TOKEN": charlie_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("send", "--to", "alice", "--reply-to", msg_id, "My answer", env=charlie_env, cwd=str(cwd))
        assert result.returncode == 0

        # Verify only Alice got the reply
        alice_inbox = atcha_dir / "users" / "alice" / "mail" / "inbox.jsonl"
        reply_msg: dict[str, T.Any] = json.loads(alice_inbox.read_text().strip())
        assert reply_msg["to"] == ["alice"]
        assert reply_msg["reply_to"] == msg_id

        # Bob should not have the reply
        bob_lines = (atcha_dir / "users" / "bob" / "mail" / "inbox.jsonl").read_text().strip().split("\n")
        assert len(bob_lines) == 1  # Only the original message

    def test_error_all_with_reply_to(self, atcha_dir: Path) -> None:
        """send: --all with --reply-to is an error."""
        cwd = atcha_dir.parent
        sender_token = _create_user(atcha_dir, "sender")
        _ = _create_user(atcha_dir, "recipient")

        # Send a message first
        sender_env = {"ATCHA_TOKEN": sender_token, "ATCHA_DIR": str(atcha_dir)}
        _ = run_cli("send", "--to", "recipient", "Test", env=sender_env, cwd=str(cwd))

        # Get message ID
        recipient_inbox = atcha_dir / "users" / "recipient" / "mail" / "inbox.jsonl"
        msg: dict[str, T.Any] = json.loads(recipient_inbox.read_text().strip())
        msg_id = msg["id"]

        # Try --all with --reply-to (should error)
        result = run_cli("send", "--all", "--reply-to", msg_id, "Test", env=sender_env, cwd=str(cwd))
        assert result.returncode != 0
        assert "ambiguous" in result.stderr.lower()

    def test_error_no_recipients(self, atcha_dir: Path) -> None:
        """send: no recipients is an error."""
        cwd = atcha_dir.parent
        sender_token = _create_user(atcha_dir, "sender")

        sender_env = {"ATCHA_TOKEN": sender_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("send", "Test message", env=sender_env, cwd=str(cwd))
        assert result.returncode != 0
        assert "no recipients" in result.stderr.lower() or "required" in result.stderr.lower()

    def test_error_recipient_not_in_thread(self, atcha_dir: Path) -> None:
        """send: --to with --reply-to validates recipient is in thread."""
        cwd = atcha_dir.parent
        alice_token = _create_user(atcha_dir, "alice")
        bob_token = _create_user(atcha_dir, "bob")
        _ = _create_user(atcha_dir, "charlie")

        # Alice sends to Bob (not Charlie)
        alice_env = {"ATCHA_TOKEN": alice_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("send", "--to", "bob", "Private message", env=alice_env, cwd=str(cwd))
        assert result.returncode == 0

        # Get message ID
        bob_inbox = atcha_dir / "users" / "bob" / "mail" / "inbox.jsonl"
        msg: dict[str, T.Any] = json.loads(bob_inbox.read_text().strip())
        msg_id = msg["id"]

        # Bob tries to reply to Charlie (who's not in the thread) - should error
        bob_env = {"ATCHA_TOKEN": bob_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("send", "--to", "charlie", "--reply-to", msg_id, "Test", env=bob_env, cwd=str(cwd))
        assert result.returncode != 0
        assert "not in thread" in result.stderr.lower()


# ---------- env ----------


class TestEnv:
    def test_outputs_exports(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent
        result = run_cli("env", cwd=str(cwd))
        assert result.returncode == 0
        assert "ATCHA_DIR" in result.stdout
        assert str(atcha_dir) in result.stdout

    def test_silent_when_no_dir(self, tmp_path: Path) -> None:
        result = run_cli("env", cwd=str(tmp_path))
        assert result.returncode == 0
        assert result.stdout == ""


# ---------- username validation ----------


class TestUsernameValidation:
    def test_valid_names(self) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location("atcha", CLI)
        assert spec is not None
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)

        valid_names = [
            "maya-backend-engineer",
            "alex-api-dev",
            "frontend-designer-2",
            "kai",
            "a-b-c",
        ]
        for name in valid_names:
            is_valid, _ = module._validate_username(name)
            assert is_valid, f"{name} should be valid"

    def test_invalid_names(self) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location("atcha", CLI)
        assert spec is not None
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)

        invalid_names = [
            ("Maya-Backend", "uppercase"),
            ("backend--engineer", "consecutive dashes"),
            ("-backend-engineer", "leading dash"),
            ("backend-engineer-", "trailing dash"),
            ("be", "too short"),
            ("123-456", "no letters"),
            ("a" * 50, "too long"),
        ]
        for name, reason in invalid_names:
            is_valid, _ = module._validate_username(name)
            assert not is_valid, f"{name} should be invalid ({reason})"


# ---------- token validation ----------


class TestTokenValidation:
    def test_token_identifies_user(self, atcha_dir: Path) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location("atcha", CLI)
        assert spec is not None
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)

        # Create user and get token
        user_token = _create_user(atcha_dir, "test-user")

        # Validate token
        result = module._validate_token(atcha_dir, user_token)
        assert result is not None
        name, is_admin = result
        assert name == "test-user"
        assert not is_admin  # User tokens are never admin

    def test_invalid_token(self, atcha_dir: Path) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location("atcha", CLI)
        assert spec is not None
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)

        result = module._validate_token(atcha_dir, "xxxxx")
        assert result is None

    def test_token_cli_option(self, atcha_dir: Path) -> None:
        """Test that --token works as alternative to ATCHA_TOKEN env var."""
        cwd = atcha_dir.parent
        user_token = _create_user(atcha_dir, "cli-test-user")

        # Use --token instead of env var (--token is on the subcommand)
        env = {"ATCHA_DIR": str(atcha_dir)}  # No ATCHA_TOKEN
        result = run_cli("whoami", f"--token={user_token}", env=env, cwd=str(cwd))
        assert result.returncode == 0
        assert result.stdout.strip() == "cli-test-user"


# ---------- Integration test ----------


class TestIntegration:
    def test_full_workflow(self, tmp_path: Path) -> None:
        """Full workflow: init → create agents → create-token → send mail → read mail."""
        # 1. Initialize
        result = run_cli("init", f"--password={PASSWORD}", cwd=str(tmp_path))
        assert result.returncode == 0

        atcha_dir = tmp_path / ".atcha"

        # 2. Use admin password env var (no admin tokens)
        admin_env = _admin_env(atcha_dir)

        # 3. Create users
        result = run_cli(
            "admin", "users", "add", "--name=maya-backend", "--role=Backend Engineer",
            "--tags=backend,auth",
            env=admin_env, cwd=str(tmp_path),
        )
        assert result.returncode == 0

        result = run_cli(
            "admin", "users", "add", "--name=alex-frontend", "--role=Frontend Dev",
            "--tags=frontend,ui",
            env=admin_env, cwd=str(tmp_path),
        )
        assert result.returncode == 0

        # 4. Get user tokens
        result = run_cli("create-token", "--user", "maya-backend", f"--password={PASSWORD}", cwd=str(tmp_path))
        maya_token = result.stdout.strip()

        result = run_cli("create-token", "--user", "alex-frontend", f"--password={PASSWORD}", cwd=str(tmp_path))
        alex_token = result.stdout.strip()

        # 5. Maya sends message to Alex
        maya_env = {"ATCHA_TOKEN": maya_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("send", "--to", "alex-frontend", "API is ready for integration", env=maya_env, cwd=str(tmp_path))
        assert result.returncode == 0

        # 6. Alex checks inbox
        alex_env = {"ATCHA_TOKEN": alex_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("messages", "check", env=alex_env, cwd=str(tmp_path))
        assert "1 unread message from maya-backend" in result.stdout

        # 7. Alex reads messages
        result = run_cli("messages", "read", env=alex_env, cwd=str(tmp_path))
        assert result.returncode == 0
        msg: dict[str, T.Any] = json.loads(result.stdout.strip())
        assert msg["from"] == "maya-backend"
        assert msg["content"] == "API is ready for integration"

        # 8. Inbox should be empty now
        result = run_cli("messages", "check", env=alex_env, cwd=str(tmp_path))
        assert "No messages" in result.stdout

        # 9. Alex replies
        result = run_cli("send", "--to", "maya-backend", "Thanks! Starting integration now.", env=alex_env, cwd=str(tmp_path))
        assert result.returncode == 0

        # 10. Maya reads reply
        result = run_cli("messages", "read", env=maya_env, cwd=str(tmp_path))
        msg = json.loads(result.stdout.strip())
        assert msg["from"] == "alex-frontend"
        assert "integration" in msg["content"]
