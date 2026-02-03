"""Tests for team_mail.py CLI with token-based authentication."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import typing as T
from pathlib import Path

import pytest

CLI: T.Final[str] = str(Path(__file__).resolve().parent.parent / "src" / "team_mail" / "cli" / "team_mail.py")
PASSWORD: T.Final[str] = "testpass123"


def run_cli(
    *args: str,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run the team-mail CLI with the given arguments."""
    full_env = {**os.environ, **(env if env is not None else {})}
    return subprocess.run(
        [sys.executable, CLI, *args],
        capture_output=True,
        text=True,
        env=full_env,
        cwd=cwd,
    )


@pytest.fixture
def team_mail_dir(tmp_path: Path) -> Path:
    """Create and initialize a .team-mail directory."""
    # Initialize the directory
    result = run_cli("init", f"--password={PASSWORD}", cwd=str(tmp_path))
    assert result.returncode == 0, result.stderr
    return tmp_path / ".team-mail"


def _admin_env(team_mail_dir: Path) -> dict[str, str]:
    """Return env dict for admin operations."""
    return {"TEAM_MAIL_ADMIN_PASS": PASSWORD, "TEAM_MAIL_DIR": str(team_mail_dir)}


def _create_agent(
    team_mail_dir: Path,
    name: str,
    role: str = "Test Agent",
) -> str:
    """Create an agent and return their token."""
    cwd = team_mail_dir.parent
    env = _admin_env(team_mail_dir)

    # Create agent
    result = run_cli("agents", "add", f"--name={name}", f"--role={role}", env=env, cwd=str(cwd))
    assert result.returncode == 0, result.stderr

    # Get agent token
    result = run_cli("create-token", "--agent", name, env=env, cwd=str(cwd))
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


# ---------- init ----------


class TestInit:
    def test_creates_structure(self, tmp_path: Path) -> None:
        result = run_cli("init", f"--password={PASSWORD}", cwd=str(tmp_path))
        assert result.returncode == 0
        assert "Initialized" in result.stdout

        team_mail_dir = tmp_path / ".team-mail"
        assert team_mail_dir.is_dir()
        assert (team_mail_dir / "admin.json").exists()
        assert (team_mail_dir / "tokens").is_dir()
        assert (team_mail_dir / "agents").is_dir()

    def test_fails_if_already_initialized(self, team_mail_dir: Path) -> None:
        cwd = team_mail_dir.parent
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

    def test_check_returns_0_when_initialized(self, team_mail_dir: Path) -> None:
        cwd = team_mail_dir.parent
        result = run_cli("init", "--check", cwd=str(cwd))
        assert result.returncode == 0
        assert "Team-mail initialized" in result.stdout

    def test_check_returns_1_when_not_initialized(self, tmp_path: Path) -> None:
        result = run_cli("init", "--check", cwd=str(tmp_path))
        assert result.returncode == 1
        assert result.stdout == ""


# ---------- admin password ----------


class TestAdminPassword:
    def test_changes_password(self, team_mail_dir: Path) -> None:
        cwd = team_mail_dir.parent
        result = run_cli(
            "admin", "password",
            f"--old={PASSWORD}",
            "--new=newpass123",
            cwd=str(cwd),
        )
        assert result.returncode == 0
        assert "Password updated" in result.stdout

        env = {"TEAM_MAIL_DIR": str(team_mail_dir)}

        # Old password should fail
        result = run_cli(
            "agents", "add", "--name=test-user", "--role=Test",
            f"--password={PASSWORD}",
            env=env, cwd=str(cwd),
        )
        assert result.returncode != 0

        # New password should work
        result = run_cli(
            "agents", "add", "--name=test-user", "--role=Test",
            "--password=newpass123",
            env=env, cwd=str(cwd),
        )
        assert result.returncode == 0

    def test_rejects_wrong_password(self, team_mail_dir: Path) -> None:
        cwd = team_mail_dir.parent
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
    def test_creates_agent_token(self, team_mail_dir: Path) -> None:
        cwd = team_mail_dir.parent
        env = _admin_env(team_mail_dir)

        # Create user first
        result = run_cli("agents", "add", "--name=test-user", "--role=Test", env=env, cwd=str(cwd))
        assert result.returncode == 0

        # Create token using --password
        result = run_cli("create-token", "--agent", "test-user", f"--password={PASSWORD}", cwd=str(cwd))
        assert result.returncode == 0
        token = result.stdout.strip()
        assert len(token) == 5

    def test_creates_agent_token_via_env(self, team_mail_dir: Path) -> None:
        """TEAM_MAIL_ADMIN_PASS env var works for create-token."""
        cwd = team_mail_dir.parent
        env = _admin_env(team_mail_dir)

        # Create user first
        result = run_cli("agents", "add", "--name=test-user", "--role=Test", env=env, cwd=str(cwd))
        assert result.returncode == 0

        # Create token using env var (no --password)
        result = run_cli("create-token", "--agent", "test-user", env=env, cwd=str(cwd))
        assert result.returncode == 0
        token = result.stdout.strip()
        assert len(token) == 5

    def test_rejects_nonexistent_user(self, team_mail_dir: Path) -> None:
        cwd = team_mail_dir.parent
        result = run_cli("create-token", "--agent", "nobody", f"--password={PASSWORD}", cwd=str(cwd))
        assert result.returncode != 0
        assert "not found" in result.stderr

    def test_token_is_deterministic(self, team_mail_dir: Path) -> None:
        """Same password + agent always produces the same token."""
        cwd = team_mail_dir.parent
        env = _admin_env(team_mail_dir)

        # Create agent
        result = run_cli("agents", "add", "--name=test-user", "--role=Test", env=env, cwd=str(cwd))
        assert result.returncode == 0

        # Create token twice - should get same result
        result1 = run_cli("create-token", "--agent", "test-user", f"--password={PASSWORD}", cwd=str(cwd))
        assert result1.returncode == 0
        token1 = result1.stdout.strip()

        result2 = run_cli("create-token", "--agent", "test-user", f"--password={PASSWORD}", cwd=str(cwd))
        assert result2.returncode == 0
        token2 = result2.stdout.strip()

        assert token1 == token2

    def test_token_stored_as_hash(self, team_mail_dir: Path) -> None:
        """Token file contains hash, not plaintext token."""
        cwd = team_mail_dir.parent
        env = _admin_env(team_mail_dir)

        # Create agent and token
        result = run_cli("agents", "add", "--name=test-user", "--role=Test", env=env, cwd=str(cwd))
        assert result.returncode == 0

        result = run_cli("create-token", "--agent", "test-user", f"--password={PASSWORD}", cwd=str(cwd))
        assert result.returncode == 0
        token = result.stdout.strip()

        # Read token file - should be a hash, not the token itself
        token_file = team_mail_dir / "tokens" / "test-user"
        stored = token_file.read_text().strip()

        # The stored value should NOT be the token (it should be a hash)
        assert stored != token
        # SHA-256 hash is 64 hex characters
        assert len(stored) == 64


# ---------- agents add ----------


class TestAgentsAdd:
    def test_creates_agent(self, team_mail_dir: Path) -> None:
        cwd = team_mail_dir.parent
        env = _admin_env(team_mail_dir)

        result = run_cli(
            "agents", "add", "--name=maya-backend", "--role=Backend Engineer",
            "--status=Working on auth",
            "--tags=backend,auth",
            env=env, cwd=str(cwd),
        )
        assert result.returncode == 0

        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert profile["id"] == "maya-backend"
        assert profile["name"] == "maya"
        assert profile["role"] == "Backend Engineer"
        assert profile["status"] == "Working on auth"
        assert profile["tags"] == ["backend", "auth"]

        # Check directory structure
        user_dir = team_mail_dir / "agents" / "maya-backend"
        assert user_dir.is_dir()
        assert (user_dir / "profile.json").exists()
        assert (user_dir / "mail" / "inbox.jsonl").exists()

    def test_requires_admin_token(self, team_mail_dir: Path) -> None:
        cwd = team_mail_dir.parent
        # No token
        result = run_cli("agents", "add", "--name=test-user", "--role=Test", cwd=str(cwd))
        assert result.returncode != 0
        assert "TEAM_MAIL_TOKEN" in result.stderr

    def test_rejects_user_token(self, team_mail_dir: Path) -> None:
        cwd = team_mail_dir.parent
        admin_env = _admin_env(team_mail_dir)

        # Create user and get their token
        _ = run_cli("agents", "add", "--name=test-user", "--role=Test", env=admin_env, cwd=str(cwd))
        result = run_cli("create-token", "--agent", "test-user", env=admin_env, cwd=str(cwd))
        user_token = result.stdout.strip()

        # Try to create with user token (no admin password in env)
        user_env = {"TEAM_MAIL_TOKEN": user_token, "TEAM_MAIL_DIR": str(team_mail_dir)}
        result = run_cli("agents", "add", "--name=another-user", "--role=Test", env=user_env, cwd=str(cwd))
        assert result.returncode != 0
        assert "Admin" in result.stderr  # "Admin token required" or similar

    def test_validates_username(self, team_mail_dir: Path) -> None:
        cwd = team_mail_dir.parent
        env = _admin_env(team_mail_dir)

        # Too short
        result = run_cli("agents", "add", "--name=ab", "--role=Test", env=env, cwd=str(cwd))
        assert result.returncode != 0
        assert "at least 3" in result.stderr

        # Invalid chars
        result = run_cli("agents", "add", "--name=User-Name", "--role=Test", env=env, cwd=str(cwd))
        assert result.returncode != 0
        assert "lowercase" in result.stderr

    def test_fails_if_id_exists(self, team_mail_dir: Path) -> None:
        """Cannot create an agent with the same id."""
        cwd = team_mail_dir.parent
        env = _admin_env(team_mail_dir)

        _ = run_cli("agents", "add", "--name=test-user", "--role=Test", env=env, cwd=str(cwd))
        result = run_cli("agents", "add", "--name=test-user", "--role=Test", env=env, cwd=str(cwd))
        assert result.returncode != 0
        # Could fail because name already taken or id already exists
        assert "already" in result.stderr

    def test_fails_if_name_taken(self, team_mail_dir: Path) -> None:
        """Cannot create agents with the same name."""
        cwd = team_mail_dir.parent
        env = _admin_env(team_mail_dir)

        _ = run_cli("agents", "add", "--name=alice-backend", "--role=Backend", env=env, cwd=str(cwd))
        # Different id but same name 'alice'
        result = run_cli("agents", "add", "--name=alice-frontend", "--role=Frontend", env=env, cwd=str(cwd))
        assert result.returncode != 0
        assert "already used" in result.stderr

    def test_password_option(self, team_mail_dir: Path) -> None:
        """admin create: --password works as alternative to token."""
        cwd = team_mail_dir.parent
        env = {"TEAM_MAIL_DIR": str(team_mail_dir)}

        # No token, just password
        result = run_cli(
            "agents", "add", "--name=pw-user", "--role=Password User",
            f"--password={PASSWORD}",
            env=env, cwd=str(cwd),
        )
        assert result.returncode == 0
        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert profile["id"] == "pw-user"
        assert profile["name"] == "pw"


# ---------- agents ----------


class TestAgents:
    def test_lists_agents(self, team_mail_dir: Path) -> None:
        """agents list: returns JSON array of profiles (without dates by default)."""
        cwd = team_mail_dir.parent
        env = {"TEAM_MAIL_DIR": str(team_mail_dir)}

        # Create some agents (using different first components for uniqueness)
        admin_env = _admin_env(team_mail_dir)
        _ = run_cli("agents", "add", "--name=alice-dev", "--role=Title A", env=admin_env, cwd=str(cwd))
        _ = run_cli("agents", "add", "--name=bob-dev", "--role=Title B", env=admin_env, cwd=str(cwd))

        result = run_cli("agents", "list", env=env, cwd=str(cwd))
        assert result.returncode == 0
        profiles = json.loads(result.stdout)
        assert len(profiles) == 2
        assert profiles[0]["id"] == "alice-dev"
        assert profiles[0]["name"] == "alice"
        assert profiles[0]["role"] == "Title A"
        assert "joined" not in profiles[0]  # No dates by default
        assert profiles[1]["id"] == "bob-dev"

    def test_names_only(self, team_mail_dir: Path) -> None:
        """agents list --names-only outputs agent ids."""
        cwd = team_mail_dir.parent
        env = {"TEAM_MAIL_DIR": str(team_mail_dir)}
        admin_env = _admin_env(team_mail_dir)
        _ = run_cli("agents", "add", "--name=alice-dev", "--role=A", env=admin_env, cwd=str(cwd))
        _ = run_cli("agents", "add", "--name=bob-dev", "--role=B", env=admin_env, cwd=str(cwd))

        result = run_cli("agents", "list", "--names-only", env=env, cwd=str(cwd))
        assert result.returncode == 0
        lines = result.stdout.strip().split("\n")
        assert lines == ["alice-dev", "bob-dev"]

    def test_exclude_self_by_default(self, team_mail_dir: Path) -> None:
        """agents list excludes current user by default."""
        cwd = team_mail_dir.parent
        alice_token = _create_agent(team_mail_dir, "alice-dev", "A")
        _ = _create_agent(team_mail_dir, "bob-dev", "B")

        env = {"TEAM_MAIL_TOKEN": alice_token, "TEAM_MAIL_DIR": str(team_mail_dir)}
        result = run_cli("agents", "list", "--names-only", env=env, cwd=str(cwd))
        assert result.returncode == 0
        lines = result.stdout.strip().split("\n")
        assert "alice-dev" not in lines
        assert "bob-dev" in lines

    def test_include_self(self, team_mail_dir: Path) -> None:
        """agents list --include-self includes current user."""
        cwd = team_mail_dir.parent
        alice_token = _create_agent(team_mail_dir, "alice-dev", "A")
        _ = _create_agent(team_mail_dir, "bob-dev", "B")

        env = {"TEAM_MAIL_TOKEN": alice_token, "TEAM_MAIL_DIR": str(team_mail_dir)}
        result = run_cli("agents", "list", "--names-only", "--include-self", env=env, cwd=str(cwd))
        assert result.returncode == 0
        lines = result.stdout.strip().split("\n")
        assert "alice-dev" in lines
        assert "bob-dev" in lines

    def test_admin_sees_all(self, team_mail_dir: Path) -> None:
        """Admin sees all agents without exclusion."""
        cwd = team_mail_dir.parent
        _ = _create_agent(team_mail_dir, "alice-dev", "A")
        _ = _create_agent(team_mail_dir, "bob-dev", "B")

        env = _admin_env(team_mail_dir)
        result = run_cli("agents", "list", "--names-only", env=env, cwd=str(cwd))
        assert result.returncode == 0
        lines = result.stdout.strip().split("\n")
        assert "alice-dev" in lines
        assert "bob-dev" in lines

    def test_filter_by_tags(self, team_mail_dir: Path) -> None:
        """agents list --tags filters agents by tag."""
        cwd = team_mail_dir.parent
        env = {"TEAM_MAIL_DIR": str(team_mail_dir)}
        admin_env = _admin_env(team_mail_dir)
        _ = run_cli("agents", "add", "--name=backend-dev", "--role=Backend", "--tags=backend,api", env=admin_env, cwd=str(cwd))
        _ = run_cli("agents", "add", "--name=frontend-dev", "--role=Frontend", "--tags=frontend,ui", env=admin_env, cwd=str(cwd))

        result = run_cli("agents", "list", "--names-only", "--tags=backend", env=env, cwd=str(cwd))
        assert result.returncode == 0
        lines = result.stdout.strip().split("\n")
        assert "backend-dev" in lines
        assert "frontend-dev" not in lines

    def test_get_user(self, team_mail_dir: Path) -> None:
        """agents get <id or name> returns profile JSON (without dates by default)."""
        cwd = team_mail_dir.parent
        env = {"TEAM_MAIL_DIR": str(team_mail_dir)}
        admin_env = _admin_env(team_mail_dir)
        _ = run_cli("agents", "add", "--name=test-user", "--role=Test Title", env=admin_env, cwd=str(cwd))

        # Can get by full id
        result = run_cli("agents", "get", "test-user", env=env, cwd=str(cwd))
        assert result.returncode == 0
        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert profile["id"] == "test-user"
        assert profile["name"] == "test"
        assert profile["role"] == "Test Title"
        assert "joined" not in profile  # No dates by default

        # Can also get by short name
        result2 = run_cli("agents", "get", "test", env=env, cwd=str(cwd))
        assert result2.returncode == 0
        profile2: dict[str, T.Any] = json.loads(result2.stdout)
        assert profile2["id"] == "test-user"

    def test_full_flag(self, team_mail_dir: Path) -> None:
        """--full includes joined/updated dates."""
        cwd = team_mail_dir.parent
        env = {"TEAM_MAIL_DIR": str(team_mail_dir)}
        admin_env = _admin_env(team_mail_dir)
        _ = run_cli("agents", "add", "--name=test-user", "--role=Test", env=admin_env, cwd=str(cwd))

        # agents get --full
        result = run_cli("agents", "get", "test-user", "--full", env=env, cwd=str(cwd))
        assert result.returncode == 0
        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert "joined" in profile
        assert "updated" in profile

        # agents list --full
        result = run_cli("agents", "list", "--full", env=env, cwd=str(cwd))
        profiles = json.loads(result.stdout)
        assert "joined" in profiles[0]

    def test_empty_when_no_agents(self, team_mail_dir: Path) -> None:
        cwd = team_mail_dir.parent
        env = {"TEAM_MAIL_DIR": str(team_mail_dir)}
        result = run_cli("agents", "list", env=env, cwd=str(cwd))
        assert result.returncode == 0
        profiles = json.loads(result.stdout)
        assert profiles == []


# ---------- profile ----------


class TestProfile:
    def test_view_own_profile(self, team_mail_dir: Path) -> None:
        """View own profile via 'agents get $(whoami)'."""
        cwd = team_mail_dir.parent
        user_token = _create_agent(team_mail_dir, "test-user", "Test User")
        env = {"TEAM_MAIL_TOKEN": user_token, "TEAM_MAIL_DIR": str(team_mail_dir)}

        # Get username via whoami, then fetch profile
        whoami_result = run_cli("whoami", env=env, cwd=str(cwd))
        assert whoami_result.returncode == 0
        username = whoami_result.stdout.strip()

        result = run_cli("agents", "get", username, env=env, cwd=str(cwd))
        assert result.returncode == 0
        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert profile["id"] == "test-user"
        assert profile["name"] == "test"
        assert profile["role"] == "Test User"

    def test_view_other_profile(self, team_mail_dir: Path) -> None:
        """View another user's profile via 'agents get <id or name>' (public, no auth required)."""
        cwd = team_mail_dir.parent
        env = _admin_env(team_mail_dir)
        _ = run_cli("agents", "add", "--name=other-user", "--role=Other", env=env, cwd=str(cwd))

        # View without auth (public) - uses 'agents get <id>'
        env_no_token = {"TEAM_MAIL_DIR": str(team_mail_dir)}
        result = run_cli("agents", "get", "other-user", env=env_no_token, cwd=str(cwd))
        assert result.returncode == 0
        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert profile["id"] == "other-user"
        assert profile["name"] == "other"

    def test_whoami_returns_username(self, team_mail_dir: Path) -> None:
        """whoami returns just the username."""
        cwd = team_mail_dir.parent
        user_token = _create_agent(team_mail_dir, "maya-backend", "Backend Engineer")
        env = {"TEAM_MAIL_TOKEN": user_token, "TEAM_MAIL_DIR": str(team_mail_dir)}

        result = run_cli("whoami", env=env, cwd=str(cwd))
        assert result.returncode == 0
        assert result.stdout.strip() == "maya-backend"

    def test_whoami_requires_token(self, team_mail_dir: Path) -> None:
        """whoami requires authentication."""
        cwd = team_mail_dir.parent
        env = {"TEAM_MAIL_DIR": str(team_mail_dir)}
        result = run_cli("whoami", env=env, cwd=str(cwd))
        assert result.returncode != 0
        assert "token" in result.stderr.lower()


# ---------- agents update ----------


class TestAgentsUpdate:
    def test_updates_own_profile(self, team_mail_dir: Path) -> None:
        """Update own profile without specifying --name."""
        cwd = team_mail_dir.parent
        user_token = _create_agent(team_mail_dir, "test-user")
        env = {"TEAM_MAIL_TOKEN": user_token, "TEAM_MAIL_DIR": str(team_mail_dir)}

        result = run_cli(
            "agents", "update",
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

    def test_updates_role(self, team_mail_dir: Path) -> None:
        """Can update role field."""
        cwd = team_mail_dir.parent
        user_token = _create_agent(team_mail_dir, "test-user", "Junior Dev")
        env = {"TEAM_MAIL_TOKEN": user_token, "TEAM_MAIL_DIR": str(team_mail_dir)}

        result = run_cli("agents", "update", "--role=Senior Dev", env=env, cwd=str(cwd))
        assert result.returncode == 0
        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert profile["role"] == "Senior Dev"

    def test_get_after_update(self, team_mail_dir: Path) -> None:
        """Verify agents get reflects updates."""
        cwd = team_mail_dir.parent
        user_token = _create_agent(team_mail_dir, "test-user")
        env = {"TEAM_MAIL_TOKEN": user_token, "TEAM_MAIL_DIR": str(team_mail_dir)}

        # Update then get
        _ = run_cli("agents", "update", "--status=Updated", env=env, cwd=str(cwd))
        result = run_cli("agents", "get", "test-user", env=env, cwd=str(cwd))
        assert result.returncode == 0
        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert profile["id"] == "test-user"
        assert profile["status"] == "Updated"

    def test_admin_updates_other_agent(self, team_mail_dir: Path) -> None:
        """Admin can update another agent's profile with --name."""
        cwd = team_mail_dir.parent
        env = _admin_env(team_mail_dir)
        _ = _create_agent(team_mail_dir, "target-agent", "Original Role")

        result = run_cli(
            "agents", "update",
            "--name=target-agent",
            "--role=New Role",
            "--status=Busy",
            env=env, cwd=str(cwd),
        )
        assert result.returncode == 0
        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert profile["role"] == "New Role"
        assert profile["status"] == "Busy"


# ---------- inbox ----------


class TestInbox:
    def test_shows_summary(self, team_mail_dir: Path) -> None:
        cwd = team_mail_dir.parent

        # Create sender and recipient
        sender_token = _create_agent(team_mail_dir, "sender")
        recipient_token = _create_agent(team_mail_dir, "recipient")

        # Send a message
        sender_env = {"TEAM_MAIL_TOKEN": sender_token, "TEAM_MAIL_DIR": str(team_mail_dir)}
        result = run_cli("send", "recipient", "Hello!", env=sender_env, cwd=str(cwd))
        assert result.returncode == 0

        # Check inbox
        recipient_env = {"TEAM_MAIL_TOKEN": recipient_token, "TEAM_MAIL_DIR": str(team_mail_dir)}
        result = run_cli("inbox", env=recipient_env, cwd=str(cwd))
        assert result.returncode == 0
        assert "1 unread message from sender" in result.stdout

    def test_empty_inbox(self, team_mail_dir: Path) -> None:
        cwd = team_mail_dir.parent
        user_token = _create_agent(team_mail_dir, "test-user")
        env = {"TEAM_MAIL_TOKEN": user_token, "TEAM_MAIL_DIR": str(team_mail_dir)}

        result = run_cli("inbox", env=env, cwd=str(cwd))
        assert result.returncode == 0
        assert "No messages" in result.stdout

    def test_password_rejects_admin(self, team_mail_dir: Path) -> None:
        """inbox: --password authenticates as admin but fails without --agent."""
        cwd = team_mail_dir.parent
        env = {"TEAM_MAIL_DIR": str(team_mail_dir)}

        result = run_cli("inbox", f"--password={PASSWORD}", env=env, cwd=str(cwd))
        assert result.returncode != 0
        assert "--password authenticates as admin" in result.stderr

    def test_admin_impersonation(self, team_mail_dir: Path) -> None:
        """inbox: admin can use --agent to check another user's inbox."""
        cwd = team_mail_dir.parent
        env = {"TEAM_MAIL_DIR": str(team_mail_dir)}

        # Create agents
        sender_token = _create_agent(team_mail_dir, "sender")
        _ = _create_agent(team_mail_dir, "recipient")

        # Send a message as sender
        sender_env = {"TEAM_MAIL_TOKEN": sender_token, "TEAM_MAIL_DIR": str(team_mail_dir)}
        _ = run_cli("send", "recipient", "Hello from sender!", env=sender_env, cwd=str(cwd))

        # Admin checks recipient's inbox using --password and --user
        result = run_cli(
            "inbox", f"--password={PASSWORD}", "--user=recipient",
            env=env, cwd=str(cwd),
        )
        assert result.returncode == 0
        assert "1 unread message from sender" in result.stdout


# ---------- inbox read ----------


class TestInboxRead:
    def test_reads_and_marks(self, team_mail_dir: Path) -> None:
        cwd = team_mail_dir.parent

        # Create sender and recipient
        sender_token = _create_agent(team_mail_dir, "sender")
        recipient_token = _create_agent(team_mail_dir, "recipient")

        # Send a message
        sender_env = {"TEAM_MAIL_TOKEN": sender_token, "TEAM_MAIL_DIR": str(team_mail_dir)}
        _ = run_cli("send", "recipient", "Hello!", env=sender_env, cwd=str(cwd))

        # Read inbox
        recipient_env = {"TEAM_MAIL_TOKEN": recipient_token, "TEAM_MAIL_DIR": str(team_mail_dir)}
        result = run_cli("inbox", "read", env=recipient_env, cwd=str(cwd))
        assert result.returncode == 0
        msg: dict[str, str] = json.loads(result.stdout.strip())
        assert msg["from"] == "sender"
        assert msg["body"] == "Hello!"

        # Should be marked as read now
        result = run_cli("inbox", env=recipient_env, cwd=str(cwd))
        assert "No messages" in result.stdout

    def test_silent_on_empty(self, team_mail_dir: Path) -> None:
        cwd = team_mail_dir.parent
        user_token = _create_agent(team_mail_dir, "test-user")
        env = {"TEAM_MAIL_TOKEN": user_token, "TEAM_MAIL_DIR": str(team_mail_dir)}

        result = run_cli("inbox", "read", env=env, cwd=str(cwd))
        assert result.returncode == 0
        assert result.stdout == ""

    def test_excludes_to_field_by_default(self, team_mail_dir: Path) -> None:
        """inbox read excludes 'to' field for regular agents (it's redundant)."""
        cwd = team_mail_dir.parent
        sender_token = _create_agent(team_mail_dir, "sender")
        recipient_token = _create_agent(team_mail_dir, "recipient")

        # Send a message
        sender_env = {"TEAM_MAIL_TOKEN": sender_token, "TEAM_MAIL_DIR": str(team_mail_dir)}
        _ = run_cli("send", "recipient", "Hello!", env=sender_env, cwd=str(cwd))

        # Read inbox - 'to' should NOT be in output
        recipient_env = {"TEAM_MAIL_TOKEN": recipient_token, "TEAM_MAIL_DIR": str(team_mail_dir)}
        result = run_cli("inbox", "read", env=recipient_env, cwd=str(cwd))
        assert result.returncode == 0
        msg: dict[str, str] = json.loads(result.stdout.strip())
        assert "to" not in msg
        assert msg["from"] == "sender"

    def test_includes_to_field_for_admin(self, team_mail_dir: Path) -> None:
        """inbox read includes 'to' field when admin is impersonating."""
        cwd = team_mail_dir.parent
        sender_token = _create_agent(team_mail_dir, "sender")
        _ = _create_agent(team_mail_dir, "recipient")

        # Send a message
        sender_env = {"TEAM_MAIL_TOKEN": sender_token, "TEAM_MAIL_DIR": str(team_mail_dir)}
        _ = run_cli("send", "recipient", "Hello!", env=sender_env, cwd=str(cwd))

        # Read inbox as admin - 'to' should be included
        admin_env = _admin_env(team_mail_dir)
        result = run_cli("inbox", "read", "--user=recipient", env=admin_env, cwd=str(cwd))
        assert result.returncode == 0
        msg: dict[str, str] = json.loads(result.stdout.strip())
        assert msg["to"] == "recipient"

    def test_include_read_filter(self, team_mail_dir: Path) -> None:
        """--include-read shows already-read messages."""
        cwd = team_mail_dir.parent
        sender_token = _create_agent(team_mail_dir, "sender")
        recipient_token = _create_agent(team_mail_dir, "recipient")

        # Send a message
        sender_env = {"TEAM_MAIL_TOKEN": sender_token, "TEAM_MAIL_DIR": str(team_mail_dir)}
        _ = run_cli("send", "recipient", "Message 1", env=sender_env, cwd=str(cwd))

        # Read inbox (marks as read)
        recipient_env = {"TEAM_MAIL_TOKEN": recipient_token, "TEAM_MAIL_DIR": str(team_mail_dir)}
        result = run_cli("inbox", "read", env=recipient_env, cwd=str(cwd))
        assert result.returncode == 0
        assert "Message 1" in result.stdout

        # Normal read shows nothing (already read)
        result = run_cli("inbox", "read", env=recipient_env, cwd=str(cwd))
        assert result.returncode == 0
        assert result.stdout == ""

        # With --include-read, message is shown again
        result = run_cli("inbox", "read", "--include-read", env=recipient_env, cwd=str(cwd))
        assert result.returncode == 0
        assert "Message 1" in result.stdout

    def test_from_filter(self, team_mail_dir: Path) -> None:
        """--from filters messages by sender."""
        cwd = team_mail_dir.parent
        alice_token = _create_agent(team_mail_dir, "alice-sender")
        bob_token = _create_agent(team_mail_dir, "bob-sender")
        recipient_token = _create_agent(team_mail_dir, "recipient")

        # Send messages from two senders
        env1 = {"TEAM_MAIL_TOKEN": alice_token, "TEAM_MAIL_DIR": str(team_mail_dir)}
        env2 = {"TEAM_MAIL_TOKEN": bob_token, "TEAM_MAIL_DIR": str(team_mail_dir)}
        _ = run_cli("send", "recipient", "From alice", env=env1, cwd=str(cwd))
        _ = run_cli("send", "recipient", "From bob", env=env2, cwd=str(cwd))

        # Filter by alice-sender
        recipient_env = {"TEAM_MAIL_TOKEN": recipient_token, "TEAM_MAIL_DIR": str(team_mail_dir)}
        result = run_cli("inbox", "read", "--from=alice-sender", env=recipient_env, cwd=str(cwd))
        assert result.returncode == 0
        assert "From alice" in result.stdout
        assert "From bob" not in result.stdout


# ---------- send ----------


class TestSend:
    def test_sends_message(self, team_mail_dir: Path) -> None:
        cwd = team_mail_dir.parent

        # Create sender and recipient
        sender_token = _create_agent(team_mail_dir, "sender")
        _ = _create_agent(team_mail_dir, "recipient")

        sender_env = {"TEAM_MAIL_TOKEN": sender_token, "TEAM_MAIL_DIR": str(team_mail_dir)}
        result = run_cli("send", "recipient", "Test message", env=sender_env, cwd=str(cwd))
        assert result.returncode == 0

        response: dict[str, str] = json.loads(result.stdout)
        assert response["status"] == "delivered"
        assert response["to"] == "recipient"

        # Verify message in recipient inbox
        inbox = team_mail_dir / "agents" / "recipient" / "mail" / "inbox.jsonl"
        msg: dict[str, str] = json.loads(inbox.read_text().strip())
        assert msg["from"] == "sender"
        assert msg["body"] == "Test message"

        # Verify message in sender sent
        sent = team_mail_dir / "agents" / "sender" / "mail" / "sent.jsonl"
        msg = json.loads(sent.read_text().strip())
        assert msg["to"] == "recipient"

    def test_unknown_recipient(self, team_mail_dir: Path) -> None:
        cwd = team_mail_dir.parent
        sender_token = _create_agent(team_mail_dir, "sender")
        sender_env = {"TEAM_MAIL_TOKEN": sender_token, "TEAM_MAIL_DIR": str(team_mail_dir)}

        result = run_cli("send", "nobody", "Test", env=sender_env, cwd=str(cwd))
        assert result.returncode != 0
        assert "not found" in result.stderr

    def test_special_characters(self, team_mail_dir: Path) -> None:
        cwd = team_mail_dir.parent
        sender_token = _create_agent(team_mail_dir, "sender")
        _ = _create_agent(team_mail_dir, "recipient")

        sender_env = {"TEAM_MAIL_TOKEN": sender_token, "TEAM_MAIL_DIR": str(team_mail_dir)}
        body = 'Changed "auth" exports & fixed <types>'
        result = run_cli("send", "recipient", body, env=sender_env, cwd=str(cwd))
        assert result.returncode == 0

        inbox = team_mail_dir / "agents" / "recipient" / "mail" / "inbox.jsonl"
        msg: dict[str, str] = json.loads(inbox.read_text().strip())
        assert msg["body"] == body

    def test_admin_send_on_behalf(self, team_mail_dir: Path) -> None:
        """send: admin can use --agent to send on behalf of another user."""
        cwd = team_mail_dir.parent
        env = {"TEAM_MAIL_DIR": str(team_mail_dir)}

        # Create agents
        _ = _create_agent(team_mail_dir, "alice")
        _ = _create_agent(team_mail_dir, "bob")

        # Admin sends from alice to bob
        result = run_cli(
            "send", "--user=alice", f"--password={PASSWORD}",
            "bob", "Hello from alice (sent by admin)",
            env=env, cwd=str(cwd),
        )
        assert result.returncode == 0

        # Verify message in bob's inbox shows alice as sender
        inbox = team_mail_dir / "agents" / "bob" / "mail" / "inbox.jsonl"
        msg: dict[str, str] = json.loads(inbox.read_text().strip())
        assert msg["from"] == "alice"
        assert msg["body"] == "Hello from alice (sent by admin)"

        # Verify message in alice's sent log
        sent = team_mail_dir / "agents" / "alice" / "mail" / "sent.jsonl"
        msg = json.loads(sent.read_text().strip())
        assert msg["to"] == "bob"


# ---------- env ----------


class TestEnv:
    def test_outputs_exports(self, team_mail_dir: Path) -> None:
        cwd = team_mail_dir.parent
        result = run_cli("env", cwd=str(cwd))
        assert result.returncode == 0
        assert "TEAM_MAIL_DIR" in result.stdout
        assert str(team_mail_dir) in result.stdout

    def test_silent_when_no_dir(self, tmp_path: Path) -> None:
        result = run_cli("env", cwd=str(tmp_path))
        assert result.returncode == 0
        assert result.stdout == ""


# ---------- username validation ----------


class TestUsernameValidation:
    def test_valid_names(self) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location("team_mail", CLI)
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

        spec = importlib.util.spec_from_file_location("team_mail", CLI)
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
    def test_token_identifies_user(self, team_mail_dir: Path) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location("team_mail", CLI)
        assert spec is not None
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)

        # Create user and get token
        user_token = _create_agent(team_mail_dir, "test-user")

        # Validate token
        result = module._validate_token(team_mail_dir, user_token)
        assert result is not None
        name, is_admin = result
        assert name == "test-user"
        assert not is_admin  # User tokens are never admin

    def test_invalid_token(self, team_mail_dir: Path) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location("team_mail", CLI)
        assert spec is not None
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)

        result = module._validate_token(team_mail_dir, "xxxxx")
        assert result is None

    def test_token_cli_option(self, team_mail_dir: Path) -> None:
        """Test that --token works as alternative to TEAM_MAIL_TOKEN env var."""
        cwd = team_mail_dir.parent
        user_token = _create_agent(team_mail_dir, "cli-test-user")

        # Use --token instead of env var (--token is on the subcommand)
        env = {"TEAM_MAIL_DIR": str(team_mail_dir)}  # No TEAM_MAIL_TOKEN
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

        team_mail_dir = tmp_path / ".team-mail"

        # 2. Use admin password env var (no admin tokens)
        admin_env = _admin_env(team_mail_dir)

        # 3. Create agents
        result = run_cli(
            "agents", "add", "--name=maya-backend", "--role=Backend Engineer",
            "--tags=backend,auth",
            env=admin_env, cwd=str(tmp_path),
        )
        assert result.returncode == 0

        result = run_cli(
            "agents", "add", "--name=alex-frontend", "--role=Frontend Dev",
            "--tags=frontend,ui",
            env=admin_env, cwd=str(tmp_path),
        )
        assert result.returncode == 0

        # 4. Get user tokens
        result = run_cli("create-token", "--agent", "maya-backend", f"--password={PASSWORD}", cwd=str(tmp_path))
        maya_token = result.stdout.strip()

        result = run_cli("create-token", "--agent", "alex-frontend", f"--password={PASSWORD}", cwd=str(tmp_path))
        alex_token = result.stdout.strip()

        # 5. Maya sends message to Alex
        maya_env = {"TEAM_MAIL_TOKEN": maya_token, "TEAM_MAIL_DIR": str(team_mail_dir)}
        result = run_cli("send", "alex-frontend", "API is ready for integration", env=maya_env, cwd=str(tmp_path))
        assert result.returncode == 0

        # 6. Alex checks inbox
        alex_env = {"TEAM_MAIL_TOKEN": alex_token, "TEAM_MAIL_DIR": str(team_mail_dir)}
        result = run_cli("inbox", env=alex_env, cwd=str(tmp_path))
        assert "1 unread message from maya-backend" in result.stdout

        # 7. Alex reads messages
        result = run_cli("inbox", "read", env=alex_env, cwd=str(tmp_path))
        assert result.returncode == 0
        msg: dict[str, str] = json.loads(result.stdout.strip())
        assert msg["from"] == "maya-backend"
        assert msg["body"] == "API is ready for integration"

        # 8. Inbox should be empty now
        result = run_cli("inbox", env=alex_env, cwd=str(tmp_path))
        assert "No messages" in result.stdout

        # 9. Alex replies
        result = run_cli("send", "maya-backend", "Thanks! Starting integration now.", env=alex_env, cwd=str(tmp_path))
        assert result.returncode == 0

        # 10. Maya reads reply
        result = run_cli("inbox", "read", env=maya_env, cwd=str(tmp_path))
        msg = json.loads(result.stdout.strip())
        assert msg["from"] == "alex-frontend"
        assert "integration" in msg["body"]
