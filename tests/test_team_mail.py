"""Tests for team_mail.py CLI with token-based authentication."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import typing as T
from pathlib import Path

import pytest

CLI: T.Final[str] = str(Path(__file__).resolve().parent.parent / "cli" / "team_mail.py")
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
    result = run_cli("admin", "init", f"--password={PASSWORD}", cwd=str(tmp_path))
    assert result.returncode == 0, result.stderr
    return tmp_path / ".team-mail"


@pytest.fixture
def admin_token(team_mail_dir: Path) -> str:
    """Get an admin token."""
    cwd = team_mail_dir.parent
    result = run_cli("admin", "auth", "--admin", f"--password={PASSWORD}", cwd=str(cwd))
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def _create_user(
    team_mail_dir: Path,
    admin_token: str,
    name: str,
    role: str = "Test User",
) -> str:
    """Create a user and return their token."""
    cwd = team_mail_dir.parent
    env = {"TEAM_MAIL_TOKEN": admin_token, "TEAM_MAIL_DIR": str(team_mail_dir)}

    # Create user
    result = run_cli("users", "add", name, role, env=env, cwd=str(cwd))
    assert result.returncode == 0, result.stderr

    # Get user token
    result = run_cli("admin", "auth", "--user", name, f"--password={PASSWORD}", cwd=str(cwd))
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


# ---------- admin init ----------


class TestAdminInit:
    def test_creates_structure(self, tmp_path: Path) -> None:
        result = run_cli("admin", "init", f"--password={PASSWORD}", cwd=str(tmp_path))
        assert result.returncode == 0
        assert "Initialized" in result.stdout

        team_mail_dir = tmp_path / ".team-mail"
        assert team_mail_dir.is_dir()
        assert (team_mail_dir / "admin.json").exists()
        assert (team_mail_dir / "tokens").is_dir()
        assert (team_mail_dir / "users").is_dir()

    def test_fails_if_already_initialized(self, team_mail_dir: Path) -> None:
        cwd = team_mail_dir.parent
        result = run_cli("admin", "init", f"--password={PASSWORD}", cwd=str(cwd))
        assert result.returncode != 0
        assert "Already initialized" in result.stderr

    def test_requires_password(self, tmp_path: Path) -> None:
        result = run_cli("admin", "init", cwd=str(tmp_path))
        assert result.returncode != 0


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

        # Old password should fail
        result = run_cli("admin", "auth", "--admin", f"--password={PASSWORD}", cwd=str(cwd))
        assert result.returncode != 0

        # New password should work
        result = run_cli("admin", "auth", "--admin", "--password=newpass123", cwd=str(cwd))
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


# ---------- admin auth ----------


class TestAdminAuth:
    def test_mints_admin_token(self, team_mail_dir: Path) -> None:
        cwd = team_mail_dir.parent
        result = run_cli("admin", "auth", "--admin", f"--password={PASSWORD}", cwd=str(cwd))
        assert result.returncode == 0
        token = result.stdout.strip()
        assert len(token) == 5

    def test_mints_user_token(self, team_mail_dir: Path, admin_token: str) -> None:
        cwd = team_mail_dir.parent
        env = {"TEAM_MAIL_TOKEN": admin_token, "TEAM_MAIL_DIR": str(team_mail_dir)}

        # Create user first
        result = run_cli("users", "add", "test-user", "Test", env=env, cwd=str(cwd))
        assert result.returncode == 0

        # Mint token
        result = run_cli("admin", "auth", "--user", "test-user", f"--password={PASSWORD}", cwd=str(cwd))
        assert result.returncode == 0
        token = result.stdout.strip()
        assert len(token) == 5

    def test_rejects_nonexistent_user(self, team_mail_dir: Path) -> None:
        cwd = team_mail_dir.parent
        result = run_cli("admin", "auth", "--user", "nobody", f"--password={PASSWORD}", cwd=str(cwd))
        assert result.returncode != 0
        assert "not found" in result.stderr


# ---------- users add ----------


class TestUsersAdd:
    def test_creates_user(self, team_mail_dir: Path, admin_token: str) -> None:
        cwd = team_mail_dir.parent
        env = {"TEAM_MAIL_TOKEN": admin_token, "TEAM_MAIL_DIR": str(team_mail_dir)}

        result = run_cli(
            "users", "add", "maya-backend", "Backend Engineer",
            "--status=Working on auth",
            "--tags=backend,auth",
            env=env, cwd=str(cwd),
        )
        assert result.returncode == 0

        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert profile["name"] == "maya-backend"
        assert profile["role"] == "Backend Engineer"
        assert profile["status"] == "Working on auth"
        assert profile["tags"] == ["backend", "auth"]

        # Check directory structure
        user_dir = team_mail_dir / "users" / "maya-backend"
        assert user_dir.is_dir()
        assert (user_dir / "profile.json").exists()
        assert (user_dir / "mail" / "inbox.jsonl").exists()

    def test_requires_admin_token(self, team_mail_dir: Path) -> None:
        cwd = team_mail_dir.parent
        # No token
        result = run_cli("users", "add", "test-user", "Test", cwd=str(cwd))
        assert result.returncode != 0
        assert "TEAM_MAIL_TOKEN" in result.stderr

    def test_rejects_user_token(self, team_mail_dir: Path, admin_token: str) -> None:
        cwd = team_mail_dir.parent
        env = {"TEAM_MAIL_TOKEN": admin_token, "TEAM_MAIL_DIR": str(team_mail_dir)}

        # Create user and get their token
        _ = run_cli("users", "add", "test-user", "Test", env=env, cwd=str(cwd))
        result = run_cli("admin", "auth", "--user", "test-user", f"--password={PASSWORD}", cwd=str(cwd))
        user_token = result.stdout.strip()

        # Try to create with user token
        env["TEAM_MAIL_TOKEN"] = user_token
        result = run_cli("users", "add", "another-user", "Test", env=env, cwd=str(cwd))
        assert result.returncode != 0
        assert "Admin token required" in result.stderr

    def test_validates_username(self, team_mail_dir: Path, admin_token: str) -> None:
        cwd = team_mail_dir.parent
        env = {"TEAM_MAIL_TOKEN": admin_token, "TEAM_MAIL_DIR": str(team_mail_dir)}

        # Too short
        result = run_cli("users", "add", "ab", "Test", env=env, cwd=str(cwd))
        assert result.returncode != 0
        assert "at least 3" in result.stderr

        # Invalid chars
        result = run_cli("users", "add", "User-Name", "Test", env=env, cwd=str(cwd))
        assert result.returncode != 0
        assert "lowercase" in result.stderr

    def test_fails_if_user_exists(self, team_mail_dir: Path, admin_token: str) -> None:
        cwd = team_mail_dir.parent
        env = {"TEAM_MAIL_TOKEN": admin_token, "TEAM_MAIL_DIR": str(team_mail_dir)}

        _ = run_cli("users", "add", "test-user", "Test", env=env, cwd=str(cwd))
        result = run_cli("users", "add", "test-user", "Test", env=env, cwd=str(cwd))
        assert result.returncode != 0
        assert "already exists" in result.stderr

    def test_password_option(self, team_mail_dir: Path) -> None:
        """admin create: --password works as alternative to token."""
        cwd = team_mail_dir.parent
        env = {"TEAM_MAIL_DIR": str(team_mail_dir)}

        # No token, just password
        result = run_cli(
            "users", "add", "pw-user", "Password User",
            f"--password={PASSWORD}",
            env=env, cwd=str(cwd),
        )
        assert result.returncode == 0
        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert profile["name"] == "pw-user"


# ---------- users ----------


class TestUsers:
    def test_lists_users(self, team_mail_dir: Path, admin_token: str) -> None:
        """users list: returns JSON array of profiles (without dates by default)."""
        cwd = team_mail_dir.parent
        env = {"TEAM_MAIL_DIR": str(team_mail_dir)}

        # Create some users
        admin_env = {"TEAM_MAIL_TOKEN": admin_token, **env}
        _ = run_cli("users", "add", "user-a", "Title A", env=admin_env, cwd=str(cwd))
        _ = run_cli("users", "add", "user-b", "Title B", env=admin_env, cwd=str(cwd))

        result = run_cli("users", "list", env=env, cwd=str(cwd))
        assert result.returncode == 0
        profiles = json.loads(result.stdout)
        assert len(profiles) == 2
        assert profiles[0]["name"] == "user-a"
        assert profiles[0]["role"] == "Title A"
        assert "joined" not in profiles[0]  # No dates by default
        assert profiles[1]["name"] == "user-b"

    def test_names_only(self, team_mail_dir: Path, admin_token: str) -> None:
        """users list --names-only outputs just usernames."""
        cwd = team_mail_dir.parent
        env = {"TEAM_MAIL_DIR": str(team_mail_dir)}
        admin_env = {"TEAM_MAIL_TOKEN": admin_token, **env}
        _ = run_cli("users", "add", "user-a", "A", env=admin_env, cwd=str(cwd))
        _ = run_cli("users", "add", "user-b", "B", env=admin_env, cwd=str(cwd))

        result = run_cli("users", "list", "--names-only", env=env, cwd=str(cwd))
        assert result.returncode == 0
        lines = result.stdout.strip().split("\n")
        assert lines == ["user-a", "user-b"]

    def test_no_self(self, team_mail_dir: Path, admin_token: str) -> None:
        """users list --no-self excludes the current user."""
        cwd = team_mail_dir.parent
        user_a_token = _create_user(team_mail_dir, admin_token, "user-a", "A")
        _ = _create_user(team_mail_dir, admin_token, "user-b", "B")

        env = {"TEAM_MAIL_TOKEN": user_a_token, "TEAM_MAIL_DIR": str(team_mail_dir)}
        result = run_cli("users", "list", "--names-only", "--no-self", env=env, cwd=str(cwd))
        assert result.returncode == 0
        lines = result.stdout.strip().split("\n")
        assert "user-a" not in lines
        assert "user-b" in lines

    def test_filter_by_tags(self, team_mail_dir: Path, admin_token: str) -> None:
        """users list --tags filters users by tag."""
        cwd = team_mail_dir.parent
        env = {"TEAM_MAIL_DIR": str(team_mail_dir)}
        admin_env = {"TEAM_MAIL_TOKEN": admin_token, **env}
        _ = run_cli("users", "add", "backend-dev", "Backend", "--tags=backend,api", env=admin_env, cwd=str(cwd))
        _ = run_cli("users", "add", "frontend-dev", "Frontend", "--tags=frontend,ui", env=admin_env, cwd=str(cwd))

        result = run_cli("users", "list", "--names-only", "--tags=backend", env=env, cwd=str(cwd))
        assert result.returncode == 0
        lines = result.stdout.strip().split("\n")
        assert "backend-dev" in lines
        assert "frontend-dev" not in lines

    def test_get_user(self, team_mail_dir: Path, admin_token: str) -> None:
        """users get <name> returns profile JSON (without dates by default)."""
        cwd = team_mail_dir.parent
        env = {"TEAM_MAIL_DIR": str(team_mail_dir)}
        admin_env = {"TEAM_MAIL_TOKEN": admin_token, **env}
        _ = run_cli("users", "add", "test-user", "Test Title", env=admin_env, cwd=str(cwd))

        result = run_cli("users", "get", "test-user", env=env, cwd=str(cwd))
        assert result.returncode == 0
        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert profile["name"] == "test-user"
        assert profile["role"] == "Test Title"
        assert "joined" not in profile  # No dates by default

    def test_full_flag(self, team_mail_dir: Path, admin_token: str) -> None:
        """--full includes joined/updated dates."""
        cwd = team_mail_dir.parent
        env = {"TEAM_MAIL_DIR": str(team_mail_dir)}
        admin_env = {"TEAM_MAIL_TOKEN": admin_token, **env}
        _ = run_cli("users", "add", "test-user", "Test", env=admin_env, cwd=str(cwd))

        # users get --full
        result = run_cli("users", "get", "test-user", "--full", env=env, cwd=str(cwd))
        assert result.returncode == 0
        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert "joined" in profile
        assert "updated" in profile

        # users list --full
        result = run_cli("users", "list", "--full", env=env, cwd=str(cwd))
        profiles = json.loads(result.stdout)
        assert "joined" in profiles[0]

    def test_empty_when_no_users(self, team_mail_dir: Path) -> None:
        cwd = team_mail_dir.parent
        env = {"TEAM_MAIL_DIR": str(team_mail_dir)}
        result = run_cli("users", "list", env=env, cwd=str(cwd))
        assert result.returncode == 0
        profiles = json.loads(result.stdout)
        assert profiles == []


# ---------- profile ----------


class TestProfile:
    def test_view_own_profile(self, team_mail_dir: Path, admin_token: str) -> None:
        cwd = team_mail_dir.parent
        user_token = _create_user(team_mail_dir, admin_token, "test-user", "Test User")
        env = {"TEAM_MAIL_TOKEN": user_token, "TEAM_MAIL_DIR": str(team_mail_dir)}

        result = run_cli("profile", "show", env=env, cwd=str(cwd))
        assert result.returncode == 0
        assert "test-user" in result.stdout
        assert "Test User" in result.stdout

    def test_view_other_profile(self, team_mail_dir: Path, admin_token: str) -> None:
        """View another user's profile via 'users get <name>' (public, no auth required)."""
        cwd = team_mail_dir.parent
        env = {"TEAM_MAIL_TOKEN": admin_token, "TEAM_MAIL_DIR": str(team_mail_dir)}
        _ = run_cli("users", "add", "other-user", "Other", env=env, cwd=str(cwd))

        # View without auth (public) - uses 'users get <name>'
        env_no_token = {"TEAM_MAIL_DIR": str(team_mail_dir)}
        result = run_cli("users", "get", "other-user", env=env_no_token, cwd=str(cwd))
        assert result.returncode == 0
        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert profile["name"] == "other-user"

    def test_llm_format(self, team_mail_dir: Path, admin_token: str) -> None:
        """profile show outputs LLM-friendly format by default."""
        cwd = team_mail_dir.parent
        user_token = _create_user(team_mail_dir, admin_token, "maya-backend", "Backend Engineer")
        env = {"TEAM_MAIL_TOKEN": user_token, "TEAM_MAIL_DIR": str(team_mail_dir)}

        result = run_cli("profile", "show", env=env, cwd=str(cwd))
        assert result.returncode == 0
        assert "maya-backend" in result.stdout
        assert "Backend Engineer" in result.stdout

    def test_requires_token_for_own_profile(self, team_mail_dir: Path) -> None:
        cwd = team_mail_dir.parent
        env = {"TEAM_MAIL_DIR": str(team_mail_dir)}
        result = run_cli("profile", "show", env=env, cwd=str(cwd))
        assert result.returncode != 0
        assert "token" in result.stderr.lower()


# ---------- profile update ----------


class TestProfileUpdate:
    def test_updates_fields(self, team_mail_dir: Path, admin_token: str) -> None:
        cwd = team_mail_dir.parent
        user_token = _create_user(team_mail_dir, admin_token, "test-user")
        env = {"TEAM_MAIL_TOKEN": user_token, "TEAM_MAIL_DIR": str(team_mail_dir)}

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

    def test_show_after_update(self, team_mail_dir: Path, admin_token: str) -> None:
        """Verify show reflects updates."""
        cwd = team_mail_dir.parent
        user_token = _create_user(team_mail_dir, admin_token, "test-user")
        env = {"TEAM_MAIL_TOKEN": user_token, "TEAM_MAIL_DIR": str(team_mail_dir)}

        # Update then show
        _ = run_cli("profile", "update", "--status=Updated", env=env, cwd=str(cwd))
        result = run_cli("profile", "show", env=env, cwd=str(cwd))
        assert result.returncode == 0
        assert "test-user" in result.stdout
        assert "Updated" in result.stdout


# ---------- inbox ----------


class TestInbox:
    def test_shows_summary(self, team_mail_dir: Path, admin_token: str) -> None:
        cwd = team_mail_dir.parent

        # Create sender and recipient
        sender_token = _create_user(team_mail_dir, admin_token, "sender")
        recipient_token = _create_user(team_mail_dir, admin_token, "recipient")

        # Send a message
        sender_env = {"TEAM_MAIL_TOKEN": sender_token, "TEAM_MAIL_DIR": str(team_mail_dir)}
        result = run_cli("send", "recipient", "Hello!", env=sender_env, cwd=str(cwd))
        assert result.returncode == 0

        # Check inbox
        recipient_env = {"TEAM_MAIL_TOKEN": recipient_token, "TEAM_MAIL_DIR": str(team_mail_dir)}
        result = run_cli("inbox", env=recipient_env, cwd=str(cwd))
        assert result.returncode == 0
        assert "1 unread message from sender" in result.stdout

    def test_empty_inbox(self, team_mail_dir: Path, admin_token: str) -> None:
        cwd = team_mail_dir.parent
        user_token = _create_user(team_mail_dir, admin_token, "test-user")
        env = {"TEAM_MAIL_TOKEN": user_token, "TEAM_MAIL_DIR": str(team_mail_dir)}

        result = run_cli("inbox", env=env, cwd=str(cwd))
        assert result.returncode == 0
        assert "No messages" in result.stdout

    def test_password_rejects_admin(self, team_mail_dir: Path) -> None:
        """inbox: --password authenticates as admin but fails without --user."""
        cwd = team_mail_dir.parent
        env = {"TEAM_MAIL_DIR": str(team_mail_dir)}

        result = run_cli("inbox", f"--password={PASSWORD}", env=env, cwd=str(cwd))
        assert result.returncode != 0
        assert "--password authenticates as admin" in result.stderr

    def test_admin_impersonation(self, team_mail_dir: Path, admin_token: str) -> None:
        """inbox: admin can use --user to check another user's inbox."""
        cwd = team_mail_dir.parent
        env = {"TEAM_MAIL_DIR": str(team_mail_dir)}

        # Create users
        sender_token = _create_user(team_mail_dir, admin_token, "sender")
        _ = _create_user(team_mail_dir, admin_token, "recipient")

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
    def test_reads_and_marks(self, team_mail_dir: Path, admin_token: str) -> None:
        cwd = team_mail_dir.parent

        # Create sender and recipient
        sender_token = _create_user(team_mail_dir, admin_token, "sender")
        recipient_token = _create_user(team_mail_dir, admin_token, "recipient")

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

    def test_silent_on_empty(self, team_mail_dir: Path, admin_token: str) -> None:
        cwd = team_mail_dir.parent
        user_token = _create_user(team_mail_dir, admin_token, "test-user")
        env = {"TEAM_MAIL_TOKEN": user_token, "TEAM_MAIL_DIR": str(team_mail_dir)}

        result = run_cli("inbox", "read", env=env, cwd=str(cwd))
        assert result.returncode == 0
        assert result.stdout == ""


# ---------- send ----------


class TestSend:
    def test_sends_message(self, team_mail_dir: Path, admin_token: str) -> None:
        cwd = team_mail_dir.parent

        # Create sender and recipient
        sender_token = _create_user(team_mail_dir, admin_token, "sender")
        _ = _create_user(team_mail_dir, admin_token, "recipient")

        sender_env = {"TEAM_MAIL_TOKEN": sender_token, "TEAM_MAIL_DIR": str(team_mail_dir)}
        result = run_cli("send", "recipient", "Test message", env=sender_env, cwd=str(cwd))
        assert result.returncode == 0

        response: dict[str, str] = json.loads(result.stdout)
        assert response["status"] == "delivered"
        assert response["to"] == "recipient"

        # Verify message in recipient inbox
        inbox = team_mail_dir / "users" / "recipient" / "mail" / "inbox.jsonl"
        msg: dict[str, str] = json.loads(inbox.read_text().strip())
        assert msg["from"] == "sender"
        assert msg["body"] == "Test message"

        # Verify message in sender sent
        sent = team_mail_dir / "users" / "sender" / "mail" / "sent.jsonl"
        msg = json.loads(sent.read_text().strip())
        assert msg["to"] == "recipient"

    def test_unknown_recipient(self, team_mail_dir: Path, admin_token: str) -> None:
        cwd = team_mail_dir.parent
        sender_token = _create_user(team_mail_dir, admin_token, "sender")
        sender_env = {"TEAM_MAIL_TOKEN": sender_token, "TEAM_MAIL_DIR": str(team_mail_dir)}

        result = run_cli("send", "nobody", "Test", env=sender_env, cwd=str(cwd))
        assert result.returncode != 0
        assert "not found" in result.stderr

    def test_special_characters(self, team_mail_dir: Path, admin_token: str) -> None:
        cwd = team_mail_dir.parent
        sender_token = _create_user(team_mail_dir, admin_token, "sender")
        _ = _create_user(team_mail_dir, admin_token, "recipient")

        sender_env = {"TEAM_MAIL_TOKEN": sender_token, "TEAM_MAIL_DIR": str(team_mail_dir)}
        body = 'Changed "auth" exports & fixed <types>'
        result = run_cli("send", "recipient", body, env=sender_env, cwd=str(cwd))
        assert result.returncode == 0

        inbox = team_mail_dir / "users" / "recipient" / "mail" / "inbox.jsonl"
        msg: dict[str, str] = json.loads(inbox.read_text().strip())
        assert msg["body"] == body

    def test_admin_send_on_behalf(self, team_mail_dir: Path, admin_token: str) -> None:
        """send: admin can use --user to send on behalf of another user."""
        cwd = team_mail_dir.parent
        env = {"TEAM_MAIL_DIR": str(team_mail_dir)}

        # Create users
        _ = _create_user(team_mail_dir, admin_token, "alice")
        _ = _create_user(team_mail_dir, admin_token, "bob")

        # Admin sends from alice to bob
        result = run_cli(
            "send", "--user=alice", f"--password={PASSWORD}",
            "bob", "Hello from alice (sent by admin)",
            env=env, cwd=str(cwd),
        )
        assert result.returncode == 0

        # Verify message in bob's inbox shows alice as sender
        inbox = team_mail_dir / "users" / "bob" / "mail" / "inbox.jsonl"
        msg: dict[str, str] = json.loads(inbox.read_text().strip())
        assert msg["from"] == "alice"
        assert msg["body"] == "Hello from alice (sent by admin)"

        # Verify message in alice's sent log
        sent = team_mail_dir / "users" / "alice" / "mail" / "sent.jsonl"
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
    def test_token_identifies_user(self, team_mail_dir: Path, admin_token: str) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location("team_mail", CLI)
        assert spec is not None
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)

        # Create user and get token
        user_token = _create_user(team_mail_dir, admin_token, "test-user")

        # Validate token
        result = module._validate_token(team_mail_dir, user_token)
        assert result is not None
        name, is_admin = result
        assert name == "test-user"
        assert not is_admin

        # Validate admin token
        result = module._validate_token(team_mail_dir, admin_token)
        assert result is not None
        name, is_admin = result
        assert name == "_admin"
        assert is_admin

    def test_invalid_token(self, team_mail_dir: Path) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location("team_mail", CLI)
        assert spec is not None
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)

        result = module._validate_token(team_mail_dir, "xxxxx")
        assert result is None

    def test_token_cli_option(self, team_mail_dir: Path, admin_token: str) -> None:
        """Test that --token works as alternative to TEAM_MAIL_TOKEN env var."""
        cwd = team_mail_dir.parent
        user_token = _create_user(team_mail_dir, admin_token, "cli-test-user")

        # Use --token instead of env var (--token is on the subcommand)
        env = {"TEAM_MAIL_DIR": str(team_mail_dir)}  # No TEAM_MAIL_TOKEN
        result = run_cli("profile", "show", f"--token={user_token}", env=env, cwd=str(cwd))
        assert result.returncode == 0
        assert "cli-test-user" in result.stdout


# ---------- Integration test ----------


class TestIntegration:
    def test_full_workflow(self, tmp_path: Path) -> None:
        """Full workflow: init → create users → auth → send mail → read mail."""
        # 1. Initialize
        result = run_cli("admin", "init", f"--password={PASSWORD}", cwd=str(tmp_path))
        assert result.returncode == 0

        team_mail_dir = tmp_path / ".team-mail"

        # 2. Get admin token
        result = run_cli("admin", "auth", "--admin", f"--password={PASSWORD}", cwd=str(tmp_path))
        assert result.returncode == 0
        admin_token = result.stdout.strip()

        admin_env = {"TEAM_MAIL_TOKEN": admin_token, "TEAM_MAIL_DIR": str(team_mail_dir)}

        # 3. Create users
        result = run_cli(
            "users", "add", "maya-backend", "Backend Engineer",
            "--tags=backend,auth",
            env=admin_env, cwd=str(tmp_path),
        )
        assert result.returncode == 0

        result = run_cli(
            "users", "add", "alex-frontend", "Frontend Dev",
            "--tags=frontend,ui",
            env=admin_env, cwd=str(tmp_path),
        )
        assert result.returncode == 0

        # 4. Get user tokens
        result = run_cli("admin", "auth", "--user", "maya-backend", f"--password={PASSWORD}", cwd=str(tmp_path))
        maya_token = result.stdout.strip()

        result = run_cli("admin", "auth", "--user", "alex-frontend", f"--password={PASSWORD}", cwd=str(tmp_path))
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
