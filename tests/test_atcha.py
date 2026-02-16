"""Tests for atcha.py CLI with token-based authentication."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import typing as T
from pathlib import Path

import pytest

import re

CLI: T.Final[str] = str(Path(__file__).resolve().parent.parent / "src" / "atcha" / "cli" / "atcha.py")
PASSWORD: T.Final[str] = "testpass123"


def _slugify_role(role: str) -> str:
    """Mirror the role slugification from validation._slugify_name."""
    s = role.lower().strip()
    s = s.replace("_", "-").replace(" ", "-")
    s = re.sub(r"[^a-z0-9-]", "", s)
    s = re.sub(r"-{2,}", "-", s)
    s = s.strip("-")
    return s


def _make_user_id(name: str, role: str) -> str:
    """Compute the user_id from name + role (mirrors auth._generate_user_id)."""
    return f"{name}-{_slugify_role(role)}"


def _user_dir(atcha_dir: Path, name: str, role: str) -> Path:
    """Get the Path to a user's directory given name and role."""
    return atcha_dir / "users" / _make_user_id(name, role)


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
    result = run_cli("admin", "init", f"--password={PASSWORD}", cwd=str(tmp_path))
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
    token, _ = _create_user_full(atcha_dir, name, role)
    return token


def _create_user_full(
    atcha_dir: Path,
    name: str,
    role: str = "Test Agent",
) -> tuple[str, str]:
    """Create a user and return (token, user_id)."""
    cwd = atcha_dir.parent
    env = _admin_env(atcha_dir)

    # Create user (returns profile with generated id)
    result = run_cli("admin", "users", "create", f"--name={name}", f"--role={role}", env=env, cwd=str(cwd))
    assert result.returncode == 0, result.stderr

    # Extract user name and id from profile
    profile = json.loads(result.stdout)
    user_name = profile["name"]
    user_id: str = profile["id"]

    # Get user token using the name
    result = run_cli("admin", "create-token", "--user", user_name, env=env, cwd=str(cwd))
    assert result.returncode == 0, result.stderr
    return result.stdout.strip(), user_id


def _user_id(atcha_dir: Path, name: str) -> str:
    """Look up a user's ID by scanning profile.json files for matching name."""
    users_dir = atcha_dir / "users"
    for user_dir in users_dir.iterdir():
        if not user_dir.is_dir():
            continue
        profile_path = user_dir / "profile.json"
        if profile_path.exists():
            profile = json.loads(profile_path.read_text())
            if profile.get("name") == name:
                uid: str = profile["id"]
                return uid
    msg = f"No user with name '{name}' found in {users_dir}"
    raise ValueError(msg)


# ---------- init ----------


class TestInit:
    def test_creates_structure(self, tmp_path: Path) -> None:
        result = run_cli("admin", "init", f"--password={PASSWORD}", cwd=str(tmp_path))
        assert result.returncode == 0
        assert "Initialized" in result.stdout

        atcha_dir = tmp_path / ".atcha"
        assert atcha_dir.is_dir()
        assert (atcha_dir / "admin.json").exists()
        assert (atcha_dir / "tokens").is_dir()
        assert (atcha_dir / "users").is_dir()

    def test_fails_if_already_initialized(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent
        result = run_cli("admin", "init", f"--password={PASSWORD}", cwd=str(cwd))
        assert result.returncode != 0
        assert "Already initialized" in result.stderr

    def test_prompts_for_password(self, tmp_path: Path) -> None:
        # Without --password, it should attempt interactive prompt
        # In non-interactive mode (CI), this will fail with EOF
        result = run_cli("admin", "init", cwd=str(tmp_path))
        # Should either prompt or fail gracefully
        # Since tests run non-interactively, expect failure
        assert result.returncode != 0

    def test_status_returns_0_when_initialized(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent
        result = run_cli("admin", "status", cwd=str(cwd))
        assert result.returncode == 0
        assert "Atcha initialized" in result.stdout

    def test_status_returns_1_when_not_initialized(self, tmp_path: Path) -> None:
        result = run_cli("admin", "status", cwd=str(tmp_path))
        assert result.returncode == 1
        assert result.stdout == ""

    def test_status_quiet_suppresses_output(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent
        result = run_cli("admin", "status", "-q", cwd=str(cwd))
        assert result.returncode == 0
        assert result.stdout == ""

    def test_status_quiet_returns_1_when_not_initialized(self, tmp_path: Path) -> None:
        result = run_cli("admin", "status", "--quiet", cwd=str(tmp_path))
        assert result.returncode == 1
        assert result.stdout == ""


# ---------- admin password ----------


class TestAdminPassword:
    def test_changes_password(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent
        result = run_cli(
            "admin", "password",
            f"--password={PASSWORD}",
            "--new=newpass123",
            cwd=str(cwd),
        )
        assert result.returncode == 0
        assert "Password updated" in result.stdout

        # Old password should fail
        old_env = {"ATCHA_DIR": str(atcha_dir), "ATCHA_ADMIN_PASS": PASSWORD}
        result = run_cli(
            "admin", "users", "create", "--name=test-user", "--role=Test",
            env=old_env, cwd=str(cwd),
        )
        assert result.returncode != 0

        # New password should work
        new_env = {"ATCHA_DIR": str(atcha_dir), "ATCHA_ADMIN_PASS": "newpass123"}
        result = run_cli(
            "admin", "users", "create", "--name=test-user", "--role=Test",
            env=new_env, cwd=str(cwd),
        )
        assert result.returncode == 0

    def test_rejects_wrong_password(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent
        result = run_cli(
            "admin", "password",
            "--password=wrongpass",
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
        result = run_cli("admin", "users", "create", "--name=test-user", "--role=Test", env=env, cwd=str(cwd))
        assert result.returncode == 0

        # Create token using --password
        result = run_cli("admin", "create-token", "--user", "test-user", f"--password={PASSWORD}", cwd=str(cwd))
        assert result.returncode == 0
        token = result.stdout.strip()
        assert len(token) == 5  # 5-char token (not user ID)

    def test_creates_agent_token_via_env(self, atcha_dir: Path) -> None:
        """ATCHA_ADMIN_PASS env var works for create-token."""
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)

        # Create user first
        result = run_cli("admin", "users", "create", "--name=test-user", "--role=Test", env=env, cwd=str(cwd))
        assert result.returncode == 0

        # Create token using env var (no --password)
        result = run_cli("admin", "create-token", "--user", "test-user", env=env, cwd=str(cwd))
        assert result.returncode == 0
        token = result.stdout.strip()
        assert len(token) == 5  # 5-char token (not user ID)

    def test_rejects_nonexistent_user(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent
        result = run_cli("admin", "create-token", "--user", "nobody", f"--password={PASSWORD}", cwd=str(cwd))
        assert result.returncode != 0
        assert "not found" in result.stderr

    def test_token_is_deterministic(self, atcha_dir: Path) -> None:
        """Same password + agent always produces the same token."""
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)

        # Create user
        result = run_cli("admin", "users", "create", "--name=test-user", "--role=Test", env=env, cwd=str(cwd))
        assert result.returncode == 0

        # Create token twice - should get same result
        result1 = run_cli("admin", "create-token", "--user", "test-user", f"--password={PASSWORD}", cwd=str(cwd))
        assert result1.returncode == 0
        token1 = result1.stdout.strip()

        result2 = run_cli("admin", "create-token", "--user", "test-user", f"--password={PASSWORD}", cwd=str(cwd))
        assert result2.returncode == 0
        token2 = result2.stdout.strip()

        assert token1 == token2

    def test_token_stored_as_hash(self, atcha_dir: Path) -> None:
        """Token file contains hash, not plaintext token."""
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)

        # Create user and token
        result = run_cli("admin", "users", "create", "--name=test-user", "--role=Test", env=env, cwd=str(cwd))
        assert result.returncode == 0

        result = run_cli("admin", "create-token", "--user", "test-user", f"--password={PASSWORD}", cwd=str(cwd))
        assert result.returncode == 0
        token = result.stdout.strip()

        # Read token file - should be a hash, not the token itself
        token_file = atcha_dir / "tokens" / _make_user_id("test-user", "Test")
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
            "admin", "users", "create", "--name=maya", "--role=Backend Engineer",
            "--status=Working on auth",
            "--tags=backend,auth",
            env=env, cwd=str(cwd),
        )
        assert result.returncode == 0

        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert profile["id"] == "maya-backend-engineer"
        assert profile["name"] == "maya"
        assert profile["role"] == "Backend Engineer"
        assert profile["status"] == "Working on auth"
        assert profile["tags"] == ["backend", "auth"]

        # Check directory structure (uses id as directory name)
        user_dir = atcha_dir / "users" / "maya-backend-engineer"
        assert user_dir.is_dir()
        assert (user_dir / "profile.json").exists()
        assert (user_dir / "messages" / "inbox.jsonl").exists()

    def test_requires_admin_token(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent
        # No token
        result = run_cli("admin", "users", "create", "--name=test-user", "--role=Test", cwd=str(cwd))
        assert result.returncode != 0
        assert "ATCHA_TOKEN" in result.stderr

    def test_rejects_user_token(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent
        admin_env = _admin_env(atcha_dir)

        # Create user and get their token
        _ = run_cli("admin", "users", "create", "--name=testuser", "--role=Test", env=admin_env, cwd=str(cwd))
        result = run_cli("admin", "create-token", "--user", "testuser", env=admin_env, cwd=str(cwd))
        user_token = result.stdout.strip()

        # Try to create with user token (no admin password in env)
        user_env = {"ATCHA_TOKEN": user_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("admin", "users", "create", "--name=another", "--role=Test", env=user_env, cwd=str(cwd))
        assert result.returncode != 0
        assert ("Admin" in result.stderr or "token required" in result.stderr)  # Error about auth

    def test_validates_username(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)

        # Too short
        result = run_cli("admin", "users", "create", "--name=ab", "--role=Test", env=env, cwd=str(cwd))
        assert result.returncode != 0
        assert "at least 3" in result.stderr

        # Invalid chars
        result = run_cli("admin", "users", "create", "--name=User-Name", "--role=Test", env=env, cwd=str(cwd))
        assert result.returncode != 0
        assert "lowercase" in result.stderr

    def test_fails_if_id_exists(self, atcha_dir: Path) -> None:
        """Cannot create a user with the same id."""
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)

        _ = run_cli("admin", "users", "create", "--name=testuser", "--role=Test", env=env, cwd=str(cwd))
        result = run_cli("admin", "users", "create", "--name=testuser", "--role=Test", env=env, cwd=str(cwd))
        assert result.returncode != 0
        # Could fail because name already taken or id already exists
        assert "already" in result.stderr

    def test_fails_if_name_taken(self, atcha_dir: Path) -> None:
        """Cannot create users with the same name."""
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)

        _ = run_cli("admin", "users", "create", "--name=alice", "--role=Backend", env=env, cwd=str(cwd))
        # Different role but same name 'alice'
        result = run_cli("admin", "users", "create", "--name=alice", "--role=Frontend", env=env, cwd=str(cwd))
        assert result.returncode != 0
        assert "already exists" in result.stderr

    def test_password_option(self, atcha_dir: Path) -> None:
        """admin create: ATCHA_ADMIN_PASS env var works."""
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)  # Uses ATCHA_ADMIN_PASS

        # No token, password from env
        result = run_cli(
            "admin", "users", "create", "--name=pwtest", "--role=Password User",
            env=env, cwd=str(cwd),
        )
        assert result.returncode == 0
        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert profile["id"] == _make_user_id("pwtest", "Password User")
        assert profile["name"] == "pwtest"

    def test_bare_admin_users_lists_all(self, atcha_dir: Path) -> None:
        """admin users (bare) lists all users as JSON."""
        cwd = atcha_dir.parent
        admin_env = _admin_env(atcha_dir)

        # Create a user first
        _ = run_cli("admin", "users", "create", "--name=list-test", "--role=Test", env=admin_env, cwd=str(cwd))

        result = run_cli("admin", "users", env=admin_env, cwd=str(cwd))
        assert result.returncode == 0
        users = json.loads(result.stdout)
        assert isinstance(users, list)
        assert len(users) >= 1
        names = [u["name"] for u in users]
        assert "list-test" in names

    def test_password_cli_flag(self, atcha_dir: Path) -> None:
        """admin users add: --password CLI flag works (no env var needed)."""
        cwd = atcha_dir.parent
        env = {"ATCHA_DIR": str(atcha_dir)}  # Only ATCHA_DIR, no password env

        # Use --password flag after the subcommand (user-friendly position)
        result = run_cli(
            "admin", "users", "create",
            "--name=clitest", "--role=CLI Test User", f"--password={PASSWORD}",
            env=env, cwd=str(cwd),
        )
        assert result.returncode == 0, f"Expected success, got: {result.stderr}"
        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert profile["name"] == "clitest"
        assert profile["role"] == "CLI Test User"


# ---------- agents ----------


class TestAgents:
    def test_requires_auth(self, atcha_dir: Path) -> None:
        """contacts list requires authentication (no anonymous access)."""
        cwd = atcha_dir.parent
        admin_env = _admin_env(atcha_dir)
        _ = run_cli("admin", "users", "create", "--name=visible", "--role=Test", env=admin_env, cwd=str(cwd))

        # No token, just ATCHA_DIR — should fail
        env = {"ATCHA_DIR": str(atcha_dir)}
        result = run_cli("contacts", env=env, cwd=str(cwd))
        assert result.returncode != 0

    def test_lists_agents(self, atcha_dir: Path) -> None:
        """agents list: returns JSON array of profiles (without dates by default)."""
        cwd = atcha_dir.parent
        admin_env = _admin_env(atcha_dir)

        # Create some users (using unique short names)
        alice_token = _create_user(atcha_dir, "alice", "Title A")
        _ = _create_user(atcha_dir, "bob", "Title B")

        # Use alice's token to list contacts (with --include-self to see both)
        user_env = {"ATCHA_TOKEN": alice_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("contacts", "--include-self", env=user_env, cwd=str(cwd))
        assert result.returncode == 0
        profiles = json.loads(result.stdout)
        assert len(profiles) == 2
        assert profiles[0]["id"] == _make_user_id("alice", "Title A")
        assert profiles[0]["name"] == "alice"
        assert profiles[0]["role"] == "Title A"
        assert "joined" not in profiles[0]  # No dates by default
        assert profiles[1]["name"] == "bob"

    def test_exclude_self_by_default(self, atcha_dir: Path) -> None:
        """contacts excludes current user by default."""
        cwd = atcha_dir.parent
        alice_token = _create_user(atcha_dir, "alice-dev", "A")
        _ = _create_user(atcha_dir, "bob-dev", "B")

        env = {"ATCHA_TOKEN": alice_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("contacts", env=env, cwd=str(cwd))
        assert result.returncode == 0
        profiles = json.loads(result.stdout)
        names = [p["name"] for p in profiles]
        assert "alice-dev" not in names
        assert "bob-dev" in names

    def test_include_self(self, atcha_dir: Path) -> None:
        """contacts --include-self includes current user."""
        cwd = atcha_dir.parent
        alice_token = _create_user(atcha_dir, "alice-dev", "A")
        _ = _create_user(atcha_dir, "bob-dev", "B")

        env = {"ATCHA_TOKEN": alice_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("contacts", "--include-self", env=env, cwd=str(cwd))
        assert result.returncode == 0
        profiles = json.loads(result.stdout)
        names = [p["name"] for p in profiles]
        assert "alice-dev" in names
        assert "bob-dev" in names

    def test_admin_as_user_sees_all(self, atcha_dir: Path) -> None:
        """Admin with --as-user sees all agents (with --include-self)."""
        cwd = atcha_dir.parent
        _, alice_id = _create_user_full(atcha_dir, "alice-dev", "A")
        _ = _create_user(atcha_dir, "bob-dev", "B")

        env = _admin_env(atcha_dir)
        result = run_cli("contacts", "--include-self", f"--as-user={alice_id}", env=env, cwd=str(cwd))
        assert result.returncode == 0
        profiles = json.loads(result.stdout)
        names = [p["name"] for p in profiles]
        assert "alice-dev" in names
        assert "bob-dev" in names

    def test_filter_by_tags(self, atcha_dir: Path) -> None:
        """contacts --tags filters agents by tag."""
        cwd = atcha_dir.parent
        admin_env = _admin_env(atcha_dir)
        # Create users with tags
        _ = run_cli("admin", "users", "create", "--name=backend-dev", "--role=Backend", "--tags=backend,api", env=admin_env, cwd=str(cwd))
        _ = run_cli("admin", "users", "create", "--name=frontend-dev", "--role=Frontend", "--tags=frontend,ui", env=admin_env, cwd=str(cwd))
        # Get a user token to authenticate with contacts
        backend_token = run_cli("admin", "create-token", "--user", "backend-dev", env=admin_env, cwd=str(cwd)).stdout.strip()

        user_env = {"ATCHA_TOKEN": backend_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("contacts", "--include-self", "--tags=backend", env=user_env, cwd=str(cwd))
        assert result.returncode == 0
        profiles = json.loads(result.stdout)
        names = [p["name"] for p in profiles]
        assert "backend-dev" in names
        assert "frontend-dev" not in names

    def test_get_user(self, atcha_dir: Path) -> None:
        """agents get <id or name> returns profile JSON (without dates by default)."""
        cwd = atcha_dir.parent
        admin_env = _admin_env(atcha_dir)
        _ = run_cli("admin", "users", "create", "--name=test-user", "--role=Test Title", env=admin_env, cwd=str(cwd))

        # Can get by name
        result = run_cli("contacts", "show", "test-user", env=admin_env, cwd=str(cwd))
        assert result.returncode == 0
        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert profile["id"] == _make_user_id("test-user", "Test Title")
        assert profile["name"] == "test-user"
        assert profile["role"] == "Test Title"
        assert "joined" not in profile  # No dates by default

    def test_full_flag(self, atcha_dir: Path) -> None:
        """--full includes joined/updated dates."""
        cwd = atcha_dir.parent
        admin_env = _admin_env(atcha_dir)
        token = _create_user(atcha_dir, "test-user", "Test")
        user_env = {"ATCHA_TOKEN": token, "ATCHA_DIR": str(atcha_dir)}

        # contacts show --full
        result = run_cli("contacts", "show", "test-user", "--full", env=admin_env, cwd=str(cwd))
        assert result.returncode == 0
        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert "joined" in profile
        assert "updated" in profile

        # contacts list --full (needs user auth)
        result = run_cli("contacts", "--include-self", "--full", env=user_env, cwd=str(cwd))
        profiles = json.loads(result.stdout)
        assert "joined" in profiles[0]

    def test_empty_when_no_other_agents(self, atcha_dir: Path) -> None:
        """contacts returns empty list when user is the only one (self excluded by default)."""
        cwd = atcha_dir.parent
        token = _create_user(atcha_dir, "lone-user", "Solo")
        user_env = {"ATCHA_TOKEN": token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("contacts", env=user_env, cwd=str(cwd))
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

        result = run_cli("contacts", "show", username, env=env, cwd=str(cwd))
        assert result.returncode == 0
        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert profile["id"] == _make_user_id("test-user", "Test User")
        assert profile["name"] == "test-user"
        assert profile["role"] == "Test User"

    def test_view_other_profile(self, atcha_dir: Path) -> None:
        """View another user's profile requires auth."""
        cwd = atcha_dir.parent
        admin_env = _admin_env(atcha_dir)
        _ = run_cli("admin", "users", "create", "--name=other-user", "--role=Other", env=admin_env, cwd=str(cwd))
        viewer_token = _create_user(atcha_dir, "viewer", "Viewer")

        # View with auth
        env = {"ATCHA_TOKEN": viewer_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("contacts", "show", "other-user", env=env, cwd=str(cwd))
        assert result.returncode == 0
        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert profile["id"] == _make_user_id("other-user", "Other")
        assert profile["name"] == "other-user"

        # View without auth works (contacts show is read-only)
        env_no_token = {"ATCHA_DIR": str(atcha_dir)}
        result = run_cli("contacts", "show", "other-user", env=env_no_token, cwd=str(cwd))
        assert result.returncode == 0
        profile_no_auth: dict[str, T.Any] = json.loads(result.stdout)
        assert profile_no_auth["name"] == "other-user"

    def test_whoami_returns_address(self, atcha_dir: Path) -> None:
        """whoami returns address format (name@) by default."""
        cwd = atcha_dir.parent
        user_token = _create_user(atcha_dir, "maya-backend", "Backend Engineer")
        env = {"ATCHA_TOKEN": user_token, "ATCHA_DIR": str(atcha_dir)}

        result = run_cli("whoami", env=env, cwd=str(cwd))
        assert result.returncode == 0
        assert result.stdout.strip() == "maya-backend@"

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

    def test_profile_update_rejects_role(self, atcha_dir: Path) -> None:
        """profile update no longer accepts --role (admin-only via admin users update)."""
        cwd = atcha_dir.parent
        user_token = _create_user(atcha_dir, "test-user", "Junior Dev")
        env = {"ATCHA_TOKEN": user_token, "ATCHA_DIR": str(atcha_dir)}

        # --role is not a valid flag for profile update
        result = run_cli("profile", "update", "--role=Senior Dev", env=env, cwd=str(cwd))
        assert result.returncode != 0

    def test_admin_rejects_role_update(self, atcha_dir: Path) -> None:
        """admin users update no longer accepts --role (name and role are immutable)."""
        cwd = atcha_dir.parent
        _ = _create_user(atcha_dir, "test-user", "Junior Dev")
        admin_env = _admin_env(atcha_dir)

        result = run_cli("admin", "users", "update", "test-user@", "--role=Senior Dev", env=admin_env, cwd=str(cwd))
        assert result.returncode != 0  # --role is no longer a valid flag

    def test_get_after_update(self, atcha_dir: Path) -> None:
        """Verify agents get reflects updates."""
        cwd = atcha_dir.parent
        user_token = _create_user(atcha_dir, "test-user")
        env = {"ATCHA_TOKEN": user_token, "ATCHA_DIR": str(atcha_dir)}

        # Update then get
        _ = run_cli("profile", "update", "--status=Updated", env=env, cwd=str(cwd))
        result = run_cli("contacts", "show", "test-user", env=env, cwd=str(cwd))
        assert result.returncode == 0
        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert profile["id"] == _make_user_id("test-user", "Test Agent")
        assert profile["status"] == "Updated"

    def test_admin_updates_other_agent(self, atcha_dir: Path) -> None:
        """Admin can update another agent's mutable profile fields via admin users update."""
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)
        _ = _create_user(atcha_dir, "target-agent", "Original Role")

        # Update mutable fields via admin users update (requires address format)
        result = run_cli(
            "admin", "users", "update", "target-agent@",
            "--status=Busy",
            "--about=Working hard",
            env=env, cwd=str(cwd),
        )
        assert result.returncode == 0
        profile: dict[str, T.Any] = json.loads(result.stdout)
        assert profile["role"] == "Original Role"  # Immutable — unchanged
        assert profile["status"] == "Busy"
        assert profile["about"] == "Working hard"


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

    def test_admin_as_user(self, atcha_dir: Path) -> None:
        """messages check: admin can use --as-user with user ID to check another user's inbox."""
        cwd = atcha_dir.parent
        env = {"ATCHA_DIR": str(atcha_dir)}

        # Create users
        sender_token = _create_user(atcha_dir, "sender")
        _, recipient_id = _create_user_full(atcha_dir, "recipient")

        # Send a message as sender
        sender_env = {"ATCHA_TOKEN": sender_token, "ATCHA_DIR": str(atcha_dir)}
        _ = run_cli("send", "--to", "recipient", "Hello from sender!", env=sender_env, cwd=str(cwd))

        # Admin checks recipient's inbox using --password and --as-user (requires user ID)
        result = run_cli(
            "messages", f"--password={PASSWORD}", f"--as-user={recipient_id}", "check",
            env=env, cwd=str(cwd),
        )
        assert result.returncode == 0
        assert "1 unread message from sender" in result.stdout


# ---------- messages read ----------


class TestMessagesRead:
    def test_requires_ids(self, atcha_dir: Path) -> None:
        """messages read without IDs returns an error."""
        cwd = atcha_dir.parent
        user_token = _create_user(atcha_dir, "test-user")
        env = {"ATCHA_TOKEN": user_token, "ATCHA_DIR": str(atcha_dir)}

        result = run_cli("messages", "read", env=env, cwd=str(cwd))
        assert result.returncode != 0

    def test_reads_and_marks(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent

        # Create sender and recipient
        sender_token = _create_user(atcha_dir, "sender")
        recipient_token = _create_user(atcha_dir, "recipient")

        # Send a message
        sender_env = {"ATCHA_TOKEN": sender_token, "ATCHA_DIR": str(atcha_dir)}
        _ = run_cli("send", "--to", "recipient", "Hello!", env=sender_env, cwd=str(cwd))

        # Get message ID from inbox
        inbox = _user_dir(atcha_dir, "recipient", "Test Agent") / "messages" / "inbox.jsonl"
        msg_id: str = json.loads(inbox.read_text().strip())["id"]

        # Read by ID
        recipient_env = {"ATCHA_TOKEN": recipient_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("messages", "read", msg_id, env=recipient_env, cwd=str(cwd))
        assert result.returncode == 0
        msg: dict[str, str] = json.loads(result.stdout.strip())
        assert msg["from"] == "sender"
        assert msg["content"] == "Hello!"

        # Should be marked as read now
        result = run_cli("messages", "check", env=recipient_env, cwd=str(cwd))
        assert "No messages" in result.stdout

    def test_excludes_to_field_by_default(self, atcha_dir: Path) -> None:
        """messages read excludes 'to' field for regular agents (it's redundant)."""
        cwd = atcha_dir.parent
        sender_token = _create_user(atcha_dir, "sender")
        recipient_token = _create_user(atcha_dir, "recipient")

        # Send a message
        sender_env = {"ATCHA_TOKEN": sender_token, "ATCHA_DIR": str(atcha_dir)}
        _ = run_cli("send", "--to", "recipient", "Hello!", env=sender_env, cwd=str(cwd))

        # Get message ID
        inbox = _user_dir(atcha_dir, "recipient", "Test Agent") / "messages" / "inbox.jsonl"
        msg_id: str = json.loads(inbox.read_text().strip())["id"]

        # Read by ID - 'to' should NOT be in output
        recipient_env = {"ATCHA_TOKEN": recipient_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("messages", "read", msg_id, env=recipient_env, cwd=str(cwd))
        assert result.returncode == 0
        msg: dict[str, str] = json.loads(result.stdout.strip())
        assert "to" not in msg
        assert msg["from"] == "sender"

    def test_includes_to_field_for_admin(self, atcha_dir: Path) -> None:
        """messages read includes 'to' field when admin uses --as-user."""
        cwd = atcha_dir.parent
        sender_token = _create_user(atcha_dir, "sender")
        _, recipient_id = _create_user_full(atcha_dir, "recipient")

        # Send a message
        sender_env = {"ATCHA_TOKEN": sender_token, "ATCHA_DIR": str(atcha_dir)}
        _ = run_cli("send", "--to", "recipient", "Hello!", env=sender_env, cwd=str(cwd))

        # Get message ID
        inbox = _user_dir(atcha_dir, "recipient", "Test Agent") / "messages" / "inbox.jsonl"
        msg_id: str = json.loads(inbox.read_text().strip())["id"]

        # Read as admin acting as recipient (--as-user requires user ID)
        admin_env = _admin_env(atcha_dir)
        result = run_cli("messages", f"--as-user={recipient_id}", "read", msg_id, env=admin_env, cwd=str(cwd))
        assert result.returncode == 0
        msg: dict[str, T.Any] = json.loads(result.stdout.strip())
        assert msg["to"] == ["recipient"]

    def test_no_mark_flag(self, atcha_dir: Path) -> None:
        """--no-mark prevents marking messages as read."""
        cwd = atcha_dir.parent
        sender_token = _create_user(atcha_dir, "sender")
        recipient_token = _create_user(atcha_dir, "recipient")

        # Send a message
        sender_env = {"ATCHA_TOKEN": sender_token, "ATCHA_DIR": str(atcha_dir)}
        _ = run_cli("send", "--to", "recipient", "Hello!", env=sender_env, cwd=str(cwd))

        # Get message ID
        inbox = _user_dir(atcha_dir, "recipient", "Test Agent") / "messages" / "inbox.jsonl"
        msg_id: str = json.loads(inbox.read_text().strip())["id"]

        # Read with --no-mark
        recipient_env = {"ATCHA_TOKEN": recipient_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("messages", "read", "--no-mark", msg_id, env=recipient_env, cwd=str(cwd))
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
        inbox = _user_dir(atcha_dir, "recipient", "Test Agent") / "messages" / "inbox.jsonl"
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
        result = run_cli("messages", env=recipient_env, cwd=str(cwd))
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
        result = run_cli("messages", env=recipient_env, cwd=str(cwd))
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
        result = run_cli("messages", "--no-preview", env=recipient_env, cwd=str(cwd))
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
        result = run_cli("messages", env=recipient_env, cwd=str(cwd))
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
        result = run_cli("messages", "--limit=2", env=recipient_env, cwd=str(cwd))
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
        result = run_cli("messages", "--from=alice", env=recipient_env, cwd=str(cwd))
        assert result.returncode == 0

        messages: list[dict[str, T.Any]] = json.loads(result.stdout)
        assert len(messages) == 1
        assert messages[0]["from"] == "alice"


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
        inbox = _user_dir(atcha_dir, "recipient", "Test Agent") / "messages" / "inbox.jsonl"
        msg: dict[str, T.Any] = json.loads(inbox.read_text().strip())
        assert msg["from"]["name"] == "sender"
        assert msg["content"] == "Test message"

        # Verify message in sender sent
        sent = _user_dir(atcha_dir, "sender", "Test Agent") / "messages" / "sent.jsonl"
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

        inbox = _user_dir(atcha_dir, "recipient", "Test Agent") / "messages" / "inbox.jsonl"
        msg: dict[str, T.Any] = json.loads(inbox.read_text().strip())
        assert msg["content"] == body

    def test_admin_send_as_user(self, atcha_dir: Path) -> None:
        """send: admin can use --as-user with user ID to send as another user."""
        cwd = atcha_dir.parent
        env = {"ATCHA_DIR": str(atcha_dir)}

        # Create users (need alice's user ID for --as-user)
        _, alice_id = _create_user_full(atcha_dir, "alice")
        _ = _create_user(atcha_dir, "bob")

        # Admin sends from alice to bob (--as-user requires user ID)
        result = run_cli(
            "send", f"--as-user={alice_id}", f"--password={PASSWORD}",
            "--to", "bob", "Hello from alice (sent by admin)",
            env=env, cwd=str(cwd),
        )
        assert result.returncode == 0

        # Verify message in bob's inbox shows alice as sender
        inbox = _user_dir(atcha_dir, "bob", "Test Agent") / "messages" / "inbox.jsonl"
        msg: dict[str, T.Any] = json.loads(inbox.read_text().strip())
        assert msg["from"]["name"] == "alice"
        assert msg["content"] == "Hello from alice (sent by admin)"

        # Verify message in alice's sent log
        sent = _user_dir(atcha_dir, "alice", "Test Agent") / "messages" / "sent.jsonl"
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
        alice_inbox = _user_dir(atcha_dir, "alice", "Test Agent") / "messages" / "inbox.jsonl"
        alice_msg: dict[str, T.Any] = json.loads(alice_inbox.read_text().strip())
        assert alice_msg["content"] == "Team update"
        assert set(alice_msg["to"]) == {"alice", "bob"}

        bob_inbox = _user_dir(atcha_dir, "bob", "Test Agent") / "messages" / "inbox.jsonl"
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
        result = run_cli("send", "--broadcast", "Broadcast message", env=sender_env, cwd=str(cwd))
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
        bob_inbox = _user_dir(atcha_dir, "bob", "Test Agent") / "messages" / "inbox.jsonl"
        original_msg: dict[str, T.Any] = json.loads(bob_inbox.read_text().strip())
        msg_id = original_msg["id"]
        thread_id = original_msg["thread_id"]

        # Bob replies
        bob_env = {"ATCHA_TOKEN": bob_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("send", "--reply-to", msg_id, "Thanks for the update", env=bob_env, cwd=str(cwd))
        assert result.returncode == 0

        # Verify reply has correct threading
        alice_inbox = _user_dir(atcha_dir, "alice", "Test Agent") / "messages" / "inbox.jsonl"
        reply_msg: dict[str, T.Any] = json.loads(alice_inbox.read_text().strip())
        assert reply_msg["thread_id"] == thread_id
        assert reply_msg["reply_to"] == msg_id
        assert reply_msg["content"] == "Thanks for the update"

    def test_error_to_with_reply_to(self, atcha_dir: Path) -> None:
        """send: --to with --reply-to is an error (mutually exclusive)."""
        cwd = atcha_dir.parent
        alice_token = _create_user(atcha_dir, "alice")
        _ = _create_user(atcha_dir, "bob")
        charlie_token = _create_user(atcha_dir, "charlie")

        # Alice sends to Bob and Charlie
        alice_env = {"ATCHA_TOKEN": alice_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("send", "--to", "bob", "--to", "charlie", "Team question", env=alice_env, cwd=str(cwd))
        assert result.returncode == 0

        # Get message ID
        bob_inbox = _user_dir(atcha_dir, "bob", "Test Agent") / "messages" / "inbox.jsonl"
        original_msg: dict[str, T.Any] = json.loads(bob_inbox.read_text().strip())
        msg_id = original_msg["id"]

        # Charlie tries --to + --reply-to (should error)
        charlie_env = {"ATCHA_TOKEN": charlie_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("send", "--to", "alice", "--reply-to", msg_id, "My answer", env=charlie_env, cwd=str(cwd))
        assert result.returncode != 0
        assert "cannot use --to with --reply-to" in result.stderr.lower()

    def test_error_all_with_reply_to(self, atcha_dir: Path) -> None:
        """send: --all with --reply-to is an error."""
        cwd = atcha_dir.parent
        sender_token = _create_user(atcha_dir, "sender")
        _ = _create_user(atcha_dir, "recipient")

        # Send a message first
        sender_env = {"ATCHA_TOKEN": sender_token, "ATCHA_DIR": str(atcha_dir)}
        _ = run_cli("send", "--to", "recipient", "Test", env=sender_env, cwd=str(cwd))

        # Get message ID
        recipient_inbox = _user_dir(atcha_dir, "recipient", "Test Agent") / "messages" / "inbox.jsonl"
        msg: dict[str, T.Any] = json.loads(recipient_inbox.read_text().strip())
        msg_id = msg["id"]

        # Try --all with --reply-to (should error)
        result = run_cli("send", "--broadcast", "--reply-to", msg_id, "Test", env=sender_env, cwd=str(cwd))
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

    def test_reply_to_all_thread_participants(self, atcha_dir: Path) -> None:
        """send: --reply-to alone replies to all thread participants except self."""
        cwd = atcha_dir.parent
        alice_token = _create_user(atcha_dir, "alice")
        _ = _create_user(atcha_dir, "bob")
        charlie_token = _create_user(atcha_dir, "charlie")

        # Alice sends to Bob and Charlie
        alice_env = {"ATCHA_TOKEN": alice_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("send", "--to", "bob", "--to", "charlie", "Team question", env=alice_env, cwd=str(cwd))
        assert result.returncode == 0

        # Get message ID from Charlie's inbox
        charlie_inbox = _user_dir(atcha_dir, "charlie", "Test Agent") / "messages" / "inbox.jsonl"
        original_msg: dict[str, T.Any] = json.loads(charlie_inbox.read_text().strip())
        msg_id = original_msg["id"]

        # Charlie replies to thread (should go to alice and bob, not charlie)
        charlie_env = {"ATCHA_TOKEN": charlie_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("send", "--reply-to", msg_id, "My answer", env=charlie_env, cwd=str(cwd))
        assert result.returncode == 0

        # Parse response to check recipients
        response: dict[str, T.Any] = json.loads(result.stdout.strip())
        recipients = sorted(response["to"])
        assert recipients == ["alice", "bob"]


# ---------- env ----------


class TestEnv:
    def test_outputs_exports(self, atcha_dir: Path) -> None:
        cwd = atcha_dir.parent
        result = run_cli("admin", "envs", cwd=str(cwd))
        assert result.returncode == 0
        assert "ATCHA_DIR" in result.stdout
        assert str(atcha_dir) in result.stdout

    def test_silent_when_no_dir(self, tmp_path: Path) -> None:
        result = run_cli("admin", "envs", cwd=str(tmp_path))
        assert result.returncode == 0
        assert result.stdout == ""


# ---------- username validation ----------


class TestUsernameValidation:
    def test_valid_names(self) -> None:
        from atcha.cli.validation import _validate_username

        valid_names = [
            "maya-backend-engineer",
            "alex-api-dev",
            "frontend-designer-2",
            "kai",
            "a-b-c",
        ]
        for name in valid_names:
            is_valid, _ = _validate_username(name)
            assert is_valid, f"{name} should be valid"

    def test_invalid_names(self) -> None:
        from atcha.cli.validation import _validate_username

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
            is_valid, _ = _validate_username(name)
            assert not is_valid, f"{name} should be invalid ({reason})"


# ---------- token validation ----------


class TestTokenValidation:
    def test_token_identifies_user(self, atcha_dir: Path) -> None:
        from atcha.cli.auth import _validate_token

        # Create user and get token
        user_token = _create_user(atcha_dir, "test-user")

        # Validate token
        result = _validate_token(atcha_dir, user_token)
        assert result is not None
        name, is_admin = result
        assert name == _make_user_id("test-user", "Test Agent")  # Returns user_id (dir name)
        assert not is_admin

    def test_invalid_token(self, atcha_dir: Path) -> None:
        from atcha.cli.auth import _validate_token

        result = _validate_token(atcha_dir, "xxxxx")
        assert result is None

    def test_token_cli_option(self, atcha_dir: Path) -> None:
        """Test that --token works as alternative to ATCHA_TOKEN env var."""
        cwd = atcha_dir.parent
        user_token = _create_user(atcha_dir, "cli-test-user")

        # Use --token instead of env var (--token is on the subcommand)
        env = {"ATCHA_DIR": str(atcha_dir)}  # No ATCHA_TOKEN
        result = run_cli("whoami", f"--token={user_token}", env=env, cwd=str(cwd))
        assert result.returncode == 0
        assert result.stdout.strip() == "cli-test-user@"


# ---------- Integration test ----------


class TestIntegration:
    def test_full_workflow(self, tmp_path: Path) -> None:
        """Full workflow: init → create agents → create-token → send mail → read mail."""
        # 1. Initialize
        result = run_cli("admin", "init", f"--password={PASSWORD}", cwd=str(tmp_path))
        assert result.returncode == 0

        atcha_dir = tmp_path / ".atcha"

        # 2. Use admin password env var (no admin tokens)
        admin_env = _admin_env(atcha_dir)

        # 3. Create users
        result = run_cli(
            "admin", "users", "create", "--name=maya-backend", "--role=Backend Engineer",
            "--tags=backend,auth",
            env=admin_env, cwd=str(tmp_path),
        )
        assert result.returncode == 0

        result = run_cli(
            "admin", "users", "create", "--name=alex-frontend", "--role=Frontend Dev",
            "--tags=frontend,ui",
            env=admin_env, cwd=str(tmp_path),
        )
        assert result.returncode == 0

        # 4. Get user tokens
        result = run_cli("admin", "create-token", "--user", "maya-backend", f"--password={PASSWORD}", cwd=str(tmp_path))
        maya_token = result.stdout.strip()

        result = run_cli("admin", "create-token", "--user", "alex-frontend", f"--password={PASSWORD}", cwd=str(tmp_path))
        alex_token = result.stdout.strip()

        # 5. Maya sends message to Alex
        maya_env = {"ATCHA_TOKEN": maya_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("send", "--to", "alex-frontend", "API is ready for integration", env=maya_env, cwd=str(tmp_path))
        assert result.returncode == 0

        # 6. Alex checks inbox
        alex_env = {"ATCHA_TOKEN": alex_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("messages", "check", env=alex_env, cwd=str(tmp_path))
        assert "1 unread message from maya-backend" in result.stdout

        # 7. Alex reads messages (get IDs from inbox first)
        alex_inbox = _user_dir(atcha_dir, "alex-frontend", "Frontend Dev") / "messages" / "inbox.jsonl"
        alex_msg_id: str = json.loads(alex_inbox.read_text().strip())["id"]
        result = run_cli("messages", "read", alex_msg_id, env=alex_env, cwd=str(tmp_path))
        assert result.returncode == 0
        msg: dict[str, T.Any] = json.loads(result.stdout.strip())
        assert msg["from"] == "maya-backend"  # CLI output has from as formatted string
        assert msg["content"] == "API is ready for integration"

        # 8. Inbox should be empty now
        result = run_cli("messages", "check", env=alex_env, cwd=str(tmp_path))
        assert "No messages" in result.stdout

        # 9. Alex replies
        result = run_cli("send", "--to", "maya-backend", "Thanks! Starting integration now.", env=alex_env, cwd=str(tmp_path))
        assert result.returncode == 0

        # 10. Maya reads reply (get ID from inbox)
        maya_inbox = _user_dir(atcha_dir, "maya-backend", "Backend Engineer") / "messages" / "inbox.jsonl"
        maya_msg_id: str = json.loads(maya_inbox.read_text().strip())["id"]
        result = run_cli("messages", "read", maya_msg_id, env=maya_env, cwd=str(tmp_path))
        msg = json.loads(result.stdout.strip())
        assert msg["from"] == "alex-frontend"
        assert "integration" in msg["content"]


# ---------- Federation ----------


def _create_federated_space(base_path: Path, space_name: str) -> Path:
    """Create and initialize a second .atcha directory for federation testing.

    Creates a new directory under base_path and initializes atcha there.
    Uses explicit ATCHA_DIR to prevent auto-discovery from walking up to parent .atcha.
    """
    space_dir = base_path / space_name
    space_dir.mkdir(parents=True, exist_ok=True)
    new_atcha_dir = space_dir / ".atcha"
    # Run init with ATCHA_DIR unset (empty string) to force fresh initialization
    # We need to remove ATCHA_DIR from env to prevent it from finding parent .atcha
    env = {k: v for k, v in os.environ.items() if k != "ATCHA_DIR"}
    result = run_cli("admin", "init", f"--password={PASSWORD}", env=env, cwd=str(space_dir))
    assert result.returncode == 0, f"Failed to init {space_name}: {result.stderr}"
    return new_atcha_dir


@pytest.fixture
def federation_base(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Create an isolated base directory for federation tests.

    Uses tmp_path_factory to create a completely separate directory tree,
    preventing atcha init from walking up and finding the test's main .atcha dir.
    """
    return tmp_path_factory.mktemp("federation")


class TestFederationSpaceIdentity:
    """Tests for FR-001: Space Identity."""

    def test_init_creates_space_json(self, tmp_path: Path) -> None:
        """atcha init creates space.json with id and name."""
        result = run_cli("admin", "init", f"--password={PASSWORD}", cwd=str(tmp_path))
        assert result.returncode == 0

        space_file = tmp_path / ".atcha" / "space.json"
        assert space_file.exists()

        space_config = json.loads(space_file.read_text())
        assert "id" in space_config
        assert space_config["id"].startswith("spc-")
        assert len(space_config["id"]) == 9  # spc- + 5 chars
        assert "name" in space_config
        assert "created" in space_config

    def test_space_id_format(self, tmp_path: Path) -> None:
        """Space ID has format spc-{5-char} with valid alphabet."""
        _ = run_cli("admin", "init", f"--password={PASSWORD}", cwd=str(tmp_path))
        space_config = json.loads((tmp_path / ".atcha" / "space.json").read_text())

        space_id = space_config["id"]
        assert space_id.startswith("spc-")
        # 5 chars from alphabet: 23456789abcdefghjkmnpqrstuvwxyz
        suffix = space_id[4:]
        assert len(suffix) == 5
        valid_chars = set("23456789abcdefghjkmnpqrstuvwxyz")
        assert all(c in valid_chars for c in suffix)

    def test_name_derived_from_directory(self, tmp_path: Path) -> None:
        """Space name is derived from parent directory name."""
        project_dir = tmp_path / "My_Cool_Project"
        project_dir.mkdir()
        _ = run_cli("admin", "init", f"--password={PASSWORD}", cwd=str(project_dir))

        space_config = json.loads((project_dir / ".atcha" / "space.json").read_text())
        # Slugified: lowercase, underscores to dashes
        assert space_config["name"] == "my-cool-project"

    def test_admin_space_rename(self, atcha_dir: Path) -> None:
        """admin space rename changes name but preserves id."""
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)

        # Get original config
        original = json.loads((atcha_dir / "space.json").read_text())

        # Rename space
        result = run_cli("admin", "spaces", "update", "--name=new-name", env=env, cwd=str(cwd))
        assert result.returncode == 0
        output = json.loads(result.stdout)
        assert output["status"] == "updated"

        # Verify ID unchanged, name changed
        updated = json.loads((atcha_dir / "space.json").read_text())
        assert updated["id"] == original["id"]
        assert updated["name"] == "new-name"


class TestFederationRegistry:
    """Tests for FR-002: Federation Registration."""

    def test_admin_federated_add(self, atcha_dir: Path, federation_base: Path) -> None:
        """admin federated add registers a remote space."""
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)

        # Create a second space
        remote_atcha = _create_federated_space(federation_base, "remote-project")

        # Register it
        result = run_cli("admin", "spaces", "add", str(remote_atcha), env=env, cwd=str(cwd))
        assert result.returncode == 0
        output = json.loads(result.stdout)
        assert output["status"] == "added"
        assert output["id"].startswith("spc-")

        # Verify federation.local.json
        federation = json.loads((atcha_dir / "federation.local.json").read_text())
        assert len(federation["spaces"]) == 1
        assert federation["spaces"][0]["path"] == str(remote_atcha)

    def test_admin_federated_add_collision(self, atcha_dir: Path, federation_base: Path) -> None:
        """admin federated add detects handle collision."""
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)

        # Create two spaces with same handle
        remote1 = _create_federated_space(federation_base, "project-a")
        remote2 = _create_federated_space(federation_base, "project-b")

        # Set same handle on both
        for remote in [remote1, remote2]:
            space_config = json.loads((remote / "space.json").read_text())
            space_config["name"] = "same-handle"
            (remote / "space.json").write_text(json.dumps(space_config, indent=2) + "\n")

        # Register first
        result = run_cli("admin", "spaces", "add", str(remote1), env=env, cwd=str(cwd))
        assert result.returncode == 0

        # Second should fail without --force
        result = run_cli("admin", "spaces", "add", str(remote2), env=env, cwd=str(cwd))
        assert result.returncode != 0
        assert "handle collision" in result.stderr.lower()

        # With --force, should succeed
        result = run_cli("admin", "spaces", "add", str(remote2), "--force", env=env, cwd=str(cwd))
        assert result.returncode == 0

    def test_admin_federated_remove(self, atcha_dir: Path, federation_base: Path) -> None:
        """admin federated remove unregisters a space."""
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)

        # Create and register a space
        remote_atcha = _create_federated_space(federation_base, "remote-project")
        result = run_cli("admin", "spaces", "add", str(remote_atcha), env=env, cwd=str(cwd))
        assert result.returncode == 0
        added = json.loads(result.stdout)

        # Remove by handle
        result = run_cli("admin", "spaces", "drop", added["name"], env=env, cwd=str(cwd))
        assert result.returncode == 0

        # Verify removed
        federation = json.loads((atcha_dir / "federation.local.json").read_text())
        assert len(federation["spaces"]) == 0

    def test_admin_spaces_list(self, atcha_dir: Path, federation_base: Path) -> None:
        """admin spaces lists local + federated spaces with availability."""
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)

        # Create and register a space
        remote_atcha = _create_federated_space(federation_base, "remote-project")
        _ = run_cli("admin", "spaces", "add", str(remote_atcha), env=env, cwd=str(cwd))

        # List - should include local + 1 remote
        result = run_cli("admin", "spaces", env=env, cwd=str(cwd))
        assert result.returncode == 0
        spaces = json.loads(result.stdout)
        assert len(spaces) == 2  # local + remote
        local_spaces = [s for s in spaces if s["scope"] == "local"]
        remote_spaces = [s for s in spaces if s["scope"] == "federated"]
        assert len(local_spaces) == 1
        assert len(remote_spaces) == 1
        assert remote_spaces[0]["available"] is True

        # Delete the remote space directory
        import shutil
        shutil.rmtree(remote_atcha)

        # List again - remote should show unavailable
        result = run_cli("admin", "spaces", env=env, cwd=str(cwd))
        spaces = json.loads(result.stdout)
        remote_spaces = [s for s in spaces if s["scope"] == "federated"]
        assert remote_spaces[0]["available"] is False


class TestFederationContacts:
    """Tests for FR-003: Cross-Space Contact Discovery."""

    def test_contacts_cross_space(self, atcha_dir: Path, federation_base: Path) -> None:
        """contacts includes users from federated spaces."""
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)

        # Create local user
        local_token = _create_user(atcha_dir, "local-user")

        # Create and register remote space with user
        remote_atcha = _create_federated_space(federation_base, "remote-project")
        remote_env = {"ATCHA_ADMIN_PASS": PASSWORD, "ATCHA_DIR": str(remote_atcha)}
        _ = run_cli("admin", "users", "create", "--name=remote-user", "--role=Remote Dev", env=remote_env, cwd=str(federation_base / "remote-project"))

        # Register remote space
        _ = run_cli("admin", "spaces", "add", str(remote_atcha), env=env, cwd=str(cwd))

        # List contacts as local user
        user_env = {"ATCHA_TOKEN": local_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("contacts", env=user_env, cwd=str(cwd))
        assert result.returncode == 0
        contacts = json.loads(result.stdout)

        # Should include remote user with address and scope fields
        names = [c["name"] for c in contacts]
        assert "remote-user" in names
        remote_contact = next(c for c in contacts if c["name"] == "remote-user")
        assert remote_contact["scope"] == "federated"
        assert remote_contact["address"] == "remote-user@remote-project"

    def test_contacts_space_filter(self, atcha_dir: Path, federation_base: Path) -> None:
        """contacts --space filters by space."""
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)

        # Create local user
        local_token = _create_user(atcha_dir, "local-user")

        # Create remote space with user
        remote_atcha = _create_federated_space(federation_base, "remote-project")
        remote_env = {"ATCHA_ADMIN_PASS": PASSWORD, "ATCHA_DIR": str(remote_atcha)}
        _ = run_cli("admin", "users", "create", "--name=remote-user", "--role=Remote Dev", env=remote_env, cwd=str(federation_base / "remote-project"))

        # Get remote space handle
        remote_config = json.loads((remote_atcha / "space.json").read_text())
        remote_handle = remote_config["name"]

        # Register
        _ = run_cli("admin", "spaces", "add", str(remote_atcha), env=env, cwd=str(cwd))

        # Filter by remote space
        user_env = {"ATCHA_TOKEN": local_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("contacts", f"--space={remote_handle}", env=user_env, cwd=str(cwd))
        assert result.returncode == 0
        contacts = json.loads(result.stdout)

        # Should only include remote user
        assert len(contacts) == 1
        assert contacts[0]["name"] == "remote-user"


class TestFederationMessaging:
    """Tests for FR-004 and FR-005: Cross-Space Messaging."""

    def test_send_cross_space(self, atcha_dir: Path, federation_base: Path) -> None:
        """send to user@space works across federated spaces."""
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)

        # Create local user
        local_token = _create_user(atcha_dir, "local-user")

        # Create remote space with user
        remote_atcha = _create_federated_space(federation_base, "remote-project")
        remote_env = {"ATCHA_ADMIN_PASS": PASSWORD, "ATCHA_DIR": str(remote_atcha)}
        result = run_cli("admin", "users", "create", "--name=remote-user", "--role=Remote Dev", env=remote_env, cwd=str(federation_base / "remote-project"))
        assert result.returncode == 0

        # Get remote user token
        result = run_cli("admin", "create-token", "--user", "remote-user", env=remote_env, cwd=str(federation_base / "remote-project"))
        remote_token = result.stdout.strip()

        # Get remote space handle
        remote_config = json.loads((remote_atcha / "space.json").read_text())
        remote_handle = remote_config["name"]

        # Register remote space
        _ = run_cli("admin", "spaces", "add", str(remote_atcha), env=env, cwd=str(cwd))

        # Send message to remote-user@remote-handle
        user_env = {"ATCHA_TOKEN": local_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("send", "--to", f"remote-user@{remote_handle}", "Hello from local!", env=user_env, cwd=str(cwd))
        assert result.returncode == 0

        # Read message as remote user (get ID from inbox)
        remote_inbox = remote_atcha / "users" / _make_user_id("remote-user", "Remote Dev") / "messages" / "inbox.jsonl"
        remote_msg_id: str = json.loads(remote_inbox.read_text().strip())["id"]
        remote_user_env = {"ATCHA_TOKEN": remote_token, "ATCHA_DIR": str(remote_atcha)}
        result = run_cli("messages", "read", remote_msg_id, env=remote_user_env, cwd=str(federation_base / "remote-project"))
        assert result.returncode == 0
        msg = json.loads(result.stdout.strip())
        assert "Hello from local!" in msg["content"]
        # Sender should show with @space suffix
        assert "@" in msg["from"]

    def test_send_ambiguous_recipient(self, atcha_dir: Path, federation_base: Path) -> None:
        """send errors on ambiguous recipient across spaces."""
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)

        # Create local user named "alice"
        local_token = _create_user(atcha_dir, "alice")

        # Create local user to be the sender
        sender_token = _create_user(atcha_dir, "sender")

        # Create remote space with user also named "alice"
        remote_atcha = _create_federated_space(federation_base, "remote-project")
        remote_env = {"ATCHA_ADMIN_PASS": PASSWORD, "ATCHA_DIR": str(remote_atcha)}
        _ = run_cli("admin", "users", "create", "--name=alice", "--role=Remote Alice", env=remote_env, cwd=str(federation_base / "remote-project"))

        # Register remote space
        _ = run_cli("admin", "spaces", "add", str(remote_atcha), env=env, cwd=str(cwd))

        # Try to send to "alice" without qualification
        sender_env = {"ATCHA_TOKEN": sender_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("send", "--to", "alice", "Hello!", env=sender_env, cwd=str(cwd))
        assert result.returncode != 0
        assert "ambiguous" in result.stderr.lower()

    def test_message_from_space_display(self, atcha_dir: Path, federation_base: Path) -> None:
        """Received messages show sender as name@space for cross-space."""
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)

        # Create local user
        local_token = _create_user(atcha_dir, "local-user")

        # Create remote space with user
        remote_atcha = _create_federated_space(federation_base, "remote-project")
        remote_env = {"ATCHA_ADMIN_PASS": PASSWORD, "ATCHA_DIR": str(remote_atcha)}
        _ = run_cli("admin", "users", "create", "--name=remote-user", "--role=Remote Dev", env=remote_env, cwd=str(federation_base / "remote-project"))

        # Get remote user token
        result = run_cli("admin", "create-token", "--user", "remote-user", env=remote_env, cwd=str(federation_base / "remote-project"))
        remote_token = result.stdout.strip()

        # Get space handles
        local_config = json.loads((atcha_dir / "space.json").read_text())
        local_handle = local_config["name"]

        # Register local space in remote (for cross-space send)
        _ = run_cli("admin", "spaces", "add", str(atcha_dir), env=remote_env, cwd=str(federation_base / "remote-project"))

        # Send from remote to local-user@local-handle
        remote_user_env = {"ATCHA_TOKEN": remote_token, "ATCHA_DIR": str(remote_atcha)}
        result = run_cli("send", "--to", f"local-user@{local_handle}", "Hello from remote!", env=remote_user_env, cwd=str(federation_base / "remote-project"))
        assert result.returncode == 0

        # Register remote space in local (for display)
        _ = run_cli("admin", "spaces", "add", str(remote_atcha), env=env, cwd=str(cwd))

        # Read as local user - should see sender@space (get ID from inbox)
        local_inbox = _user_dir(atcha_dir, "local-user", "Test Agent") / "messages" / "inbox.jsonl"
        local_msg_id: str = json.loads(local_inbox.read_text().strip())["id"]
        user_env = {"ATCHA_TOKEN": local_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("messages", "read", local_msg_id, env=user_env, cwd=str(cwd))
        assert result.returncode == 0
        msg = json.loads(result.stdout.strip())
        assert "@" in msg["from"]

    def test_from_filter_cross_space(self, atcha_dir: Path, federation_base: Path) -> None:
        """--from=name@space filters cross-space messages correctly."""
        cwd = atcha_dir.parent
        env = _admin_env(atcha_dir)

        # Create local user (recipient)
        local_token = _create_user(atcha_dir, "local-user")

        # Create remote space with a user
        remote_atcha = _create_federated_space(federation_base, "remote-proj")
        remote_env = {"ATCHA_ADMIN_PASS": PASSWORD, "ATCHA_DIR": str(remote_atcha)}
        result = run_cli("admin", "users", "create", "--name=remote-user", "--role=Remote Dev", env=remote_env, cwd=str(federation_base / "remote-proj"))
        assert result.returncode == 0

        # Get remote user token
        result = run_cli("admin", "create-token", "--user", "remote-user", env=remote_env, cwd=str(federation_base / "remote-proj"))
        remote_token = result.stdout.strip()

        # Get space handles
        local_config = json.loads((atcha_dir / "space.json").read_text())
        local_handle = local_config["name"]
        remote_config = json.loads((remote_atcha / "space.json").read_text())
        remote_handle = remote_config["name"]

        # Register local space in remote (so remote can send to local)
        _ = run_cli("admin", "spaces", "add", str(atcha_dir), env=remote_env, cwd=str(federation_base / "remote-proj"))
        # Register remote space in local (so local can display sender@space)
        _ = run_cli("admin", "spaces", "add", str(remote_atcha), env=env, cwd=str(cwd))

        # Also create a local sender to send a local message
        local_sender_token = _create_user(atcha_dir, "local-sender")
        local_sender_env = {"ATCHA_TOKEN": local_sender_token, "ATCHA_DIR": str(atcha_dir)}
        _ = run_cli("send", "--to", "local-user", "Local message", env=local_sender_env, cwd=str(cwd))

        # Send from remote to local-user@local-handle
        remote_user_env = {"ATCHA_TOKEN": remote_token, "ATCHA_DIR": str(remote_atcha)}
        result = run_cli("send", "--to", f"local-user@{local_handle}", "Cross-space message", env=remote_user_env, cwd=str(federation_base / "remote-proj"))
        assert result.returncode == 0

        # Read with --from=remote-user@remote-handle: should only get the cross-space msg
        user_env = {"ATCHA_TOKEN": local_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("messages", f"--from=remote-user@{remote_handle}", env=user_env, cwd=str(cwd))
        assert result.returncode == 0
        messages = json.loads(result.stdout)
        assert len(messages) == 1
        assert "Cross-space" in messages[0].get("preview", messages[0].get("content", ""))

        # --from=remote-user@wrong-space should return nothing
        result = run_cli("messages", "--from=remote-user@wrong-space", env=user_env, cwd=str(cwd))
        assert result.returncode == 0
        messages = json.loads(result.stdout)
        assert len(messages) == 0

        # --from=remote-user (bare name) should still match the cross-space message
        result = run_cli("messages", "--from=remote-user", env=user_env, cwd=str(cwd))
        assert result.returncode == 0
        messages = json.loads(result.stdout)
        assert len(messages) == 1


class TestFederationBackwardCompat:
    """Tests for FR-006: Backward Compatibility."""

    def test_backward_compat_no_space_json(self, tmp_path: Path) -> None:
        """Existing spaces without space.json get auto-upgraded on federation-aware commands."""
        # Initialize space
        result = run_cli("admin", "init", f"--password={PASSWORD}", cwd=str(tmp_path))
        assert result.returncode == 0
        atcha_dir = tmp_path / ".atcha"

        # Delete space.json to simulate pre-federation space
        space_file = atcha_dir / "space.json"
        space_file.unlink()
        assert not space_file.exists()

        # Create users for sending
        env = _admin_env(atcha_dir)
        _ = run_cli("admin", "users", "create", "--name=sender", "--role=Test", env=env, cwd=str(tmp_path))
        _ = run_cli("admin", "users", "create", "--name=recipient", "--role=Test", env=env, cwd=str(tmp_path))

        # Get sender token
        result = run_cli("admin", "create-token", "--user", "sender", env=env, cwd=str(tmp_path))
        sender_token = result.stdout.strip()

        # Send a message - this triggers auto-upgrade because cmd_send uses _ensure_space_config
        sender_env = {"ATCHA_TOKEN": sender_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("send", "--to", "recipient", "test message", env=sender_env, cwd=str(tmp_path))
        assert result.returncode == 0

        # space.json should now exist (auto-created by send command)
        assert space_file.exists()
        config = json.loads(space_file.read_text())
        assert config["id"].startswith("spc-")

    def test_backward_compat_no_from_space(self, atcha_dir: Path) -> None:
        """Messages without from_space are treated as local."""
        cwd = atcha_dir.parent

        # Create users
        sender_token = _create_user(atcha_dir, "sender")
        recipient_token = _create_user(atcha_dir, "recipient")

        # Manually write a message without from_space (simulating old format)
        recipient_inbox = _user_dir(atcha_dir, "recipient", "Test Agent") / "messages" / "inbox.jsonl"
        old_msg = {
            "id": "msg-old12345",
            "thread_id": "msg-old12345",
            "from": "sender",
            "to": ["recipient"],
            "ts": "2026-01-01T00:00:00Z",
            "type": "message",
            "content": "Old format message",
        }
        with open(recipient_inbox, "a") as f:
            f.write(json.dumps(old_msg) + "\n")

        # Read message by ID - should work without errors
        recipient_env = {"ATCHA_TOKEN": recipient_token, "ATCHA_DIR": str(atcha_dir)}
        result = run_cli("messages", "read", "msg-old12345", env=recipient_env, cwd=str(cwd))
        assert result.returncode == 0
        # Output from "messages read" formats from as a string, not dict
        # Should not have @space suffix (local message)
        msg = json.loads(result.stdout.strip())
        assert msg["from"] == "sender"
        assert "@" not in msg["from"]
