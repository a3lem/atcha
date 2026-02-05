---
locked: false
status: active
---

# Tasks: Federation

## Plan

### Phase 1: Space Identity Foundation

Add space identity to new and existing spaces.

**Files:**
| File | Action | Changes |
|------|--------|---------|
| `src/atcha/cli/atcha.py` | modify | Add SpaceConfig type, _generate_space_id(), space.json helpers |

**Code Pattern:**

```python
# Add after line 68 (MessagesState)
class SpaceConfig(T.TypedDict):
    """Space identity stored in space.json."""
    id: str      # spc-{5-char}, immutable
    handle: str  # human-readable, mutable
    created: str # ISO timestamp

# Add constant after line 30
SPACE_ID_PREFIX: T.Final[str] = "spc-"

# Add helper functions
def _generate_space_id() -> str:
    """Generate a random space ID with spc- prefix."""
    chars = "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(5))
    return f"{SPACE_ID_PREFIX}{chars}"

def _slugify_handle(name: str) -> str:
    """Convert directory name to valid handle."""
    # Similar to _slugify_role but for handles

def _load_space_config(atcha_dir: Path) -> SpaceConfig | None:
    """Load space.json if it exists."""

def _save_space_config(atcha_dir: Path, config: SpaceConfig) -> None:
    """Save space.json."""

def _ensure_space_config(atcha_dir: Path) -> SpaceConfig:
    """Load or auto-create space.json for backward compatibility."""
```

**Modify cmd_init (around line 710):**
```python
# After creating admin.json, also create space.json
handle = _slugify_handle(atcha_dir.parent.name)
space_config: SpaceConfig = {
    "id": _generate_space_id(),
    "handle": handle,
    "created": _now_iso(),
}
_save_space_config(atcha_dir, space_config)
```

### Phase 2: Federation Registry

Add federation.local.json management.

**Files:**
| File | Action | Changes |
|------|--------|---------|
| `src/atcha/cli/atcha.py` | modify | Add FederatedSpace type, federation helpers, admin federated commands |

**Code Pattern:**

```python
# Add after SpaceConfig
class FederatedSpace(T.TypedDict):
    """Entry in federation.local.json."""
    id: str      # space ID from remote space.json
    handle: str  # handle from remote space.json
    path: str    # absolute path to remote .atcha/
    added: str   # ISO timestamp

class FederationConfig(T.TypedDict):
    """Federation registry stored in federation.local.json."""
    spaces: list[FederatedSpace]

# Add helpers
def _load_federation(atcha_dir: Path) -> FederationConfig:
    """Load federation.local.json, returns empty if not exists."""

def _save_federation(atcha_dir: Path, config: FederationConfig) -> None:
    """Save federation.local.json."""

def _is_space_available(space: FederatedSpace) -> bool:
    """Check if federated space path is accessible."""
    return Path(space["path"]).is_dir()

def _find_space(federation: FederationConfig, identifier: str) -> FederatedSpace | None:
    """Find space by handle or ID."""
```

**Add command handlers:**
```python
def cmd_admin_federated(args: argparse.Namespace) -> None:
    """Admin federated command - add/remove/list federated spaces."""

def cmd_admin_federated_add(args: argparse.Namespace) -> None:
    """Register a federated space."""

def cmd_admin_federated_remove(args: argparse.Namespace) -> None:
    """Unregister a federated space."""

def cmd_admin_federated_list(args: argparse.Namespace) -> None:
    """List federated spaces."""
```

**Add to parser (after admin_users, around line 1870):**
```python
# admin federated
admin_federated = admin_sub.add_parser("federated", ...)
admin_federated_sub = admin_federated.add_subparsers(dest="federated_command", ...)

# admin federated add
admin_federated_add = admin_federated_sub.add_parser("add", ...)
admin_federated_add.add_argument("path", help="Path to .atcha/ directory")
admin_federated_add.add_argument("--force", action="store_true", ...)

# admin federated remove
admin_federated_remove = admin_federated_sub.add_parser("remove", ...)
admin_federated_remove.add_argument("identifier", help="Space handle or ID")

# admin federated list
admin_federated_list = admin_federated_sub.add_parser("list", ...)
```

**Update dispatch (line 2014-2019):**
```python
admin_cmd_map: dict[str, T.Callable[[argparse.Namespace], None]] = {
    "password": cmd_admin_password,
    "users": cmd_admin_users,
    "hints": cmd_admin_hints,
    "federated": cmd_admin_federated,  # Add this
    "space": cmd_admin_space,          # Add this (Phase 6)
}
```

### Phase 3: Admin Space Command

Add command to rename space handle.

**Files:**
| File | Action | Changes |
|------|--------|---------|
| `src/atcha/cli/atcha.py` | modify | Add admin space rename command |

**Code Pattern:**
```python
def cmd_admin_space(args: argparse.Namespace) -> None:
    """Admin space command - manage this space's identity."""

def cmd_admin_space_rename(args: argparse.Namespace) -> None:
    """Rename space handle."""
```

**Add to parser:**
```python
# admin space
admin_space = admin_sub.add_parser("space", ...)
admin_space_sub = admin_space.add_subparsers(dest="space_command", ...)

# admin space rename
admin_space_rename = admin_space_sub.add_parser("rename", ...)
admin_space_rename.add_argument("--handle", required=True, ...)
```

### Phase 4: Address Resolution

Add cross-space address parsing and resolution.

**Files:**
| File | Action | Changes |
|------|--------|---------|
| `src/atcha/cli/atcha.py` | modify | Add address parsing, cross-space resolution |

**Code Pattern:**
```python
def _parse_address(address: str) -> tuple[str, str | None]:
    """Parse 'name' or 'name@space' into (name, space_ref).

    Returns (name, None) for local addresses.
    Returns (name, space_ref) for cross-space addresses.
    """
    if "@" in address:
        name, space_ref = address.rsplit("@", 1)
        return name, space_ref
    return address, None

def _resolve_space(atcha_dir: Path, identifier: str) -> tuple[Path, SpaceConfig] | None:
    """Resolve space handle or ID to (atcha_dir, space_config).

    Checks local space first, then federation.local.json.
    Returns None if not found.
    """

def _resolve_user_cross_space(
    local_atcha_dir: Path,
    address: str
) -> tuple[str, Path, SpaceConfig] | None:
    """Resolve potentially cross-space address to (user_id, target_atcha_dir, space_config).

    For local addresses: resolves in local space, then checks federated spaces for ambiguity.
    For qualified addresses (name@space): resolves directly in specified space.
    """
```

### Phase 5: Cross-Space Contacts

Extend contacts to show federated users.

**Files:**
| File | Action | Changes |
|------|--------|---------|
| `src/atcha/cli/atcha.py` | modify | Extend cmd_contacts, cmd_agents_list |

**Code Pattern:**

**Modify cmd_agents_list (around line 1019):**
```python
def cmd_agents_list(args: argparse.Namespace) -> None:
    """List team agents from local and federated spaces."""
    atcha_dir = _get_atcha_dir()
    # ... existing code ...

    # New: filter by space
    space_filter = T.cast(str | None, getattr(args, "space", None))

    # New: collect users from federated spaces
    local_space = _ensure_space_config(atcha_dir)
    federation = _load_federation(atcha_dir)

    # For each space (local + federated), collect profiles
    # Add "space" field to output: {"name": "maya", "space": "backend", ...}
```

**Add to contacts parser (around line 1812):**
```python
_ = contacts_parser.add_argument("--space", help="Filter by space handle or ID")
```

**Update _compact_profile to optionally include space:**
```python
def _compact_profile(
    profile: UserProfile,
    full: bool = False,
    show_last_seen_ago: bool = True,
    space_handle: str | None = None  # New parameter
) -> dict[str, T.Any]:
```

### Phase 6: Cross-Space Messaging

Extend send/receive to work across spaces.

**Files:**
| File | Action | Changes |
|------|--------|---------|
| `src/atcha/cli/atcha.py` | modify | Extend Message type, cmd_send, message display |

**Code Pattern:**

**Message type update (line 71):**
```python
# Message now has optional from_space, to_space fields
Message = dict[str, T.Any]  # Fields: id, thread_id, from, from_space (opt), to, to_space (opt), ts, type, content
```

**Modify cmd_send (around line 1607):**
```python
def cmd_send(args: argparse.Namespace) -> None:
    """Send message (local or cross-space)."""
    atcha_dir, sender = _require_user()

    # Get local space config
    local_space = _ensure_space_config(atcha_dir)

    # Parse recipient addresses
    # For each recipient:
    #   - Parse address (name or name@space)
    #   - Resolve to (user_id, target_atcha_dir, target_space)
    #   - Check for ambiguity

    # Build message with from_space
    msg: Message = {
        "id": msg_id,
        "thread_id": thread_id,
        "from": sender,
        "from_space": local_space["id"],  # Always include
        "to": recipients,
        # to_space only if cross-space
        ...
    }

    # Write to recipient inboxes (may be in different .atcha/ dirs)
```

**Modify message display functions:**
```python
def _format_sender(msg: Message, local_space_id: str, federation: FederationConfig) -> str:
    """Format sender for display, adding @space suffix if cross-space."""
    sender = msg["from"]
    from_space = msg.get("from_space")

    if from_space is None or from_space == local_space_id:
        return sender  # Local message

    # Look up space handle
    space = _find_space_by_id(federation, from_space)
    if space:
        return f"{sender}@{space['handle']}"
    else:
        return f"{sender}@{from_space}"  # Raw ID if unknown
```

### Phase 7: Backward Compatibility

Handle pre-federation spaces and messages.

**Files:**
| File | Action | Changes |
|------|--------|---------|
| `src/atcha/cli/atcha.py` | modify | Auto-upgrade logic |

**Code Pattern:**

**_ensure_space_config already handles auto-creation. Add:**
```python
def _ensure_space_config(atcha_dir: Path) -> SpaceConfig:
    """Load or auto-create space.json for backward compatibility."""
    space_file = atcha_dir / "space.json"
    if space_file.exists():
        return T.cast(SpaceConfig, json.loads(space_file.read_text()))

    # Auto-create for existing spaces
    handle = _slugify_handle(atcha_dir.parent.name)
    config: SpaceConfig = {
        "id": _generate_space_id(),
        "handle": handle,
        "created": _now_iso(),
    }
    _save_space_config(atcha_dir, config)
    return config
```

**Message handling (already covered in Phase 6):**
- Messages without `from_space` are treated as local
- Display functions check for presence of `from_space`

### Phase 8: Tests

Add tests for federation functionality.

**Files:**
| File | Action | Changes |
|------|--------|---------|
| `tests/test_atcha.py` | modify | Add federation tests |

**Test cases:**
1. `test_init_creates_space_json` - verify space.json created on init
2. `test_space_id_format` - verify spc-{5-char} format
3. `test_admin_federated_add` - add a federated space
4. `test_admin_federated_add_collision` - handle collision detection
5. `test_admin_federated_remove` - remove a federated space
6. `test_admin_federated_list` - list with availability status
7. `test_admin_space_rename` - rename space handle
8. `test_contacts_cross_space` - contacts from federated spaces
9. `test_contacts_space_filter` - --space filter
10. `test_send_cross_space` - send to user in federated space
11. `test_send_ambiguous_recipient` - error on ambiguous name
12. `test_message_from_space_display` - cross-space sender display
13. `test_backward_compat_no_space_json` - auto-upgrade
14. `test_backward_compat_no_from_space` - handle old messages

## Implementation Order

1. Phase 1 first - foundation for all other phases
2. Phase 7 (backward compat) with Phase 1 - _ensure_space_config needs to work immediately
3. Phase 2 - federation registry before cross-space features
4. Phase 3 - admin space command (simple, no dependencies)
5. Phase 4 - address resolution (needed by Phases 5 & 6)
6. Phase 5 - cross-space contacts
7. Phase 6 - cross-space messaging
8. Phase 8 - tests throughout, final verification at end

## Checklist

- [ ] [NEXT] Add SpaceConfig type and _generate_space_id() _[FR-001.1]_
- [ ] Add _slugify_handle() and space.json helpers _[FR-001.2]_
- [ ] Modify cmd_init to create space.json _[FR-001.1, FR-001.2]_
- [ ] Add _ensure_space_config() for auto-upgrade _[FR-006.1, FR-006.2]_
- [ ] Add FederatedSpace and FederationConfig types _[FR-002.1]_
- [ ] Add federation.local.json helpers _[FR-002.1]_
- [ ] Add cmd_admin_federated_add with collision detection _[FR-002.1, FR-002.2, FR-002.3, FR-002.4]_
- [ ] Add cmd_admin_federated_remove _[FR-002.5]_
- [ ] Add cmd_admin_federated_list with availability _[FR-002.6]_
- [ ] Add parser entries for admin federated _[FR-002.1]_
- [ ] Add cmd_admin_space_rename _[FR-001.3]_
- [ ] Add parser entries for admin space _[FR-001.3]_
- [ ] Add _parse_address() for name@space syntax _[FR-004.1]_
- [ ] Add _resolve_space() helper _[FR-003.4, FR-004.1]_
- [ ] Add _resolve_user_cross_space() with ambiguity detection _[FR-004.3, FR-004.4]_
- [ ] Extend cmd_agents_list for federated users _[FR-003.1]_
- [ ] Add --space filter to contacts _[FR-003.2]_
- [ ] Handle multiple users with same name _[FR-003.3]_
- [ ] Add unavailable space warning _[FR-003.5]_
- [ ] Add from_space to sent messages _[FR-005.1]_
- [ ] Display cross-space sender as name@handle _[FR-005.2]_
- [ ] Handle unknown from_space in display _[FR-005.3, FR-005.4]_
- [ ] Extend cmd_send for cross-space recipients _[FR-004.1, FR-004.2]_
- [ ] Handle ambiguous recipient error _[FR-004.4]_
- [ ] Handle unavailable space error _[FR-004.5]_
- [ ] Handle messages without from_space _[FR-006.3]_
- [ ] Add tests for all acceptance criteria _[FR-*, NFR-*]_
- [ ] Verify all acceptance criteria _[FR-*, NFR-*]_

## Notes

- All new JSON files should match existing style: `indent=2`, trailing newline
- Space IDs use same alphabet as user IDs (no ambiguous chars)
- federation.local.json should be added to .gitignore template/docs
- Consider adding `atcha admin federated check` to verify all paths (future enhancement)
- Thread participants across spaces: need to handle when thread spans multiple spaces
