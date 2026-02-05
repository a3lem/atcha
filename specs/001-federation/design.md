---
locked: false
status: active
---

# Design: Federation

## Approach

Extend the existing Atcha architecture with two new JSON files (`space.json` for identity, `federation.local.json` for registry) and modify message format to include origin space. The local space is always implicitly available; federation.local.json only tracks remote spaces.

Address resolution follows a layered approach: bare names resolve locally first, then across federated spaces (error on ambiguity). Qualified addresses (`name@handle`) resolve directly to the specified space.

## Decisions

| Decision | Rationale |
|----------|-----------|
| Space ID format: `spc-{5-char}` | Prefix disambiguates from user IDs in logs and messages |
| Local space implicit | Avoids redundancy; `$ATCHA_DIR` always identifies local space |
| Handle derived from directory at init | Sensible default; admin can rename later |
| Messages store space ID, not handle | IDs are immutable; handles can change |
| `federation.local.json` gitignored | Paths are machine-specific; each dev configures their own |
| Command: `admin federated add/remove/list` | Concise; mirrors `admin users add/list` pattern |

## Data Models

### space.json

Location: `.atcha/space.json`

```json
{
  "id": "spc-a3k9m",
  "handle": "backend",
  "created": "2026-02-05T10:00:00Z"
}
```

| Field | Type | Mutable | Description |
|-------|------|---------|-------------|
| `id` | string | No | Unique identifier, format `spc-[a-z0-9]{5}` |
| `handle` | string | Yes | Human-readable name, derived from directory at init |
| `created` | string | No | ISO 8601 timestamp of space creation |

**Generation:**
- `id`: Generated using same alphabet as user IDs (`23456789abcdefghjkmnpqrstuvwxyz`), prefixed with `spc-`
- `handle`: Derived from parent directory name, slugified (lowercase, alphanumeric + hyphens, max 40 chars)

**Validation:**
- Handle format: `[a-z0-9][a-z0-9-]{1,38}[a-z0-9]` (same rules as user names)
- ID format: `spc-[23456789abcdefghjkmnpqrstuvwxyz]{5}`

### federation.local.json

Location: `.atcha/federation.local.json` (gitignored)

```json
{
  "spaces": [
    {
      "id": "spc-x7p2q",
      "handle": "frontend",
      "path": "/Users/dev/repos/frontend-app/.atcha",
      "added": "2026-02-05T12:00:00Z"
    },
    {
      "id": "spc-m4n8r",
      "handle": "shared-lib",
      "path": "/Users/dev/repos/shared-lib/.atcha",
      "added": "2026-02-05T12:05:00Z"
    }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `spaces` | array | List of registered federated spaces |
| `spaces[].id` | string | Space ID (copied from remote space.json at registration) |
| `spaces[].handle` | string | Space handle (copied from remote space.json, updated on access) |
| `spaces[].path` | string | Absolute path to the remote `.atcha/` directory |
| `spaces[].added` | string | ISO 8601 timestamp of when this space was registered |

**Behavior:**
- On `admin federated add`: Read remote `space.json`, copy `id` and `handle`, store `path`
- On access: Verify path exists, optionally refresh `handle` if changed in remote
- On handle collision: Warn and require `--force`

### Extended Message Format

Existing message format with new `from_space` field:

```json
{
  "id": "msg-3146b979",
  "thread_id": "msg-3146b979",
  "from": "anna",
  "from_space": "spc-a3k9m",
  "to": ["maya"],
  "to_space": "spc-x7p2q",
  "ts": "2026-02-05T14:30:00Z",
  "type": "message",
  "content": "API endpoint is ready for integration."
}
```

| New Field | Type | Description |
|-----------|------|-------------|
| `from_space` | string | Space ID of sender (always present in new messages) |
| `to_space` | string | Space ID of recipient's space (present for cross-space messages) |

**Backward compatibility:**
- Messages without `from_space` are treated as originating from the current space
- Messages without `to_space` are treated as local-only

## Interfaces

### New Commands

#### `atcha admin federated add <path>`

Register a federated space.

```
Arguments:
  path              Absolute path to remote .atcha/ directory (or parent with .atcha/)

Options:
  --force           Proceed despite handle collision

Output (JSON):
  {"status": "added", "id": "spc-x7p2q", "handle": "frontend", "path": "/path/to/.atcha"}

Errors:
  - "not a valid atcha space: <path>" (no space.json found)
  - "handle collision: <handle> already registered (spc-xxx)" (requires --force)
```

#### `atcha admin federated remove <handle-or-id>`

Unregister a federated space.

```
Arguments:
  handle-or-id      Space handle or ID to remove

Output (JSON):
  {"status": "removed", "id": "spc-x7p2q", "handle": "frontend"}

Errors:
  - "space not found: <identifier>"
```

#### `atcha admin federated list`

List all federated spaces.

```
Output (JSON array):
  [
    {"id": "spc-x7p2q", "handle": "frontend", "path": "/path/to/.atcha", "available": true},
    {"id": "spc-m4n8r", "handle": "shared-lib", "path": "/other/path/.atcha", "available": false}
  ]

Notes:
  - "available" indicates whether path is currently accessible
  - Local space is NOT included (it's implicit)
```

#### `atcha admin space rename --handle <new-handle>`

Rename the current space's handle.

```
Options:
  --handle          New handle for the space

Output (JSON):
  {"status": "renamed", "id": "spc-a3k9m", "old_handle": "backend", "new_handle": "api-services"}

Errors:
  - "invalid handle format: <handle>"
```

### Modified Commands

#### `atcha contacts` (extended)

```
New behavior:
  - Includes users from all available federated spaces
  - Display format: "maya (frontend)" or "maya" if unambiguous
  - JSON output includes "space" field: {"name": "maya", "space": "frontend", ...}

New options:
  --space <handle-or-id>    Filter to specific space
  --local                   Show only local users (equivalent to --space <local-handle>)

Lookup syntax:
  atcha contacts maya           # Show all users named maya across spaces
  atcha contacts maya@frontend  # Show maya from frontend space specifically
```

#### `atcha send` (extended)

```
New behavior:
  - Recipient can be "name" or "name@space-handle"
  - Bare name: resolve locally first, then federated (error if ambiguous)
  - Messages include from_space in metadata

Address resolution:
  1. If "@" in recipient: split into name and space, resolve space, find user in that space
  2. If no "@": check local space first, then federated spaces
  3. If found in multiple spaces: error with disambiguation hint
```

## Data Flow

### Sending Cross-Space Message

```
1. Parse recipient: "maya@frontend"
2. Resolve space: "frontend" → federation.local.json → path "/Users/dev/repos/frontend/.atcha"
3. Verify space accessible: check path exists
4. Resolve user: find "maya" in that space's users/
5. Construct message with from_space = local space ID, to_space = target space ID
6. Write to recipient inbox: /Users/dev/repos/frontend/.atcha/users/maya/messages/inbox.jsonl
7. Write to sender sent: local .atcha/users/<sender>/messages/sent.jsonl
```

### Reading Messages with Unknown Space

```
1. Read inbox.jsonl
2. For each message with from_space:
   a. Check if from_space in federation.local.json → use handle
   b. If not found → display raw ID, warn "unknown space: spc-xyz"
3. Display sender as "anna@backend" (cross-space) or "anna" (local)
```

### Address Resolution Algorithm

```python
def resolve_recipient(recipient: str, local_space: Space, federation: list[Space]) -> tuple[User, Space]:
    if "@" in recipient:
        name, space_ref = recipient.rsplit("@", 1)
        space = find_space_by_handle_or_id(space_ref, federation + [local_space])
        if not space:
            error(f"unknown space: {space_ref}")
        user = find_user_in_space(name, space)
        if not user:
            error(f"user not found: {name} in {space.handle}")
        return user, space
    else:
        # Check local first
        local_user = find_user_in_space(recipient, local_space)

        # Check federated spaces
        federated_matches = []
        for space in federation:
            if space.available:
                user = find_user_in_space(recipient, space)
                if user:
                    federated_matches.append((user, space))

        if local_user and not federated_matches:
            return local_user, local_space
        elif federated_matches and not local_user:
            if len(federated_matches) == 1:
                return federated_matches[0]
            else:
                spaces = [m[1].handle for m in federated_matches]
                error(f"ambiguous recipient: {recipient} exists in {', '.join(spaces)}")
        elif local_user and federated_matches:
            all_matches = [local_space.handle] + [m[1].handle for m in federated_matches]
            error(f"ambiguous recipient: {recipient} exists in {', '.join(all_matches)}")
        else:
            error(f"user not found: {recipient}")
```

## Error Handling

| Scenario | Error Message | Recovery |
|----------|---------------|----------|
| Space path inaccessible | "space unavailable: frontend (path not found: /path)" | Re-register with correct path |
| Handle collision on add | "handle collision: frontend already registered (spc-xxx)" | Use `--force` or rename one space |
| Ambiguous recipient | "ambiguous recipient: maya exists in backend, frontend" | Use `maya@backend` syntax |
| Unknown from_space in message | "unknown space: spc-xyz" (warning) | Register the space |
| Corrupt space.json | "corrupt space identity" (error) | Manual fix required |

## Testing Strategy

### Unit Tests

- Space ID generation (format, uniqueness)
- Handle validation (format rules)
- Address parsing (`name@handle` splitting)
- Resolution algorithm (local priority, ambiguity detection)

### Integration Tests

- `admin federated add` with valid/invalid paths
- `admin federated add` with handle collision
- `admin federated list` with available/unavailable spaces
- `contacts` aggregation across spaces
- `send` to local, federated, ambiguous recipients
- Message display with known/unknown from_space

### Edge Cases

- Sending to self across spaces (same user name in local and federated)
- Space handle renamed after registration (stale handle in federation.local.json)
- Message from space that was later unregistered
- Empty federation (single-space operation, backward compatible)
