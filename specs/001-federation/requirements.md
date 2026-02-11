---
locked: false
status: completed
---

# Requirements: Federation

## Overview

### Context

Atcha currently supports a single `.atcha/` space per project. Agents communicate within that space via filesystem-based messaging. However, users often work across multiple git repositories simultaneously, each potentially having its own Atcha space.

### Problem

When agents in separate git repositories need to communicate, the current options are:
1. Create a shared Atcha space outside both repos (loses git version control of messages)
2. Manually copy messages between spaces (error-prone, no identity tracking)

Users want agents in different repositories to message each other while preserving the benefits of per-repo Atcha spaces (version control, isolation, clear ownership).

### Goal

Enable multiple local Atcha spaces to federate, allowing agents to send messages across space boundaries while maintaining identity integrity and message durability.

## Functional Requirements

### FR-001: Space Identity

Each Atcha space has a unique, immutable identity that persists across renames and moves.

**Acceptance Criteria:**

1. WHEN `atcha init` creates a new space, the CLI SHALL generate a unique space ID (format: `spc-[a-z0-9]{5}`) and store it in `.atcha/space.json`
2. WHEN `atcha init` creates a new space, the CLI SHALL derive a default handle from the parent directory name and store it in `.atcha/space.json`
3. WHEN admin runs `atcha admin space rename --handle <new-handle>`, the CLI SHALL update the handle in `space.json` while preserving the space ID
4. [system] SHALL reject any operation that would modify a space ID after creation
5. WHEN any command reads `space.json`, IF the space ID is missing or malformed, THEN the CLI SHALL error with "corrupt space identity"

### FR-002: Federation Registration

Spaces are federated by registering their paths in a local configuration file.

**Acceptance Criteria:**

1. WHEN admin runs `atcha admin federated add <path>`, the CLI SHALL read the target space's `space.json`, extract its ID and handle, and add an entry to `.atcha/federation.local.json`
2. WHEN admin runs `atcha admin federated add <path>`, IF the path does not contain a valid `.atcha/space.json`, THEN the CLI SHALL error with "not a valid atcha space: <path>"
3. WHEN admin runs `atcha admin federated add <path>`, IF a space with the same ID is already registered, THEN the CLI SHALL update the path and confirm "updated path for space <handle>"
4. WHEN admin runs `atcha admin federated add <path>`, IF a space with the same handle but different ID is already registered, THEN the CLI SHALL warn "handle collision: <handle> already registered (spc-xxx); new space has ID spc-yyy" and require `--force` to proceed
5. WHEN admin runs `atcha admin federated remove <handle-or-id>`, the CLI SHALL remove the entry from `federation.local.json`
6. WHEN admin runs `atcha admin federated list`, the CLI SHALL display all registered spaces with their handle, ID, path, and availability status

### FR-003: Cross-Space Contact Discovery

Users from federated spaces appear in contact listings.

**Acceptance Criteria:**

1. WHEN user runs `atcha contacts`, the CLI SHALL include users from all available federated spaces, displaying their name and space handle (e.g., "maya (backend)")
2. WHEN user runs `atcha contacts --space <handle-or-id>`, the CLI SHALL filter to only users from that space
3. WHEN user runs `atcha contacts <name>`, IF multiple users with that name exist across spaces, THEN the CLI SHALL list all matches with their space handles
4. WHEN user runs `atcha contacts <name>@<space-handle>`, the CLI SHALL show the profile of that specific user
5. WHEN a federated space's path is inaccessible (moved/deleted), the CLI SHALL exclude its users from listings and warn "space unavailable: <handle> (path not found: <path>)"

### FR-004: Cross-Space Messaging

Agents can send messages to users in federated spaces.

**Acceptance Criteria:**

1. WHEN user runs `atcha send --to <name>@<space-handle> <content>`, the CLI SHALL write the message to the recipient's inbox in the federated space
2. WHEN user runs `atcha send --to <name>@<space-handle> <content>`, the CLI SHALL include the sender's space ID in the message metadata (`from_space: "spc-xxx"`)
3. WHEN user runs `atcha send --to <name> <content>`, IF the name is unique across all federated spaces, THEN the CLI SHALL send to that user without requiring the space qualifier
4. WHEN user runs `atcha send --to <name> <content>`, IF multiple users with that name exist across spaces, THEN the CLI SHALL error with "ambiguous recipient: <name> exists in <space1>, <space2>; use <name>@<space> to specify"
5. WHEN user runs `atcha send` to a user in an unavailable space, the CLI SHALL error with "recipient unavailable: <name>@<space> (space not accessible)"

### FR-005: Message Origin Tracking

Messages preserve their origin space for durability and display.

**Acceptance Criteria:**

1. WHEN a message is sent, the CLI SHALL store `from_space` (space ID) in the message JSON
2. WHEN displaying a received message, the CLI SHALL show the sender as `<name>@<space-handle>` if the message originated from a different space
3. WHEN displaying a received message, IF the `from_space` ID is not in `federation.local.json`, THEN the CLI SHALL show the sender as `<name>@<space-id>` (raw ID) and warn "unknown space: <space-id>"
4. WHEN `atcha messages read` encounters a message from an unknown space, the CLI SHALL suggest "run `atcha admin federation add <path>` to register this space"

### FR-006: Backward Compatibility

Existing single-space installations continue to work without changes.

**Acceptance Criteria:**

1. WHEN `atcha init` is run on an existing space without `space.json`, the CLI SHALL generate and write `space.json` without disrupting existing data
2. WHEN any command runs in a space without `space.json`, the CLI SHALL auto-generate `space.json` with a new ID and handle derived from directory name
3. WHEN messages lack a `from_space` field (pre-federation messages), the CLI SHALL treat them as originating from the current space

## Non-Functional Requirements

### NFR-001: Local-Only Operation

Federation operates entirely on the local filesystem without network protocols.

**Acceptance Criteria:**

1. [CLI] SHALL NOT make any network requests for federation operations
2. [CLI] SHALL access federated spaces only via filesystem paths
3. WHEN a federated space path is inaccessible, [CLI] SHALL gracefully degrade (warn, exclude from listings) rather than fail

### NFR-002: Identity Durability

Space and user identities remain valid even as handles and paths change.

**Acceptance Criteria:**

1. [Messages] SHALL reference space IDs (not handles) in `from_space` field
2. [Messages] SHALL reference user IDs (not names) in `from` field
3. WHEN a space handle changes, existing messages SHALL remain readable and correctly attributed

## Constraints

- All Atcha spaces must be on the same filesystem (or mounted filesystem) accessible to the CLI
- Federation configuration (`federation.local.json`) is machine-local and should be gitignored
- Space IDs are immutable once created; handles may change

## Assumptions

- Users have filesystem read/write access to all federated spaces they register
- Federated spaces trust each other's admins (any admin can operate across federated spaces)
- Agents do not maliciously spoof space IDs (no cryptographic verification in v1)

## Out of Scope

- Network-based federation (ActivityPub, WebSocket, etc.)
- Cryptographic verification of space identity
- Access control between federated spaces (all-or-nothing trust)
- Automatic discovery of nearby Atcha spaces
- Synchronization or conflict resolution for concurrent edits

## Verification

### Testable Properties

- Space ID is immutable: no operation can change an existing space ID
- Handle collision detection: registering a space with a duplicate handle warns unless forced
- Message durability: messages remain readable after source space handle changes
- Graceful degradation: unavailable spaces produce warnings, not errors

## Glossary

- **Space**: An Atcha installation (a `.atcha/` directory and its contents)
- **Space ID**: Immutable unique identifier for a space (format: `spc-[a-z0-9]{5}`)
- **Space Handle**: Human-readable name for a space, mutable, must be unique within federation
- **Federation**: The set of spaces registered in `federation.local.json`
- **Local space**: The space containing the current `$ATCHA_DIR`
- **Federated space**: Any space registered in `federation.local.json` (includes local space)
