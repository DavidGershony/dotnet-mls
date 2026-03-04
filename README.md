# dotnet-mls

A pure C# implementation of the **Messaging Layer Security (MLS)** protocol, as specified in [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420).

## Overview

`dotnet-mls` provides a complete MLS group state machine for end-to-end encrypted messaging. MLS is an IETF standard protocol that enables efficient, scalable, and forward-secret group key agreement for messaging applications.

The library is split into two NuGet packages:

| Package | Description |
|---------|-------------|
| `DotnetMls` | Core MLS protocol implementation (group lifecycle, message framing, tree operations, key schedule) |
| `DotnetMls.Crypto` | Cryptographic primitives and cipher suite implementations |

## Features

- **Group lifecycle**: Create groups, add members (via `Welcome`), remove members, and self-update key material
- **Proposals and Commits**: Generate and process `Add`, `Remove`, and `Update` proposals; create and process `Commit` messages
- **Application messages**: Encrypt and decrypt application data as `PrivateMessage` (AEAD-protected, sender-authenticated)
- **Public messages**: Support for `PublicMessage` wire format (signed, membership-tagged commits)
- **TreeKEM**: Full ratchet tree implementation with `Encap`/`Decap` for forward secrecy and post-compromise security
- **Key schedule**: Epoch-based key derivation (init secret, joiner secret, welcome secret, encryption secret, exporter secret, and more)
- **Secret export**: MLS exporter mechanism for deriving application-level keying material
- **TLS codec**: Complete TLS-style binary encoding/decoding used throughout the protocol
- **Cipher suite `0x0001`**: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`

## Requirements

- .NET 9.0 or later

## Installation

The packages are published to [GitHub Packages](https://github.com/DavidGershony/dotnet-mls/packages).

```xml
<PackageReference Include="DotnetMls" Version="1.0.0" />
<PackageReference Include="DotnetMls.Crypto" Version="1.0.0" />
```

To consume packages from GitHub Packages, add the feed to your `nuget.config`:

```xml
<configuration>
  <packageSources>
    <add key="github" value="https://nuget.pkg.github.com/DavidGershony/index.json" />
  </packageSources>
</configuration>
```

## Quick Start

### 1. Create a group (Alice)

```csharp
using DotnetMls.Crypto;
using DotnetMls.Group;

ICipherSuite cs = new CipherSuite0x0001();

// Generate Alice's signing key pair
var (aliceSigPriv, aliceSigPub) = cs.GenerateSignatureKeyPair();

// Alice creates a new MLS group
var aliceGroup = MlsGroup.CreateGroup(
    cs,
    identity: "alice"u8.ToArray(),
    signingPrivateKey: aliceSigPriv,
    signingPublicKey: aliceSigPub);
```

### 2. Generate a KeyPackage (Bob, before being added)

```csharp
var (bobSigPriv, bobSigPub) = cs.GenerateSignatureKeyPair();

// Bob creates a KeyPackage to share with the group
var bobKeyPackage = MlsGroup.CreateKeyPackage(
    cs,
    identity: "bob"u8.ToArray(),
    signingPrivateKey: bobSigPriv,
    signingPublicKey: bobSigPub,
    out byte[] bobInitPriv,   // store securely
    out byte[] bobHpkePriv);  // store securely
```

### 3. Add Bob to the group (Alice commits)

```csharp
// Alice proposes adding Bob
var addProposals = aliceGroup.ProposeAdd(new[] { bobKeyPackage });

// Alice creates a Commit; the Welcome is for Bob
var (commitMessage, welcome) = aliceGroup.Commit(addProposals);

// After the Commit is distributed, Alice merges the new epoch
aliceGroup.MergePendingCommit();
```

### 4. Join the group (Bob processes the Welcome)

```csharp
var bobGroup = MlsGroup.ProcessWelcome(
    cs,
    welcome!,
    myKeyPackage: bobKeyPackage,
    myInitPrivateKey: bobInitPriv,
    myHpkePrivateKey: bobHpkePriv,
    mySigningPrivateKey: bobSigPriv);

// Both members are now in the same epoch
Console.WriteLine(aliceGroup.Epoch == bobGroup.Epoch); // true
```

### 5. Send encrypted application messages

```csharp
// Alice sends a message
var encrypted = aliceGroup.EncryptApplicationMessage("Hello, Bob!"u8.ToArray());

// Bob decrypts it
var (plaintext, senderLeaf) = bobGroup.DecryptApplicationMessage(encrypted);
Console.WriteLine(System.Text.Encoding.UTF8.GetString(plaintext)); // "Hello, Bob!"
Console.WriteLine(senderLeaf); // 0 (Alice is leaf 0)
```

### 6. Remove a member

```csharp
// Alice removes Bob (leaf index 1)
var removeProposal = aliceGroup.ProposeRemove(leafIndex: 1);
var (commitMsg2, _) = aliceGroup.Commit(new List<Proposal> { removeProposal });
aliceGroup.MergePendingCommit();
```

### 7. Export a secret

```csharp
// Derive application-level keying material from the current epoch
byte[] exportedKey = aliceGroup.ExportSecret(
    label: "my-app-label",
    context: "session-context"u8.ToArray(),
    length: 32);
```

### 8. List group members

```csharp
var members = aliceGroup.GetMembers();
foreach (var (leafIndex, identity) in members)
{
    Console.WriteLine($"Leaf {leafIndex}: {System.Text.Encoding.UTF8.GetString(identity)}");
}
```

## Architecture

```
dotnet-mls/
├── src/
│   ├── DotnetMls/                  # Core MLS protocol
│   │   ├── Group/
│   │   │   ├── MlsGroup.cs         # Main group state machine
│   │   │   └── MlsGroupConfig.cs   # Configuration (padding, ratchet tolerances)
│   │   ├── Tree/
│   │   │   ├── RatchetTree.cs      # Left-balanced binary tree of leaf/parent nodes
│   │   │   ├── TreeKem.cs          # TreeKEM Encap/Decap
│   │   │   ├── TreeMath.cs         # Tree index arithmetic (RFC 9420 Appendix C)
│   │   │   ├── TreeNode.cs         # Typed tree node (leaf or parent)
│   │   │   └── ParentNode.cs       # Parent node with unmerged leaves tracking
│   │   ├── KeySchedule/
│   │   │   ├── KeyScheduleEpoch.cs # Epoch-based secret derivation
│   │   │   ├── SecretTree.cs       # Per-leaf/generation ratchet for AEAD keys
│   │   │   └── TranscriptHash.cs   # Confirmed/interim transcript hash state
│   │   ├── Message/
│   │   │   ├── MessageFraming.cs   # PublicMessage/PrivateMessage framing
│   │   │   └── SenderRatchet.cs    # Per-sender generation ratchet
│   │   ├── Codec/                  # TLS binary codec (reader/writer, varint)
│   │   └── Types/                  # MLS struct definitions (KeyPackage, LeafNode,
│   │                               #   Commit, Welcome, GroupInfo, Proposal, ...)
│   └── DotnetMls.Crypto/           # Cryptographic primitives
│       ├── ICipherSuite.cs         # Cipher suite abstraction
│       ├── CipherSuite0x0001.cs    # MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
│       ├── AesGcmProvider.cs       # AES-128-GCM AEAD
│       ├── Ed25519Provider.cs      # Ed25519 signatures (via BouncyCastle)
│       ├── HkdfProvider.cs         # HKDF-SHA256
│       ├── HpkeX25519Aes128.cs     # HPKE (DHKEM(X25519) + AES-128-GCM)
│       └── X25519Provider.cs       # X25519 key exchange (via BouncyCastle)
├── tests/
│   ├── DotnetMls.Tests/            # Unit and integration tests (xUnit)
│   └── DotnetMls.Crypto.Tests/     # Cipher suite unit tests
└── benchmarks/
    └── DotnetMls.Benchmarks/       # BenchmarkDotNet performance benchmarks
```

### Key Design Concepts

**`MlsGroup`** is the central type. It holds the complete per-member epoch state:

| Field | Description |
|-------|-------------|
| `GroupId` | Unique identifier for the group |
| `Epoch` | Monotonically increasing epoch counter |
| `MyLeafIndex` | This member's position in the ratchet tree |
| `CipherSuiteId` | Cipher suite in use (e.g. `0x0001`) |
| `Tree` | The current ratchet tree |
| `GroupContext` | Authenticated context (version, suite, tree hash, transcript hash) |
| `KeySchedule` | Current epoch's key material |

**Commit flow**:
1. Call `Commit(proposals)` → returns `(PublicMessage, Welcome?)`
2. Distribute the `PublicMessage` to all current members; send the `Welcome` to new members
3. Call `MergePendingCommit()` to apply the new epoch state

**Receiving a commit**:
- Call `ProcessCommit(commitMessage)` to verify and apply a commit from another member

## Supported Cipher Suites

| ID | Name | KEM | AEAD | Hash | Signature |
|----|------|-----|------|------|-----------|
| `0x0001` | `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` | DHKEM(X25519, HKDF-SHA256) | AES-128-GCM | SHA-256 | Ed25519 |

Implement `ICipherSuite` to add additional cipher suites.

## Configuration

`MlsGroupConfig` controls group-level settings:

```csharp
var config = new MlsGroupConfig
{
    OutOfOrderTolerance = 5,       // Max generations a message may arrive out of order
    MaxForwardDistance  = 1000,    // Max forward ratchet steps (DoS protection)
    Padding             = new byte[16], // Zero-padded bytes appended to encrypted messages
};

var group = MlsGroup.CreateGroup(cs, identity, sigPriv, sigPub, config: config);
```

## Building

```bash
dotnet build
```

## Testing

```bash
dotnet test
```

Tests use [xUnit](https://xunit.net/) and cover:

- TLS codec round-trips
- Tree math (levels, parents, siblings, roots)
- Ratchet tree operations
- Key schedule epoch derivation
- Full MLS group lifecycle (create, add, remove, commit, process, encrypt, decrypt)
- Secret export
- Cipher suite primitives

## Benchmarks

```bash
dotnet run --project benchmarks/DotnetMls.Benchmarks -c Release
```

Benchmarks (using [BenchmarkDotNet](https://benchmarkdotnet.org/)) cover:

- Group creation
- KeyPackage creation
- TreeKEM Encap/Decap
- Commit creation and processing
- Application message encryption and decryption
- Key schedule derivation
- TLS codec serialization

## License

MIT
