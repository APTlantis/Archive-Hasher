# AAMHS Hashing Standard v2.0

## Purpose

The Aptlantis Archive Multi-Hash Standard (AAMHS) defines the hashing half of the publication workflow for Aptlantis archive artifacts.

In the current process, Aptlantis publishes an archive artifact such as a `.zip`, `.tar.zst`, `.tar.gz`, `.tar.xz`, or `.torrent`. That published artifact is the object being hashed. The archive may contain software originating from Python, Node, Rust, or other ecosystems, and those upstream materials may already have their own signatures or keys. Those upstream signatures are not republished by AAMHS and are not part of the AAMHS hash contract.

AAMHS v2.0 governs:

- which hashes are required for a published archive artifact
- how `snapshot-hashes.txt` is formatted
- which archive metadata fields must be recorded
- how validators compare a published archive against its manifest

AAMHS v2.0 records the standard detached signature artifact names in the manifest. Signature generation and verification are governed by the companion signing workflow and occur after `snapshot-hashes.txt` has been generated.

## Current Publication Process

The normative sequence is:

1. Build or assemble the archive artifact that will actually be published.
2. Hash that archive artifact as a single byte stream.
3. Write the canonical manifest `snapshot-hashes.txt`.
4. Hand `snapshot-hashes.txt` to the detached signer workflow.
5. Publish the archive artifact, the manifest, and any detached signature artifacts together.

The archive artifact is the publication unit. The manifest describes the published artifact, not the internal per-package signatures or keyrings contained within it.

## Required Hash Suite

Every AAMHS-compliant archive artifact MUST publish all of the following hashes:

| Algorithm | Output | Role | Notes |
| --- | --- | --- | --- |
| `SHA-512` | 512-bit | Conservative baseline | SHA-2 family baseline with wide tooling support |
| `SHA3-512` | 512-bit | Sponge | Independent SHA-3 sponge-family digest |
| `SHAKE256-512` | 512-bit | PQ baseline | 64-byte SHAKE256 XOF output |
| `SHAKE256-1024` | 1024-bit | Long-term archival | 128-byte SHAKE256 XOF output |
| `K12-512` | 512-bit | Fast Keccak | KangarooTwelve digest with 64-byte output |
| `BLAKE3-512` | 512-bit | Fast + strong | BLAKE3 with 64-byte output |
| `BLAKE2bp-512` | 512-bit | Parallel ARX diversity | Four-lane BLAKE2b tree hashing |
| `CRC32` | 32-bit | Legacy/tooling | IEEE CRC-32 for legacy interoperability |

No AAMHS v1.0 legacy hashes are emitted in v2.0 manifests.

`CRC32` MUST be the standard IEEE/ISO-HDLC CRC-32 variant using polynomial `0x04C11DB7`, reflected input/output, initial value `0xffffffff`, and final XOR `0xffffffff`. It MUST be encoded as exactly 8 lowercase hexadecimal characters.

## Canonical Output

The canonical manifest filename is:

```text
snapshot-hashes.txt
```

This file MUST be plaintext UTF-8, MUST use LF line endings (`\n`), MUST NOT include a UTF-8 BOM, and MUST describe exactly one published archive artifact.

Canonical layout:

```text
# Aptlantis Archive Multi-Hash Standard (AAMHS v2.0)
snapshot_name: python-1990-2025-snapshot
snapshot_format: tar.zst
snapshot_size_bytes: 61293487321
snapshot_date_utc: 2025-12-03T17:42:00Z
schema_version: 2.0
hash_profile: pq-balanced-8
hash_encoding: hex

[Hashes]
SHA-512:         <hex>
SHA3-512:        <hex>
SHAKE256-512:    <hex>
SHAKE256-1024:   <hex>
K12-512:         <hex>
BLAKE3-512:      <hex>
BLAKE2bp-512:    <hex>
CRC32:           <hex>

[Signatures]
PGP-Signature:   snapshot-hashes.txt.asc
PQ-Signature:    snapshot-hashes.txt.sphincs

[Notes]
Generated-By: AAMHS Archive Hasher v2.0
Documentation: https://aptlantis.net/aamhs
```

Fields and sections MUST appear in exactly the order shown. Implementations MUST NOT reorder fields, omit blank separator lines, add extra fields, or emit CRLF in canonical manifests.

`snapshot-hashes.txt` MUST NOT embed detached signature payloads, inline PGP payloads, PQ signature blocks, or upstream package-signing metadata.

## Required Metadata Semantics

- `snapshot_name` identifies the published archive set.
- `snapshot_format` records the published archive/container format.
- `snapshot_size_bytes` records the exact byte length of the published archive artifact.
- `snapshot_date_utc` records the artifact timestamp in UTC using RFC 3339 format.
- `schema_version` is `2.0` for this revision.
- `hash_profile` is `pq-balanced-8` for the default eight-hash v2.0 profile.
- `hash_encoding` is `hex` for lowercase hexadecimal hash values.

The manifest is about the published archive artifact as a whole. It is not a package inventory, directory tree manifest, tar recipe, or embedded metadata container.

## File Inclusion Rules

An AAMHS-compliant published set MUST include:

```text
<published-archive>
snapshot-hashes.txt
snapshot-hashes.txt.asc
snapshot-hashes.txt.sphincs
```

Detached signature files are adjacent publication artifacts, not part of the hash manifest schema itself.

For AAMHS v2.0 compliance, both detached signature files are mandatory publication artifacts. A local unsigned or partially signed manifest MAY exist during generation, but it is not a complete published v2.0 set.

## Validation Workflow

A compliant hashing validator MUST:

1. Read `snapshot-hashes.txt`
2. Validate the canonical field structure
3. Compute the required hashes over the published archive artifact bytes
4. Validate exact output lengths for all length-qualified hashes
5. Compare each computed hash to the manifest values
6. Compare the observed byte size with `snapshot_size_bytes`
7. Verify the detached PGP signature
8. Verify the detached PQ signature
9. Report any mismatch deterministically

## Out of Scope

The following are explicitly out of scope for AAMHS Hashing v2.0:

- signing key generation
- inline signature embedding
- package-level inventories inside the archive
- preservation or republication of upstream package signatures and keys

## Forward Compatibility

Future AAMHS revisions may add:

- richer manifest metadata
- transparency-log integration
- notarization or attestation layers

No v2.0 required field should be removed without a documented transition.
