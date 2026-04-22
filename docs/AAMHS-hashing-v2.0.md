# AAMHS Hashing Standard v2.0

## Purpose

The Aptlantis Archive Multi-Hash Standard (AAMHS) defines the hashing half of the publication workflow for Aptlantis archive artifacts.

In the current process, Aptlantis publishes an archive artifact such as a `.zip`, `.tar.zst`, `.tar.gz`, `.tar.xz`, or `.torrent`. That published artifact is the object being hashed. The archive may contain software originating from Python, Node, Rust, or other ecosystems, and those upstream materials may already have their own signatures or keys. Those upstream signatures are not republished by AAMHS and are not part of the AAMHS hash contract.

AAMHS v2.0 governs:

- which hashes are required for a published archive artifact
- how `snapshot-hashes.txt` is formatted
- which archive metadata fields must be recorded
- how validators compare a published archive against its manifest

AAMHS v2.0 does not define detached signing. Signing is governed by the companion signing standard and occurs after `snapshot-hashes.txt` has been generated.

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

| Algorithm | Role | Notes |
| --- | --- | --- |
| `SHA-512` | Conservative baseline | SHA-2 family baseline with wide tooling support |
| `SHA3-512` | Sponge | Independent SHA-3 sponge-family digest |
| `SHAKE256-512` | PQ baseline | 64-byte SHAKE256 XOF output |
| `SHAKE256-1024` | Long-term archival | 128-byte SHAKE256 XOF output |
| `K12` | Fast Keccak | KangarooTwelve digest with 32-byte output |
| `BLAKE3-512` | Fast + strong | BLAKE3 with 64-byte output |
| `BLAKE2bp` | Parallel ARX diversity | Four-lane BLAKE2b tree hashing |
| `CRC32` | Legacy/tooling | IEEE CRC-32 for legacy interoperability |

No AAMHS v1.0 legacy hashes are emitted in v2.0 manifests.

## Canonical Output

The canonical manifest filename is:

```text
snapshot-hashes.txt
```

This file MUST be plaintext UTF-8 and MUST describe exactly one published archive artifact.

Canonical layout:

```text
# Aptlantis Archive Multi-Hash Standard (AAMHS v2.0)
snapshot_name: python-1990-2025-snapshot
snapshot_format: tar.zst
snapshot_size_bytes: 61293487321
snapshot_date_utc: 2025-12-03T17:42:00Z
schema_version: 2.0

[Hashes]
SHA-512:        <hex>
SHA3-512:       <hex>
SHAKE256-512:   <hex>
SHAKE256-1024:  <hex>
K12:            <hex>
BLAKE3-512:     <hex>
BLAKE2bp:       <hex>
CRC32:          <hex>

[Notes]
Generated-By: AAMHS Archive Hasher v2.0
Documentation: https://aptlantis.net/aamhs
```

`snapshot-hashes.txt` MUST NOT embed detached signatures, inline PGP payloads, PQ signature blocks, or upstream package-signing metadata.

## Required Metadata Semantics

- `snapshot_name` identifies the published archive set.
- `snapshot_format` records the published archive/container format.
- `snapshot_size_bytes` records the exact byte length of the published archive artifact.
- `snapshot_date_utc` records the artifact timestamp in UTC using RFC 3339 format.
- `schema_version` is `2.0` for this revision.

The manifest is about the published archive artifact as a whole. It is not a package inventory, directory tree manifest, tar recipe, or embedded metadata container.

## File Inclusion Rules

An AAMHS-compliant published set MUST include:

```text
<published-archive>
snapshot-hashes.txt
```

It MAY include detached signature files defined by the companion signing standard, such as:

```text
snapshot-hashes.txt.asc
```

Detached signature files are adjacent publication artifacts, not part of the hash manifest schema itself.

## Validation Workflow

A compliant hashing validator MUST:

1. Read `snapshot-hashes.txt`
2. Validate the canonical field structure
3. Compute the required hashes over the published archive artifact bytes
4. Compare each computed hash to the manifest values
5. Compare the observed byte size with `snapshot_size_bytes`
6. Report any mismatch deterministically

Signature verification is out of scope for this document and is handled separately by the signing standard.

## Out of Scope

The following are explicitly out of scope for AAMHS Hashing v2.0:

- signing key generation
- detached signature generation
- inline signature embedding
- post-quantum signature requirements
- package-level inventories inside the archive
- preservation or republication of upstream package signatures and keys

## Forward Compatibility

Future AAMHS revisions may add:

- richer manifest metadata
- transparency-log integration
- notarization or attestation layers

No v2.0 required field should be removed without a documented transition.
