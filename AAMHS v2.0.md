# AAMHS v2.0 - Aptlantis Archive Multi-Hash Standard

The Aptlantis Archive Multi-Hash Standard (AAMHS) ensures long-term integrity and verification diversity for archival snapshots published by the Aptlantis Project.

AAMHS v2.0 defines:

- the required archive hash suite
- the canonical `snapshot-hashes.txt` manifest format
- detached signing as a separate workflow
- validator expectations for comparing a published artifact to its manifest

## 1. Scope

AAMHS hashes the published archive artifact as a single byte stream. It does not hash individual packages inside the archive and does not republish upstream package signatures, keyrings, or package-level metadata.

## 2. Hash Suite

Each snapshot MUST generate and publish the following hash set:

| Algorithm | Role | Notes |
| --- | --- | --- |
| **SHA-512** | Conservative baseline | SHA-2 family baseline with broad tooling support |
| **SHA3-512** | Sponge | SHA-3 sponge-family digest |
| **SHAKE256-512** | PQ baseline | 64-byte SHAKE256 XOF output |
| **SHAKE256-1024** | Long-term archival | 128-byte SHAKE256 XOF output |
| **K12-512** | Fast Keccak | KangarooTwelve digest with 64-byte output |
| **BLAKE3-512** | Fast + strong | BLAKE3 with 64-byte output |
| **BLAKE2bp-512** | Parallel ARX diversity | Four-lane BLAKE2b tree hashing |
| **CRC32** | Legacy/tooling | IEEE CRC-32 for compatibility |

AAMHS v2.0 manifests emit only this suite. AAMHS v1.0 legacy hashes such as SHA256, SHA3-256, BLAKE3-256, and xxHash64 are not included.

`CRC32` MUST be the standard IEEE/ISO-HDLC CRC-32 variant using polynomial `0x04C11DB7`, reflected input/output, initial value `0xffffffff`, and final XOR `0xffffffff`. It MUST be encoded as exactly 8 lowercase hexadecimal characters.

## 3. Required Output File

The canonical output filename is:

```text
snapshot-hashes.txt
```

Canonical layout:

```text
# Aptlantis Archive Multi-Hash Standard (AAMHS v2.0)
snapshot_name: <snapshot-name>
snapshot_format: <zip|tar.zst|tar.gz|tar.xz|torrent|...>
snapshot_size_bytes: <bytes>
snapshot_date_utc: <RFC3339 UTC timestamp>
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

The manifest MUST be UTF-8 text with LF line endings (`\n`) and no UTF-8 BOM. Fields and sections MUST appear in exactly the order shown above. Implementations MUST NOT reorder fields, omit blank separator lines, add extra fields, or emit CRLF in canonical manifests.

The manifest MUST NOT embed detached signature payloads, inline PGP payloads, PQ signature blocks, or upstream package-signing metadata.

## 4. Signing

The hasher writes `snapshot-hashes.txt`. The signer then creates adjacent detached signatures:

```text
snapshot-hashes.txt.asc
snapshot-hashes.txt.sphincs
```

`snapshot-hashes.txt.asc` is the detached ASCII-armored PGP signature. `snapshot-hashes.txt.sphincs` is an armored AAMHS PQ signature envelope containing a detached `SLH-DSA-SHAKE-256s` signature over the exact manifest bytes.

The `.sphincs` extension is a legacy-friendly label. The PQ signature envelope uses `base64` for the detached signature payload and records `Version: 1`, `Algorithm: SLH-DSA-SHAKE-256s`, the signed artifact name, and SHA-256 fingerprint of the public key material. The fingerprint is the lowercase hexadecimal SHA-256 digest of the DER-encoded public key. Signing must not regenerate, reinterpret, or mutate the manifest contents.

For AAMHS v2.0 compliance, both detached signature files are mandatory publication artifacts. A manifest may be generated locally before signing, but a published v2.0 set is incomplete until both `snapshot-hashes.txt.asc` and `snapshot-hashes.txt.sphincs` are present and valid.

The canonical PQ envelope structure is:

```text
-----BEGIN AAMHS PQ SIGNATURE-----
Version: 1
Algorithm: SLH-DSA-SHAKE-256s
Encoding: base64
Artifact: snapshot-hashes.txt
Public-Key-Fingerprint-SHA256: <hex>

<base64 detached signature>
-----END AAMHS PQ SIGNATURE-----
```

The envelope MUST be UTF-8 text with LF line endings (`\n`) and no UTF-8 BOM. Header fields MUST appear in exactly the order shown.

## 5. Verification

A compliant validator MUST:

1. Read `snapshot-hashes.txt`.
2. Validate the canonical field structure.
3. Compute all required hashes over the published archive artifact bytes.
4. Compare each computed hash to the manifest values.
5. Compare the observed byte size with `snapshot_size_bytes`.
6. Verify the detached PGP signature.
7. Verify the detached PQ signature.
8. Report any mismatch deterministically.

## 6. Forward Compatibility

Future AAMHS revisions may add richer metadata, transparency-log integration, notarization, or attestation layers. No v2.0 required field should be removed without a documented transition.
