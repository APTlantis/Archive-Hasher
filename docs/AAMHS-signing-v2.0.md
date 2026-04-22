# AAMHS Detached Signing Standard v2.0

## Purpose

The AAMHS Detached Signing Standard defines the signing half of the publication workflow for Aptlantis archive artifacts.

The hasher produces `snapshot-hashes.txt`. The signer then signs that manifest as a separate step. This split is intentional: hashing and signing are distinct responsibilities, and the signer must never regenerate or reinterpret the manifest contents.

This standard governs:

- the signer input
- the detached signature outputs
- the signing workflow boundary
- PGP and post-quantum signature requirements for v2.0

This standard does not define how archive hashes are computed.

## Current Signing Process

The normative sequence is:

1. Accept an existing `snapshot-hashes.txt` produced by the hashing workflow.
2. Sign that file as written with the normal PGP signing key.
3. Emit a detached ASCII-armored PGP signature.
4. Sign that file as written with the SLH-DSA post-quantum signing key.
5. Emit an armored AAMHS PQ signature envelope.
6. Publish the manifest and detached signatures alongside the archive artifact.

The signer operates on the manifest only. It does not need access to the original archive artifact in order to sign.

## Required Input

The signer input is the exact bytes of:

```text
snapshot-hashes.txt
```

The signer MUST treat the manifest as immutable input.

The signer MUST NOT:

- recompute archive hashes
- rewrite the manifest
- inject inline signatures into the manifest
- append signature references into the manifest
- convert the manifest into another schema as part of signing

## Required Outputs

The required detached signature outputs are:

```text
snapshot-hashes.txt.asc
snapshot-hashes.txt.sphincs
```

`snapshot-hashes.txt.asc` MUST be an ASCII-armored detached PGP signature over the manifest bytes as written.

`snapshot-hashes.txt.sphincs` MUST be an armored AAMHS PQ signature envelope containing a detached `SLH-DSA-SHAKE-256s` signature over the manifest bytes as written.

## PQ Signature Envelope

The PQ signature envelope is UTF-8 text:

```text
-----BEGIN AAMHS PQ SIGNATURE-----
algorithm: SLH-DSA-SHAKE-256s
signature_encoding: base64
signed_artifact: snapshot-hashes.txt
public_key_fingerprint_sha256: <hex>

<base64 detached signature>
-----END AAMHS PQ SIGNATURE-----
```

The `.sphincs` filename is retained as a legacy-friendly label. The authoritative PQ algorithm identity is the envelope `algorithm` field.

The `public_key_fingerprint_sha256` value is the lowercase hexadecimal SHA-256 digest of the DER-encoded public key material.

## v2.0 Requirements

- Detached PGP signing is required.
- Detached SLH-DSA signing is required.
- The required PQ algorithm is `SLH-DSA-SHAKE-256s`.
- Signing keys are externally managed and supplied to the signer.
- OpenSSL 3.5+ native SLH-DSA support is the default local backend.
- Aegis may replace direct OpenSSL use as the key authority when it exposes a compatible signer helper.

## Validation Workflow

A compliant signature verifier MUST:

1. Read `snapshot-hashes.txt`.
2. Read `snapshot-hashes.txt.asc`.
3. Verify the detached PGP signature against the manifest bytes.
4. Read `snapshot-hashes.txt.sphincs`.
5. Parse the AAMHS PQ signature envelope.
6. Verify the detached `SLH-DSA-SHAKE-256s` signature against the manifest bytes.
7. Fail if the manifest contents changed, the key is wrong, or either signature is invalid.

## Out of Scope

The following are explicitly out of scope for AAMHS Signing v2.0:

- archive hashing
- manifest generation
- embedded signature payloads inside `snapshot-hashes.txt`
- republishing upstream package signatures
- package-level signature verification inside the archive

## Forward Compatibility

Future revisions may add:

- Aegis-managed signer discovery
- additional PQ signature algorithms
- multi-signature workflows
- transparency-log recording
- signer identity policy requirements
