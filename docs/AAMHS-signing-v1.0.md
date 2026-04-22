# AAMHS Detached Signing Standard v1.0

## Purpose

The AAMHS Detached Signing Standard defines the signing half of the publication workflow for Aptlantis archive artifacts.

The hasher produces `snapshot-hashes.txt`. The signer then signs that manifest as a separate step. This split is intentional: hashing and signing are distinct responsibilities, and the signer must never regenerate or reinterpret the manifest contents.

This standard governs:

- the signer input
- the detached signature output
- the signing workflow boundary
- PGP requirements for v1.0

This standard does not define how archive hashes are computed.

## Current Signing Process

The normative sequence is:

1. Accept an existing `snapshot-hashes.txt` produced by the hashing workflow.
2. Sign that file as written.
3. Emit a detached ASCII-armored PGP signature.
4. Publish the manifest and detached signature alongside the archive artifact.

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

## Required Output

The required detached signature output is:

```text
snapshot-hashes.txt.asc
```

This output MUST be an ASCII-armored detached PGP signature over the manifest bytes as written.

## v1.0 Requirements

- Detached PGP signing is the required signing mechanism in v1.0.
- Signing keys are externally managed and supplied to the signer.
- The signer tool should load existing key material and sign the manifest without modifying it.
- Post-quantum signatures remain reserved for future revisions and are not required in v1.0.

## Validation Workflow

A compliant signature verifier MUST:

1. Read `snapshot-hashes.txt`
2. Read `snapshot-hashes.txt.asc`
3. Verify the detached PGP signature against the manifest bytes
4. Fail if the manifest contents changed, the key is wrong, or the signature is invalid

## Out of Scope

The following are explicitly out of scope for AAMHS Signing v1.0:

- archive hashing
- manifest generation
- post-quantum signature enforcement
- republishing upstream package signatures
- package-level signature verification inside the archive

## Forward Compatibility

Future revisions may add:

- optional or required PQ detached signatures
- multi-signature workflows
- transparency-log recording
- signer identity policy requirements
