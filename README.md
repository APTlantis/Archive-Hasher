# Archive-Hasher

`Archive-Hasher` now follows the real AAMHS publication workflow:

1. Hash the published archive artifact and emit `snapshot-hashes.txt`
2. Sign that manifest with detached PGP and optional SLH-DSA post-quantum signatures

The production implementation is now Go-based and split into two focused CLIs:

- `archive-hasher`: hashes a single archive artifact and writes the canonical AAMHS manifest
- `manifest-signer`: signs an existing `snapshot-hashes.txt` without mutating it

The older Python tool remains in the repo only as a deprecated prototype/reference.

## Commands

Build both tools:

```powershell
go build ./cmd/archive-hasher
go build ./cmd/manifest-signer
```

Run the hasher:

```powershell
go run ./cmd/archive-hasher --verbose python-complete-1990-2025.python.zip.aamhs
```

This writes:

```text
C:\Artifacts\python-1990-2025-snapshot.tar.zst.aamhs\snapshot-hashes.txt
```

Run the signer:

```powershell
go run ./cmd/manifest-signer --key "A:\AptWeb\zypper-operations\Archive-Hasher\AptlantisSigningKey-Private.asc" "A:\downloads\python-complete-1990-2025.python.zip.aamhs\snapshot-hashes.txt"
```

This writes:

```text
C:\Artifacts\python-1990-2025-snapshot.tar.zst.aamhs\snapshot-hashes.txt.asc
```

Run the dual signer with OpenSSL 3.5+ native SLH-DSA:

```powershell
openssl genpkey -algorithm SLH-DSA-SHAKE-256s -out sphincs.key
openssl pkey -in sphincs.key -pubout -out sphincs.pub
go run ./cmd/manifest-signer --key "A:\AptWeb\zypper-operations\Archive-Hasher\AptlantisSigningKey-Private.asc" --pq-key ".\sphincs.key" "A:\downloads\python-complete-1990-2025.python.zip.aamhs\snapshot-hashes.txt"
```

This also writes:

```text
C:\Artifacts\python-1990-2025-snapshot.tar.zst.aamhs\snapshot-hashes.txt.sphincs
```

## Hashing behavior

The hasher streams the archive file and computes the required AAMHS hash suite:

- `SHA-512`
- `SHA3-512`
- `SHAKE256-512`
- `SHAKE256-1024`
- `K12-512`
- `BLAKE3-512`
- `BLAKE2bp-512`
- `CRC32`

The manifest includes the standard signature artifact names. Signing is still performed as a separate step and a separate tool.

## Signer behavior

`manifest-signer` only signs a manifest that already exists. It does not:

- hash archives
- regenerate manifests
- embed signatures back into the manifest

Supported inputs:

- manifest path
- ASCII-armored private key path
- optional passphrase via environment variable
- optional signature output path override
- optional OpenSSL SLH-DSA private key path
- optional PQ signature output path override
- optional OpenSSL command path and PQ algorithm override

The default PQ signature algorithm is `SLH-DSA-SHAKE-256s`. `snapshot-hashes.txt.sphincs` is retained as a legacy-friendly filename, while the envelope records `Version: 1` and `Algorithm: SLH-DSA-SHAKE-256s` as the authoritative format and algorithm identity. The public key fingerprint is SHA-256 over the DER-encoded public key.

## Standards

Repo docs now mirror the split workflow:

- [docs/AAMHS-hashing-v2.0.md](docs/AAMHS-hashing-v2.0.md)
- [docs/AAMHS-signing-v2.0.md](docs/AAMHS-signing-v2.0.md)

## Testing

Run:

```powershell
go test ./...
```
