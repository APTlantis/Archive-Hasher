# Archive-Hasher

`Archive-Hasher` now follows the real AAMHS publication workflow:

1. Hash the published archive artifact and emit `snapshot-hashes.txt`
2. Sign that manifest with a detached ASCII-armored PGP signature

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

## Hashing behavior

The hasher streams the archive file and computes the required AAMHS hash suite:

- `SHA-512`
- `SHA3-512`
- `SHAKE256-512`
- `SHAKE256-1024`
- `K12`
- `BLAKE3-512`
- `BLAKE2bp`
- `CRC32`

The manifest intentionally contains no signing metadata. Signing is now a separate step and a separate tool.

## Signer behavior

`manifest-signer` only signs a manifest that already exists. It does not:

- hash archives
- regenerate manifests
- embed signatures back into the manifest
- produce PQ signatures

Supported inputs:

- manifest path
- ASCII-armored private key path
- optional passphrase via environment variable
- optional signature output path override

## Standards

Repo docs now mirror the split workflow:

- [docs/AAMHS-hashing-v2.0.md](docs/AAMHS-hashing-v2.0.md)
- [docs/AAMHS-signing-v1.0.md](docs/AAMHS-signing-v1.0.md)

## Testing

Run:

```powershell
go test ./...
```
