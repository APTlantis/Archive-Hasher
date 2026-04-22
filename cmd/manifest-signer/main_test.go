package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/APTlantis/Mirror-Rust-Crates/archive-hasher/aamhs"
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func TestRunPGPOnlyWritesArmoredSignature(t *testing.T) {
	tempDir := t.TempDir()
	manifestPath := filepath.Join(tempDir, "snapshot-hashes.txt")
	keyPath := filepath.Join(tempDir, "signing-key.asc")

	if err := os.WriteFile(manifestPath, []byte("test manifest\n"), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(armorTestPrivateKey(t)), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if err := run([]string{"--key", keyPath, manifestPath}, &stdout, &stderr); err != nil {
		t.Fatalf("run returned error: %v\nstderr:\n%s", err, stderr.String())
	}

	signatureData, err := os.ReadFile(aamhs.DefaultSignaturePath(manifestPath))
	if err != nil {
		t.Fatalf("read PGP signature: %v", err)
	}
	if !bytes.Contains(signatureData, []byte("BEGIN PGP SIGNATURE")) {
		t.Fatalf("expected PGP armored signature, got %q", string(signatureData))
	}
	if _, err := os.Stat(aamhs.DefaultPQSignaturePath(manifestPath)); !os.IsNotExist(err) {
		t.Fatalf("PQ signature should not be written without --pq-key, stat err = %v", err)
	}
}

func TestRunHelpReturnsFlagHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"--help"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("run should return flag.ErrHelp for --help")
	}
	if !strings.Contains(stderr.String(), "Usage of manifest-signer") {
		t.Fatalf("stderr = %q, want usage text", stderr.String())
	}
}

func TestRunMissingOpenSSLForPQReturnsClearError(t *testing.T) {
	tempDir := t.TempDir()
	manifestPath := filepath.Join(tempDir, "snapshot-hashes.txt")
	pgpKeyPath := filepath.Join(tempDir, "signing-key.asc")
	pqKeyPath := filepath.Join(tempDir, "sphincs.key")

	if err := os.WriteFile(manifestPath, []byte("test manifest\n"), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := os.WriteFile(pgpKeyPath, []byte(armorTestPrivateKey(t)), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	if err := os.WriteFile(pqKeyPath, []byte("not a real key"), 0o600); err != nil {
		t.Fatalf("write PQ key: %v", err)
	}

	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--key", pgpKeyPath,
		"--pq-key", pqKeyPath,
		"--openssl", "openssl-command-that-does-not-exist",
		manifestPath,
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("run should fail when PQ signing OpenSSL command is missing")
	}
	if !strings.Contains(stderr.String(), "openssl-command-that-does-not-exist") {
		t.Fatalf("stderr = %q, want missing OpenSSL command detail", stderr.String())
	}
}

func TestRunOpenSSLFlagMissingValueReturnsClearError(t *testing.T) {
	tempDir := t.TempDir()
	manifestPath := filepath.Join(tempDir, "snapshot-hashes.txt")
	pgpKeyPath := filepath.Join(tempDir, "signing-key.asc")
	pqKeyPath := filepath.Join(tempDir, "sphincs.key")

	if err := os.WriteFile(manifestPath, []byte("test manifest\n"), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := os.WriteFile(pgpKeyPath, []byte(armorTestPrivateKey(t)), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	if err := os.WriteFile(pqKeyPath, []byte("not a real key"), 0o600); err != nil {
		t.Fatalf("write PQ key: %v", err)
	}

	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--key", pgpKeyPath,
		"--pq-key", pqKeyPath,
		"--openssl", "--overwrite",
		"--verbose",
		manifestPath,
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("run should fail when --openssl consumes another flag as its value")
	}
	if !strings.Contains(stderr.String(), "--openssl requires a command path") {
		t.Fatalf("stderr = %q, want missing --openssl value detail", stderr.String())
	}
}

func TestRunPGPOverwriteProtection(t *testing.T) {
	tempDir := t.TempDir()
	manifestPath := filepath.Join(tempDir, "snapshot-hashes.txt")
	keyPath := filepath.Join(tempDir, "signing-key.asc")
	signaturePath := aamhs.DefaultSignaturePath(manifestPath)

	if err := os.WriteFile(manifestPath, []byte("test manifest\n"), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(armorTestPrivateKey(t)), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	if err := os.WriteFile(signaturePath, []byte("existing"), 0o644); err != nil {
		t.Fatalf("write existing signature: %v", err)
	}

	var stdout, stderr bytes.Buffer
	err := run([]string{"--key", keyPath, manifestPath}, &stdout, &stderr)
	if err == nil {
		t.Fatal("run should fail when PGP signature exists and --overwrite is false")
	}
	if !strings.Contains(stderr.String(), "already exists") {
		t.Fatalf("stderr = %q, want overwrite detail", stderr.String())
	}
}

func TestRunPQOverwriteProtectionPreventsPartialPGPSignature(t *testing.T) {
	tempDir := t.TempDir()
	manifestPath := filepath.Join(tempDir, "snapshot-hashes.txt")
	pgpKeyPath := filepath.Join(tempDir, "signing-key.asc")
	pqKeyPath := filepath.Join(tempDir, "sphincs.key")
	pqSignaturePath := aamhs.DefaultPQSignaturePath(manifestPath)

	if err := os.WriteFile(manifestPath, []byte("test manifest\n"), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := os.WriteFile(pgpKeyPath, []byte(armorTestPrivateKey(t)), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	if err := os.WriteFile(pqKeyPath, []byte("not a real key"), 0o600); err != nil {
		t.Fatalf("write PQ key: %v", err)
	}
	if err := os.WriteFile(pqSignaturePath, []byte("existing"), 0o644); err != nil {
		t.Fatalf("write existing PQ signature: %v", err)
	}

	var stdout, stderr bytes.Buffer
	err := run([]string{"--key", pgpKeyPath, "--pq-key", pqKeyPath, manifestPath}, &stdout, &stderr)
	if err == nil {
		t.Fatal("run should fail when PQ signature exists and --overwrite is false")
	}
	if !strings.Contains(stderr.String(), "check PQ signature output") {
		t.Fatalf("stderr = %q, want PQ overwrite detail", stderr.String())
	}
	if _, err := os.Stat(aamhs.DefaultSignaturePath(manifestPath)); !os.IsNotExist(err) {
		t.Fatalf("PGP signature should not be written after PQ preflight failure, stat err = %v", err)
	}
}

func TestRunDualSigningWithOpenSSLWhenAvailable(t *testing.T) {
	pqSigner := aamhs.NewOpenSSLPQSigner("openssl", aamhs.DefaultPQSignatureAlgorithm)
	if err := pqSigner.CheckSupport(); err != nil {
		t.Skipf("OpenSSL native %s support is unavailable: %v", aamhs.DefaultPQSignatureAlgorithm, err)
	}

	tempDir := t.TempDir()
	manifestPath := filepath.Join(tempDir, "snapshot-hashes.txt")
	pgpKeyPath := filepath.Join(tempDir, "signing-key.asc")
	pqKeyPath := filepath.Join(tempDir, "sphincs.key")
	pqPublicKeyPath := filepath.Join(tempDir, "sphincs.pub")

	if err := os.WriteFile(manifestPath, []byte("test manifest\n"), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := os.WriteFile(pgpKeyPath, []byte(armorTestPrivateKey(t)), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	if err := pqSigner.GenerateKeyPair(pqKeyPath, pqPublicKeyPath, false); err != nil {
		t.Fatalf("GenerateKeyPair returned error: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if err := run([]string{"--key", pgpKeyPath, "--pq-key", pqKeyPath, manifestPath}, &stdout, &stderr); err != nil {
		t.Fatalf("run returned error: %v\nstderr:\n%s", err, stderr.String())
	}
	if _, err := os.Stat(aamhs.DefaultSignaturePath(manifestPath)); err != nil {
		t.Fatalf("stat PGP signature: %v", err)
	}
	if err := pqSigner.VerifyManifest(manifestPath, pqPublicKeyPath, aamhs.DefaultPQSignaturePath(manifestPath)); err != nil {
		t.Fatalf("VerifyManifest returned error: %v", err)
	}
}

func armorTestPrivateKey(t *testing.T) string {
	t.Helper()

	entity, err := openpgp.NewEntity("AAMHS Test", "Manifest Signer", "test@example.com", &packet.Config{})
	if err != nil {
		t.Fatalf("generate entity: %v", err)
	}

	var serialized bytes.Buffer
	armorWriter, err := armor.Encode(&serialized, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatalf("armor encode: %v", err)
	}
	if err := entity.SerializePrivate(armorWriter, nil); err != nil {
		t.Fatalf("serialize private key: %v", err)
	}
	if err := armorWriter.Close(); err != nil {
		t.Fatalf("close armor writer: %v", err)
	}

	return serialized.String()
}
