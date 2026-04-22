package aamhs

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func TestSignManifestArmoredProducesDetachedSignature(t *testing.T) {
	tempDir := t.TempDir()
	manifestPath := filepath.Join(tempDir, "snapshot-hashes.txt")
	keyPath := filepath.Join(tempDir, "signing-key.asc")
	signaturePath := filepath.Join(tempDir, "snapshot-hashes.txt.asc")

	manifestBody := []byte("test manifest\n")
	if err := os.WriteFile(manifestPath, manifestBody, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	entity := mustGenerateEntity(t)
	if err := os.WriteFile(keyPath, []byte(armorPrivateKey(t, entity)), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}

	if err := SignManifestArmored(manifestPath, keyPath, signaturePath, false, nil); err != nil {
		t.Fatalf("SignManifestArmored returned error: %v", err)
	}

	signatureData, err := os.ReadFile(signaturePath)
	if err != nil {
		t.Fatalf("read signature: %v", err)
	}
	if !bytes.Contains(signatureData, []byte("BEGIN PGP SIGNATURE")) {
		t.Fatalf("expected armored detached signature, got %q", string(signatureData))
	}

	manifestAfter, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest after signing: %v", err)
	}
	if !bytes.Equal(manifestBody, manifestAfter) {
		t.Fatal("manifest contents changed during signing")
	}

	publicRing := openpgp.EntityList{entity}
	_, err = openpgp.CheckArmoredDetachedSignature(
		publicRing,
		bytes.NewReader(manifestBody),
		bytes.NewReader(signatureData),
		nil,
	)
	if err != nil {
		t.Fatalf("detached signature verification failed: %v", err)
	}
}

func TestDefaultSignaturePath(t *testing.T) {
	got := DefaultSignaturePath("C:\\artifacts\\snapshot-hashes.txt")
	want := "C:\\artifacts\\snapshot-hashes.txt.asc"
	if got != want {
		t.Fatalf("DefaultSignaturePath = %q, want %q", got, want)
	}
}

func TestDefaultPQSignaturePath(t *testing.T) {
	got := DefaultPQSignaturePath("C:\\artifacts\\snapshot-hashes.txt")
	want := "C:\\artifacts\\snapshot-hashes.txt.sphincs"
	if got != want {
		t.Fatalf("DefaultPQSignaturePath = %q, want %q", got, want)
	}
}

func TestSignManifestArmoredOverwriteProtection(t *testing.T) {
	tempDir := t.TempDir()
	manifestPath := filepath.Join(tempDir, "snapshot-hashes.txt")
	keyPath := filepath.Join(tempDir, "signing-key.asc")
	signaturePath := filepath.Join(tempDir, "snapshot-hashes.txt.asc")

	if err := os.WriteFile(manifestPath, []byte("manifest"), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := os.WriteFile(signaturePath, []byte("existing"), 0o644); err != nil {
		t.Fatalf("write existing signature: %v", err)
	}

	entity := mustGenerateEntity(t)
	if err := os.WriteFile(keyPath, []byte(armorPrivateKey(t, entity)), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}

	err := SignManifestArmored(manifestPath, keyPath, signaturePath, false, nil)
	if err == nil {
		t.Fatal("SignManifestArmored should fail when overwrite is false")
	}
}

func TestPQSignatureEnvelopeRoundTrip(t *testing.T) {
	envelope := PQSignatureEnvelope{
		Algorithm:             DefaultPQSignatureAlgorithm,
		SignatureEncoding:     PQSignatureEncoding,
		SignedArtifact:        "snapshot-hashes.txt",
		PublicKeyFingerprint:  strings.Repeat("a", 64),
		DetachedSignatureData: []byte("detached signature bytes"),
	}

	rendered, err := RenderPQSignatureEnvelope(envelope)
	if err != nil {
		t.Fatalf("RenderPQSignatureEnvelope returned error: %v", err)
	}

	required := []string{
		"-----BEGIN AAMHS PQ SIGNATURE-----",
		"algorithm: SLH-DSA-SHAKE-256s",
		"signature_encoding: base64",
		"signed_artifact: snapshot-hashes.txt",
		"public_key_fingerprint_sha256: " + strings.Repeat("a", 64),
		"-----END AAMHS PQ SIGNATURE-----",
	}
	for _, fragment := range required {
		if !strings.Contains(rendered, fragment) {
			t.Fatalf("rendered envelope missing %q:\n%s", fragment, rendered)
		}
	}

	parsed, err := ReadPQSignatureEnvelope(strings.NewReader(rendered))
	if err != nil {
		t.Fatalf("ReadPQSignatureEnvelope returned error: %v", err)
	}
	if parsed.Algorithm != envelope.Algorithm {
		t.Fatalf("Algorithm = %q, want %q", parsed.Algorithm, envelope.Algorithm)
	}
	if parsed.SignatureEncoding != envelope.SignatureEncoding {
		t.Fatalf("SignatureEncoding = %q, want %q", parsed.SignatureEncoding, envelope.SignatureEncoding)
	}
	if parsed.SignedArtifact != envelope.SignedArtifact {
		t.Fatalf("SignedArtifact = %q, want %q", parsed.SignedArtifact, envelope.SignedArtifact)
	}
	if parsed.PublicKeyFingerprint != envelope.PublicKeyFingerprint {
		t.Fatalf("PublicKeyFingerprint = %q, want %q", parsed.PublicKeyFingerprint, envelope.PublicKeyFingerprint)
	}
	if !bytes.Equal(parsed.DetachedSignatureData, envelope.DetachedSignatureData) {
		t.Fatalf("DetachedSignatureData = %q, want %q", parsed.DetachedSignatureData, envelope.DetachedSignatureData)
	}
}

func TestReadPQSignatureEnvelopeAcceptsLegacyHeaderNames(t *testing.T) {
	input := strings.Join([]string{
		"-----BEGIN AAMHS PQ SIGNATURE-----",
		"Algorithm: SLH-DSA-SHAKE-256s",
		"Signature-Encoding: base64",
		"Signed-Artifact: snapshot-hashes.txt",
		"Public-Key-Fingerprint-SHA256: " + strings.Repeat("b", 64),
		"",
		"bGVnYWN5IHNpZ25hdHVyZQ==",
		"-----END AAMHS PQ SIGNATURE-----",
		"",
	}, "\n")

	parsed, err := ReadPQSignatureEnvelope(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ReadPQSignatureEnvelope returned error: %v", err)
	}
	if parsed.Algorithm != DefaultPQSignatureAlgorithm {
		t.Fatalf("Algorithm = %q, want %q", parsed.Algorithm, DefaultPQSignatureAlgorithm)
	}
	if !bytes.Equal(parsed.DetachedSignatureData, []byte("legacy signature")) {
		t.Fatalf("DetachedSignatureData = %q, want legacy signature", parsed.DetachedSignatureData)
	}
}

func TestReadPQSignatureEnvelopeRejectsInvalidArmor(t *testing.T) {
	_, err := ReadPQSignatureEnvelope(strings.NewReader("not an envelope"))
	if err == nil {
		t.Fatal("ReadPQSignatureEnvelope should reject invalid armor")
	}
}

func TestOpenSSLPQSignerOverwriteProtection(t *testing.T) {
	tempDir := t.TempDir()
	manifestPath := filepath.Join(tempDir, "snapshot-hashes.txt")
	keyPath := filepath.Join(tempDir, "sphincs.key")
	signaturePath := filepath.Join(tempDir, "snapshot-hashes.txt.sphincs")

	if err := os.WriteFile(manifestPath, []byte("manifest"), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("key"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.WriteFile(signaturePath, []byte("existing"), 0o644); err != nil {
		t.Fatalf("write existing signature: %v", err)
	}

	err := NewOpenSSLPQSigner("openssl-command-that-does-not-exist", "").SignManifest(manifestPath, keyPath, signaturePath, false)
	if err == nil {
		t.Fatal("SignManifest should fail when overwrite is false")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("SignManifest error = %v, want overwrite protection", err)
	}
}

func TestOpenSSLPQSignerMissingCommand(t *testing.T) {
	err := NewOpenSSLPQSigner("openssl-command-that-does-not-exist", "").CheckSupport()
	if err == nil {
		t.Fatal("CheckSupport should fail for a missing OpenSSL command")
	}
	if !strings.Contains(err.Error(), "is not available") {
		t.Fatalf("CheckSupport error = %v, want missing command detail", err)
	}
}

func TestRequireOpenSSL35(t *testing.T) {
	if err := requireOpenSSL35("OpenSSL 3.5.0 8 Apr 2025"); err != nil {
		t.Fatalf("requireOpenSSL35 rejected OpenSSL 3.5.0: %v", err)
	}
	if err := requireOpenSSL35("OpenSSL 3.4.9 11 Feb 2025"); err == nil {
		t.Fatal("requireOpenSSL35 should reject OpenSSL 3.4")
	}
}

func TestOpenSSLPQSignerGeneratesSignsAndVerifies(t *testing.T) {
	signer := NewOpenSSLPQSigner("openssl", DefaultPQSignatureAlgorithm)
	if err := signer.CheckSupport(); err != nil {
		t.Skipf("OpenSSL native %s support is unavailable: %v", DefaultPQSignatureAlgorithm, err)
	}

	tempDir := t.TempDir()
	manifestPath := filepath.Join(tempDir, "snapshot-hashes.txt")
	privateKeyPath := filepath.Join(tempDir, "sphincs.key")
	publicKeyPath := filepath.Join(tempDir, "sphincs.pub")
	signaturePath := filepath.Join(tempDir, "snapshot-hashes.txt.sphincs")

	if err := os.WriteFile(manifestPath, []byte("test manifest\n"), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	if err := signer.GenerateKeyPair(privateKeyPath, publicKeyPath, false); err != nil {
		t.Fatalf("GenerateKeyPair returned error: %v", err)
	}
	if err := signer.SignManifest(manifestPath, privateKeyPath, signaturePath, false); err != nil {
		t.Fatalf("SignManifest returned error: %v", err)
	}
	if err := signer.VerifyManifest(manifestPath, publicKeyPath, signaturePath); err != nil {
		t.Fatalf("VerifyManifest returned error: %v", err)
	}

	signatureFile, err := os.Open(signaturePath)
	if err != nil {
		t.Fatalf("open signature: %v", err)
	}
	defer signatureFile.Close()
	envelope, err := ReadPQSignatureEnvelope(signatureFile)
	if err != nil {
		t.Fatalf("ReadPQSignatureEnvelope returned error: %v", err)
	}
	if envelope.Algorithm != DefaultPQSignatureAlgorithm {
		t.Fatalf("Algorithm = %q, want %q", envelope.Algorithm, DefaultPQSignatureAlgorithm)
	}
	if envelope.SignedArtifact != "snapshot-hashes.txt" {
		t.Fatalf("SignedArtifact = %q, want snapshot-hashes.txt", envelope.SignedArtifact)
	}
	if len(envelope.DetachedSignatureData) == 0 {
		t.Fatal("detached signature is empty")
	}
}

func mustGenerateEntity(t *testing.T) *openpgp.Entity {
	t.Helper()

	entity, err := openpgp.NewEntity("AAMHS Test", "Manifest Signer", "test@example.com", &packet.Config{})
	if err != nil {
		t.Fatalf("generate entity: %v", err)
	}
	return entity
}

func armorPrivateKey(t *testing.T, entity *openpgp.Entity) string {
	t.Helper()

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
