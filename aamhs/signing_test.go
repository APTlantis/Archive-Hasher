package aamhs

import (
	"bytes"
	"os"
	"path/filepath"
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
