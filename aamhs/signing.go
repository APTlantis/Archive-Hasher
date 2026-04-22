package aamhs

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func SignManifestArmored(manifestPath, keyPath, outputPath string, overwrite bool, passphrase []byte) error {
	if err := EnsureCanWrite(outputPath, overwrite); err != nil {
		return err
	}

	entity, err := LoadPrivateEntity(keyPath, passphrase)
	if err != nil {
		return err
	}

	manifestFile, err := os.Open(manifestPath)
	if err != nil {
		return fmt.Errorf("open manifest: %w", err)
	}
	defer manifestFile.Close()

	signatureFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create signature: %w", err)
	}
	defer signatureFile.Close()

	config := &packet.Config{DefaultHash: crypto.SHA256}
	if err := openpgp.ArmoredDetachSign(signatureFile, entity, manifestFile, config); err != nil {
		return fmt.Errorf("sign manifest: %w", err)
	}

	return nil
}

func LoadPrivateEntity(path string, passphrase []byte) (*openpgp.Entity, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}

	block, err := armor.Decode(bytes.NewReader(keyData))
	if err != nil {
		return nil, fmt.Errorf("decode armored key: %w", err)
	}

	if block.Type != openpgp.PrivateKeyType {
		return nil, fmt.Errorf("expected armored private key, got %q", block.Type)
	}

	entity, err := openpgp.ReadEntity(packet.NewReader(block.Body))
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	if entity.PrivateKey == nil {
		return nil, errors.New("private key is missing signing material")
	}

	if entity.PrivateKey.Encrypted {
		if len(passphrase) == 0 {
			return nil, errors.New("private key is encrypted; provide a passphrase")
		}
		if err := entity.DecryptPrivateKeys(passphrase); err != nil {
			return nil, fmt.Errorf("decrypt private key: %w", err)
		}
	}

	return entity, nil
}

func DefaultSignaturePath(manifestPath string) string {
	return manifestPath + ".asc"
}

func PassphraseFromEnv(name string) ([]byte, error) {
	if strings.TrimSpace(name) == "" {
		return nil, nil
	}

	value, ok := os.LookupEnv(name)
	if !ok {
		return nil, fmt.Errorf("environment variable %s is not set", name)
	}

	return []byte(value), nil
}
