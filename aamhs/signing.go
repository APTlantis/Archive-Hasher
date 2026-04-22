package aamhs

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

const (
	DefaultPQSignatureAlgorithm = "SLH-DSA-SHAKE-256s"
	PQSignatureEncoding         = "base64"
	pqSignatureArmorType        = "AAMHS PQ SIGNATURE"
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

type OpenSSLPQSigner struct {
	Command   string
	Algorithm string
}

type PQSignatureEnvelope struct {
	Algorithm             string
	SignatureEncoding     string
	SignedArtifact        string
	PublicKeyFingerprint  string
	DetachedSignatureData []byte
}

func NewOpenSSLPQSigner(command, algorithm string) OpenSSLPQSigner {
	if strings.TrimSpace(command) == "" {
		command = "openssl"
	}
	if strings.TrimSpace(algorithm) == "" {
		algorithm = DefaultPQSignatureAlgorithm
	}
	return OpenSSLPQSigner{
		Command:   command,
		Algorithm: algorithm,
	}
}

func (s OpenSSLPQSigner) SignManifest(manifestPath, keyPath, outputPath string, overwrite bool) error {
	if err := EnsureCanWrite(outputPath, overwrite); err != nil {
		return err
	}
	if err := s.CheckSupport(); err != nil {
		return err
	}

	tempDir, err := os.MkdirTemp("", "aamhs-pq-sign-*")
	if err != nil {
		return fmt.Errorf("create temporary signature directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	rawSignaturePath := filepath.Join(tempDir, "signature.raw")
	if err := s.run("sign manifest with "+s.Algorithm, "pkeyutl", "-sign", "-in", manifestPath, "-inkey", keyPath, "-out", rawSignaturePath); err != nil {
		return err
	}

	rawSignature, err := os.ReadFile(rawSignaturePath)
	if err != nil {
		return fmt.Errorf("read raw PQ signature: %w", err)
	}

	fingerprint, err := s.PublicKeyFingerprint(keyPath)
	if err != nil {
		return err
	}

	envelope := PQSignatureEnvelope{
		Algorithm:             s.Algorithm,
		SignatureEncoding:     PQSignatureEncoding,
		SignedArtifact:        filepath.Base(manifestPath),
		PublicKeyFingerprint:  fingerprint,
		DetachedSignatureData: rawSignature,
	}

	signatureFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create PQ signature: %w", err)
	}
	defer signatureFile.Close()

	if err := WritePQSignatureEnvelope(signatureFile, envelope); err != nil {
		return fmt.Errorf("write PQ signature envelope: %w", err)
	}

	return nil
}

func (s OpenSSLPQSigner) VerifyManifest(manifestPath, publicKeyPath, envelopePath string) error {
	if err := s.CheckSupport(); err != nil {
		return err
	}

	envelopeFile, err := os.Open(envelopePath)
	if err != nil {
		return fmt.Errorf("open PQ signature envelope: %w", err)
	}
	defer envelopeFile.Close()

	envelope, err := ReadPQSignatureEnvelope(envelopeFile)
	if err != nil {
		return err
	}
	if envelope.Algorithm != s.Algorithm {
		return fmt.Errorf("PQ signature algorithm %q does not match expected %q", envelope.Algorithm, s.Algorithm)
	}

	tempDir, err := os.MkdirTemp("", "aamhs-pq-verify-*")
	if err != nil {
		return fmt.Errorf("create temporary verification directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	rawSignaturePath := filepath.Join(tempDir, "signature.raw")
	if err := os.WriteFile(rawSignaturePath, envelope.DetachedSignatureData, 0o600); err != nil {
		return fmt.Errorf("write raw PQ signature: %w", err)
	}

	if err := s.run("verify manifest with "+s.Algorithm, "pkeyutl", "-verify", "-in", manifestPath, "-inkey", publicKeyPath, "-pubin", "-sigfile", rawSignaturePath); err != nil {
		return err
	}

	return nil
}

func (s OpenSSLPQSigner) GenerateKeyPair(privateKeyPath, publicKeyPath string, overwrite bool) error {
	if err := EnsureCanWrite(privateKeyPath, overwrite); err != nil {
		return err
	}
	if err := EnsureCanWrite(publicKeyPath, overwrite); err != nil {
		return err
	}
	if err := s.CheckSupport(); err != nil {
		return err
	}
	if err := s.run("generate "+s.Algorithm+" private key", "genpkey", "-algorithm", s.Algorithm, "-out", privateKeyPath); err != nil {
		return err
	}
	if err := s.run("extract "+s.Algorithm+" public key", "pkey", "-in", privateKeyPath, "-pubout", "-out", publicKeyPath); err != nil {
		return err
	}
	return nil
}

func (s OpenSSLPQSigner) PublicKeyFingerprint(keyPath string) (string, error) {
	output, err := s.output("extract public key fingerprint", "pkey", "-in", keyPath, "-pubout", "-outform", "DER")
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(output)
	return hex.EncodeToString(sum[:]), nil
}

func (s OpenSSLPQSigner) CheckSupport() error {
	if _, err := exec.LookPath(s.Command); err != nil {
		return fmt.Errorf("openssl command %q is not available: %w", s.Command, err)
	}

	versionOutput, err := s.output("check OpenSSL version", "version")
	if err != nil {
		return err
	}
	if err := requireOpenSSL35(string(versionOutput)); err != nil {
		return err
	}

	signatures, sigErr := s.output("list OpenSSL signature algorithms", "list", "-signature-algorithms")
	publicKeys, keyErr := s.output("list OpenSSL public key algorithms", "list", "-public-key-algorithms")
	supported := bytes.Contains(signatures, []byte(s.Algorithm)) || bytes.Contains(publicKeys, []byte(s.Algorithm))
	if !supported {
		if sigErr != nil && keyErr != nil {
			return fmt.Errorf("check OpenSSL support for %s: %v; %v", s.Algorithm, sigErr, keyErr)
		}
		return fmt.Errorf("OpenSSL does not report support for %s", s.Algorithm)
	}

	return nil
}

func WritePQSignatureEnvelope(w io.Writer, envelope PQSignatureEnvelope) error {
	if envelope.Algorithm == "" {
		envelope.Algorithm = DefaultPQSignatureAlgorithm
	}
	if envelope.SignatureEncoding == "" {
		envelope.SignatureEncoding = PQSignatureEncoding
	}
	if envelope.SignatureEncoding != PQSignatureEncoding {
		return fmt.Errorf("unsupported PQ signature encoding %q", envelope.SignatureEncoding)
	}
	if envelope.SignedArtifact == "" {
		return errors.New("signed artifact is required")
	}
	if envelope.PublicKeyFingerprint == "" {
		return errors.New("public key fingerprint is required")
	}
	if len(envelope.DetachedSignatureData) == 0 {
		return errors.New("detached signature data is required")
	}

	encodedSignature := base64.StdEncoding.EncodeToString(envelope.DetachedSignatureData)
	_, err := fmt.Fprintf(
		w,
		"-----BEGIN %s-----\nalgorithm: %s\nsignature_encoding: %s\nsigned_artifact: %s\npublic_key_fingerprint_sha256: %s\n\n%s\n-----END %s-----\n",
		pqSignatureArmorType,
		envelope.Algorithm,
		envelope.SignatureEncoding,
		envelope.SignedArtifact,
		envelope.PublicKeyFingerprint,
		encodedSignature,
		pqSignatureArmorType,
	)
	return err
}

func RenderPQSignatureEnvelope(envelope PQSignatureEnvelope) (string, error) {
	var rendered strings.Builder
	if err := WritePQSignatureEnvelope(&rendered, envelope); err != nil {
		return "", err
	}
	return rendered.String(), nil
}

func ReadPQSignatureEnvelope(r io.Reader) (PQSignatureEnvelope, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return PQSignatureEnvelope{}, fmt.Errorf("read PQ signature envelope: %w", err)
	}

	text := strings.TrimSpace(string(data))
	begin := "-----BEGIN " + pqSignatureArmorType + "-----"
	end := "-----END " + pqSignatureArmorType + "-----"
	if !strings.HasPrefix(text, begin) || !strings.HasSuffix(text, end) {
		return PQSignatureEnvelope{}, errors.New("invalid PQ signature envelope armor")
	}

	body := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(text, begin), end))
	parts := strings.SplitN(body, "\n\n", 2)
	if len(parts) != 2 {
		return PQSignatureEnvelope{}, errors.New("invalid PQ signature envelope body")
	}

	headers := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(parts[0]), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return PQSignatureEnvelope{}, fmt.Errorf("invalid PQ signature header %q", line)
		}
		headers[canonicalPQEnvelopeHeaderName(name)] = strings.TrimSpace(value)
	}

	signatureData, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(parts[1]), ""))
	if err != nil {
		return PQSignatureEnvelope{}, fmt.Errorf("decode PQ signature: %w", err)
	}

	envelope := PQSignatureEnvelope{
		Algorithm:             headers["algorithm"],
		SignatureEncoding:     headers["signature_encoding"],
		SignedArtifact:        headers["signed_artifact"],
		PublicKeyFingerprint:  headers["public_key_fingerprint_sha256"],
		DetachedSignatureData: signatureData,
	}
	if envelope.SignatureEncoding != PQSignatureEncoding {
		return PQSignatureEnvelope{}, fmt.Errorf("unsupported PQ signature encoding %q", envelope.SignatureEncoding)
	}
	if envelope.Algorithm == "" || envelope.SignedArtifact == "" || envelope.PublicKeyFingerprint == "" || len(envelope.DetachedSignatureData) == 0 {
		return PQSignatureEnvelope{}, errors.New("PQ signature envelope is missing required fields")
	}
	return envelope, nil
}

func canonicalPQEnvelopeHeaderName(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "algorithm":
		return "algorithm"
	case "signature-encoding", "signature_encoding":
		return "signature_encoding"
	case "signed-artifact", "signed_artifact":
		return "signed_artifact"
	case "public-key-fingerprint-sha256", "public_key_fingerprint_sha256":
		return "public_key_fingerprint_sha256"
	default:
		return strings.ToLower(strings.TrimSpace(name))
	}
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

func DefaultPQSignaturePath(manifestPath string) string {
	return manifestPath + ".sphincs"
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

func (s OpenSSLPQSigner) output(action string, args ...string) ([]byte, error) {
	command := exec.Command(s.Command, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %s", action, err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func (s OpenSSLPQSigner) run(action string, args ...string) error {
	_, err := s.output(action, args...)
	return err
}

func requireOpenSSL35(versionOutput string) error {
	fields := strings.Fields(versionOutput)
	if len(fields) < 2 || !strings.EqualFold(fields[0], "OpenSSL") {
		return fmt.Errorf("could not parse OpenSSL version from %q", strings.TrimSpace(versionOutput))
	}

	re := regexp.MustCompile(`^(\d+)\.(\d+)`)
	match := re.FindStringSubmatch(fields[1])
	if len(match) != 3 {
		return fmt.Errorf("could not parse OpenSSL version number from %q", strings.TrimSpace(versionOutput))
	}

	major, err := strconv.Atoi(match[1])
	if err != nil {
		return fmt.Errorf("parse OpenSSL major version: %w", err)
	}
	minor, err := strconv.Atoi(match[2])
	if err != nil {
		return fmt.Errorf("parse OpenSSL minor version: %w", err)
	}

	if major < 3 || (major == 3 && minor < 5) {
		return fmt.Errorf("OpenSSL 3.5+ is required for native SLH-DSA support, got %s", strings.TrimSpace(versionOutput))
	}
	return nil
}
