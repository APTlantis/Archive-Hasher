package aamhs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	SchemaVersion     = "2.0"
	DocumentationURL  = "https://aptlantis.net/aamhs"
	GeneratedBy       = "AAMHS Archive Hasher v2.0"
	DefaultBaseName   = "snapshot-hashes"
	DefaultOutputMode = 0o644
)

type ManifestMetadata struct {
	SnapshotName      string
	SnapshotFormat    string
	SnapshotSizeBytes int64
	SnapshotDateUTC   time.Time
	SchemaVersion     string
	GeneratedBy       string
	DocumentationURL  string
}

func RenderManifest(meta ManifestMetadata, hashes Hashes) string {
	schemaVersion := meta.SchemaVersion
	if schemaVersion == "" {
		schemaVersion = SchemaVersion
	}

	generatedBy := meta.GeneratedBy
	if generatedBy == "" {
		generatedBy = GeneratedBy
	}

	documentationURL := meta.DocumentationURL
	if documentationURL == "" {
		documentationURL = DocumentationURL
	}

	lines := []string{
		"# Aptlantis Archive Multi-Hash Standard (AAMHS v2.0)",
		fmt.Sprintf("snapshot_name: %s", meta.SnapshotName),
		fmt.Sprintf("snapshot_format: %s", meta.SnapshotFormat),
		fmt.Sprintf("snapshot_size_bytes: %d", meta.SnapshotSizeBytes),
		fmt.Sprintf("snapshot_date_utc: %s", meta.SnapshotDateUTC.UTC().Format(time.RFC3339)),
		fmt.Sprintf("schema_version: %s", schemaVersion),
		"",
		"[Hashes]",
		fmt.Sprintf("%-15s %s", "SHA-512:", hashes.SHA512),
		fmt.Sprintf("%-15s %s", "SHA3-512:", hashes.SHA3_512),
		fmt.Sprintf("%-15s %s", "SHAKE256-512:", hashes.SHAKE256_512),
		fmt.Sprintf("%-15s %s", "SHAKE256-1024:", hashes.SHAKE256_1024),
		fmt.Sprintf("%-15s %s", "K12:", hashes.K12),
		fmt.Sprintf("%-15s %s", "BLAKE3-512:", hashes.BLAKE3_512),
		fmt.Sprintf("%-15s %s", "BLAKE2bp:", hashes.BLAKE2bp),
		fmt.Sprintf("%-15s %s", "CRC32:", hashes.CRC32),
		"",
		"[Notes]",
		fmt.Sprintf("Generated-By: %s", generatedBy),
		fmt.Sprintf("Documentation: %s", documentationURL),
	}

	return strings.Join(lines, "\n") + "\n"
}

func WriteManifest(outputPath string, meta ManifestMetadata, hashes Hashes, overwrite bool) error {
	if err := EnsureCanWrite(outputPath, overwrite); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	if err := os.WriteFile(outputPath, []byte(RenderManifest(meta, hashes)), DefaultOutputMode); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}

	return nil
}

func ResolveOutputDir(targetDir, artifactPath string) string {
	if strings.TrimSpace(targetDir) != "" {
		return targetDir
	}
	return filepath.Join(filepath.Dir(artifactPath), filepath.Base(artifactPath)+".aamhs")
}

func EnsureCanWrite(path string, overwrite bool) error {
	if overwrite {
		return nil
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists (use --overwrite to replace it)", path)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("check output path: %w", err)
	}
	return nil
}
