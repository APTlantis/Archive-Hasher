package aamhs

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestComputeArtifactHashesGolden(t *testing.T) {
	tempDir := t.TempDir()
	artifactPath := filepath.Join(tempDir, "fixture.tar.zst")
	content := []byte("Aptlantis archive fixture\nLine two.\n")
	if err := os.WriteFile(artifactPath, content, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	hashes, size, err := ComputeArtifactHashes(artifactPath, HashOptions{})
	if err != nil {
		t.Fatalf("ComputeArtifactHashes returned error: %v", err)
	}

	if size != int64(len(content)) {
		t.Fatalf("size = %d, want %d", size, len(content))
	}

	expected := Hashes{
		SHA512:        "c2d0959b3f1258b12ec095c6e38ee2fd7d8341261fc633b46f11b44209d83e803fd2d70dbc5330aed97fe03763dc8ad2ea225aa403c6aca4ab3835b9c0b30f2d",
		SHA3_512:      "8f8a08eecfa7e54f1c9b41fa7fd0a4d534d8d6395df34324dca5ce872eb5eefc715a31b806050a2560179408df7c8f6ac1f808b6c6e0e601bc78e18841cb28e8",
		SHAKE256_512:  "946c337b10297304b27af4d201d475ae750e0ddc782f103f82f9931abddaa2f837c3d4d7dfed974dc40e338beb1a19cbde912ecf94164ea5b3ce41b50233cb97",
		SHAKE256_1024: "946c337b10297304b27af4d201d475ae750e0ddc782f103f82f9931abddaa2f837c3d4d7dfed974dc40e338beb1a19cbde912ecf94164ea5b3ce41b50233cb97e5c0b6117c5a6bddbd9a90241b43183ac887c5b9fa46295c29a512afe06b3c83250d2638478020839d09dc5a563a6b8ec0b7bc757de32a7815d6ef76c770d0a9",
		K12_512:       "e0c738dce32fffea3fcb8049762a174401bf24663a668448f07edff5430edbfe017eb1e1d83cfe814ccb6a154082da7e22467ed2ffa6e7fa1936c422c535e1b0",
		BLAKE3_512:    "6e3051a7d9e694a6c25c072ef89a880e4852e7bec042149a897ecbf6033110cfeaa40994c16ac3555d9d1908b5479d4719f0a882742019e7a0594b354d48fdd5",
		BLAKE2bp_512:  "a611ad931fc938d9ca899393f86c03cebd8dcb50e0962edc47141f51c6f2e2f33f470050f8db56cacaefab9b44df1012e7f56d3bc83b1c52fc7befedb348c5c4",
		CRC32:         "68d7b776",
	}

	if hashes != expected {
		t.Fatalf("hash mismatch:\n got  %#v\n want %#v", hashes, expected)
	}
}

func TestRenderManifestCanonicalOutput(t *testing.T) {
	meta := ManifestMetadata{
		SnapshotName:      "python-1990-2025-snapshot",
		SnapshotFormat:    "tar.zst",
		SnapshotSizeBytes: 35,
		SnapshotDateUTC:   time.Date(2025, 12, 3, 17, 42, 0, 0, time.UTC),
	}

	hashes := Hashes{
		SHA512:        "sha512-value",
		SHA3_512:      "sha3-512-value",
		SHAKE256_512:  "shake256-512-value",
		SHAKE256_1024: "shake256-1024-value",
		K12_512:       "k12-512-value",
		BLAKE3_512:    "blake3-512-value",
		BLAKE2bp_512:  "blake2bp-512-value",
		CRC32:         "crc32value",
	}

	manifest := RenderManifest(meta, hashes)
	expected := "" +
		"# Aptlantis Archive Multi-Hash Standard (AAMHS v2.0)\n" +
		"snapshot_name: python-1990-2025-snapshot\n" +
		"snapshot_format: tar.zst\n" +
		"snapshot_size_bytes: 35\n" +
		"snapshot_date_utc: 2025-12-03T17:42:00Z\n" +
		"schema_version: 2.0\n" +
		"hash_profile: pq-balanced-8\n" +
		"hash_encoding: hex\n" +
		"\n" +
		"[Hashes]\n" +
		"SHA-512:         sha512-value\n" +
		"SHA3-512:        sha3-512-value\n" +
		"SHAKE256-512:    shake256-512-value\n" +
		"SHAKE256-1024:   shake256-1024-value\n" +
		"K12-512:         k12-512-value\n" +
		"BLAKE3-512:      blake3-512-value\n" +
		"BLAKE2bp-512:    blake2bp-512-value\n" +
		"CRC32:           crc32value\n" +
		"\n" +
		"[Signatures]\n" +
		"PGP-Signature:   snapshot-hashes.txt.asc\n" +
		"PQ-Signature:    snapshot-hashes.txt.sphincs\n" +
		"\n" +
		"[Notes]\n" +
		"Generated-By: AAMHS Archive Hasher v2.0\n" +
		"Documentation: https://aptlantis.net/aamhs\n"

	if manifest != expected {
		t.Fatalf("manifest mismatch:\n%s", manifest)
	}
	if bytes.Contains([]byte(manifest), []byte("\r")) {
		t.Fatal("manifest must use LF line endings only")
	}
}

func TestWriteManifestOverwriteProtection(t *testing.T) {
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "snapshot-hashes.txt")
	if err := os.WriteFile(outputPath, []byte("existing"), 0o644); err != nil {
		t.Fatalf("seed manifest: %v", err)
	}

	err := WriteManifest(outputPath, ManifestMetadata{
		SnapshotName:      "fixture",
		SnapshotFormat:    "zip",
		SnapshotSizeBytes: 1,
		SnapshotDateUTC:   time.Unix(0, 0).UTC(),
	}, Hashes{}, false)
	if err == nil {
		t.Fatal("WriteManifest should fail when overwrite is false")
	}
}

func TestComputeArtifactHashesLargeStreaming(t *testing.T) {
	tempDir := t.TempDir()
	artifactPath := filepath.Join(tempDir, "large.tar")

	var content bytes.Buffer
	chunk := bytes.Repeat([]byte("abcd1234"), 1024)
	for i := 0; i < 2048; i++ {
		content.Write(chunk)
	}
	if err := os.WriteFile(artifactPath, content.Bytes(), 0o644); err != nil {
		t.Fatalf("write large fixture: %v", err)
	}

	progressCalls := 0
	hashes, size, err := ComputeArtifactHashes(artifactPath, HashOptions{
		ChunkSize:        4096,
		ProgressInterval: time.Nanosecond,
		Progress: func(Progress) {
			progressCalls++
		},
	})
	if err != nil {
		t.Fatalf("ComputeArtifactHashes returned error: %v", err)
	}

	if size != int64(content.Len()) {
		t.Fatalf("size = %d, want %d", size, content.Len())
	}
	if progressCalls == 0 {
		t.Fatal("expected at least one progress callback")
	}
	if hashes.K12_512 == "" || hashes.BLAKE3_512 == "" || hashes.SHAKE256_1024 == "" {
		t.Fatal("expected required hashes to be populated")
	}
}

func TestBLAKE2bpGoldenEmpty(t *testing.T) {
	got := blake2bpHex(t, nil)
	want := "b5ef811a8038f70b628fa8b294daae7492b1ebe343a80eaabbf1f6ae664dd67b9d90b0120791eab81dc96985f28849f6a305186a85501b405114bfa678df9380"
	if got != want {
		t.Fatalf("BLAKE2bp empty mismatch:\n got  %s\n want %s", got, want)
	}
}

func TestBLAKE2bpGoldenMultiStripe(t *testing.T) {
	input := make([]byte, 1000)
	for i := range input {
		input[i] = byte(i)
	}

	got := blake2bpHex(t, input)
	want := "1ce5b8d6f6fcc89fcb6ed29f12796cc210a03f4763e528cb2c0e1b4b1255d6ae86c79332529f6368d0bcfe9d316a5f999a53af47a8f0ec4412ce19156bbafd04"
	if got != want {
		t.Fatalf("BLAKE2bp multi-stripe mismatch:\n got  %s\n want %s", got, want)
	}

	fragmented, err := newBLAKE2bpHasher()
	if err != nil {
		t.Fatalf("newBLAKE2bpHasher: %v", err)
	}
	_, _ = fragmented.Write(input[:7])
	_, _ = fragmented.Write(input[7:301])
	_, _ = fragmented.Write(input[301:])
	if fragmentedGot := hex.EncodeToString(fragmented.Sum(nil)); fragmentedGot != got {
		t.Fatalf("fragmented BLAKE2bp mismatch:\n got  %s\n want %s", fragmentedGot, got)
	}
}

func blake2bpHex(t *testing.T, input []byte) string {
	t.Helper()

	hasher, err := newBLAKE2bpHasher()
	if err != nil {
		t.Fatalf("newBLAKE2bpHasher: %v", err)
	}
	_, _ = hasher.Write(input)
	return hex.EncodeToString(hasher.Sum(nil))
}
