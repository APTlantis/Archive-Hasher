package aamhs

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cloudflare/circl/xof/k12"
	"golang.org/x/crypto/sha3"
	"lukechampine.com/blake3"
)

const (
	DefaultChunkSize = 4 * 1024 * 1024
)

var knownArchiveSuffixes = []string{
	".tar.zst",
	".tar.xz",
	".tar.gz",
	".tar.bz2",
	".tar",
	".zip",
	".torrent",
}

type Hashes struct {
	SHA512        string
	SHA3_512      string
	SHAKE256_512  string
	SHAKE256_1024 string
	K12_512       string
	BLAKE3_512    string
	BLAKE2bp_512  string
	CRC32         string
}

type Progress struct {
	BytesProcessed int64
	TotalBytes     int64
	StartedAt      time.Time
}

type HashOptions struct {
	ChunkSize        int
	ProgressInterval time.Duration
	Progress         func(Progress)
}

func ComputeArtifactHashes(path string, options HashOptions) (Hashes, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return Hashes{}, 0, fmt.Errorf("open artifact: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return Hashes{}, 0, fmt.Errorf("stat artifact: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Hashes{}, 0, fmt.Errorf("artifact must be a regular file: %s", path)
	}

	chunkSize := options.ChunkSize
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}

	sha512Hasher := sha512.New()
	sha3_512Hasher := sha3.New512()
	shake256_512Hasher := sha3.NewShake256()
	shake256_1024Hasher := sha3.NewShake256()
	blake3_512Hasher := blake3.New(64, nil)
	blake2bpHasher, err := newBLAKE2bpHasher()
	if err != nil {
		return Hashes{}, 0, fmt.Errorf("initialize BLAKE2bp hash: %w", err)
	}
	k12Hasher := k12.NewDraft10([]byte(""))
	crc32Hasher := crc32.NewIEEE()

	buffer := make([]byte, chunkSize)
	var total int64
	startedAt := time.Now()
	lastProgress := startedAt

	for {
		readSize, readErr := file.Read(buffer)
		if readSize > 0 {
			chunk := buffer[:readSize]
			total += int64(readSize)

			_, _ = sha512Hasher.Write(chunk)
			_, _ = sha3_512Hasher.Write(chunk)
			_, _ = shake256_512Hasher.Write(chunk)
			_, _ = shake256_1024Hasher.Write(chunk)
			_, _ = blake3_512Hasher.Write(chunk)
			_, _ = blake2bpHasher.Write(chunk)
			_, _ = crc32Hasher.Write(chunk)
			_, _ = k12Hasher.Write(chunk)

			if options.Progress != nil && time.Since(lastProgress) >= options.progressIntervalOrDefault() {
				options.Progress(Progress{
					BytesProcessed: total,
					TotalBytes:     info.Size(),
					StartedAt:      startedAt,
				})
				lastProgress = time.Now()
			}
		}

		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return Hashes{}, 0, fmt.Errorf("read artifact: %w", readErr)
		}
	}

	if options.Progress != nil {
		options.Progress(Progress{
			BytesProcessed: total,
			TotalBytes:     info.Size(),
			StartedAt:      startedAt,
		})
	}

	k12Digest := make([]byte, 64)
	if _, err := k12Hasher.Read(k12Digest); err != nil {
		return Hashes{}, 0, fmt.Errorf("finalize K12-512 hash: %w", err)
	}

	shake256_512Digest := make([]byte, 64)
	if _, err := shake256_512Hasher.Read(shake256_512Digest); err != nil {
		return Hashes{}, 0, fmt.Errorf("finalize SHAKE256-512 hash: %w", err)
	}

	shake256_1024Digest := make([]byte, 128)
	if _, err := shake256_1024Hasher.Read(shake256_1024Digest); err != nil {
		return Hashes{}, 0, fmt.Errorf("finalize SHAKE256-1024 hash: %w", err)
	}

	blake2bpDigest := blake2bpHasher.Sum(nil)

	return Hashes{
		SHA512:        hex.EncodeToString(sha512Hasher.Sum(nil)),
		SHA3_512:      hex.EncodeToString(sha3_512Hasher.Sum(nil)),
		SHAKE256_512:  hex.EncodeToString(shake256_512Digest),
		SHAKE256_1024: hex.EncodeToString(shake256_1024Digest),
		K12_512:       hex.EncodeToString(k12Digest),
		BLAKE3_512:    hex.EncodeToString(blake3_512Hasher.Sum(nil)),
		BLAKE2bp_512:  hex.EncodeToString(blake2bpDigest),
		CRC32:         fmt.Sprintf("%08x", crc32Hasher.Sum32()),
	}, total, nil
}

func (o HashOptions) progressIntervalOrDefault() time.Duration {
	if o.ProgressInterval <= 0 {
		return 500 * time.Millisecond
	}
	return o.ProgressInterval
}

func GuessFormat(path string) string {
	lowerName := strings.ToLower(filepath.Base(path))
	for _, suffix := range knownArchiveSuffixes {
		if strings.HasSuffix(lowerName, suffix) {
			return strings.TrimPrefix(suffix, ".")
		}
	}

	ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(lowerName)), ".")
	if ext == "" {
		return "bin"
	}
	return ext
}

func DefaultSnapshotName(path string) string {
	name := filepath.Base(path)
	lowerName := strings.ToLower(name)
	for _, suffix := range knownArchiveSuffixes {
		if strings.HasSuffix(lowerName, suffix) {
			return name[:len(name)-len(suffix)]
		}
	}

	ext := filepath.Ext(name)
	return strings.TrimSuffix(name, ext)
}
