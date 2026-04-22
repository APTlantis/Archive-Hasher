package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/APTlantis/Mirror-Rust-Crates/archive-hasher/aamhs"
)

func main() {
	var (
		snapshotName     string
		snapshotFormat   string
		snapshotDatetime string
		outputDir        string
		outputBaseName   string
		overwrite        bool
		verbose          bool
	)

	flag.StringVar(&snapshotName, "snapshot-name", "", "Friendly snapshot name (default: derived from artifact name)")
	flag.StringVar(&snapshotFormat, "format", "", "Snapshot format override (default: derived from extension)")
	flag.StringVar(&snapshotDatetime, "snapshot-datetime", "", "UTC datetime in RFC3339 format (default: artifact modified time)")
	flag.StringVar(&outputDir, "output-dir", "", "Directory for generated outputs (default: <artifact>.aamhs beside the artifact)")
	flag.StringVar(&outputBaseName, "output-basename", aamhs.DefaultBaseName, "Base filename without extension for generated outputs")
	flag.BoolVar(&overwrite, "overwrite", false, "Overwrite existing outputs if present")
	flag.BoolVar(&verbose, "verbose", false, "Print progress information")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: archive-hasher [flags] <artifact>")
		flag.PrintDefaults()
		os.Exit(2)
	}

	artifactPath, err := filepath.Abs(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] resolve artifact path: %v\n", err)
		os.Exit(1)
	}

	info, err := os.Stat(artifactPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] stat artifact: %v\n", err)
		os.Exit(1)
	}
	if !info.Mode().IsRegular() {
		fmt.Fprintf(os.Stderr, "[error] artifact must be a regular file: %s\n", artifactPath)
		os.Exit(1)
	}

	snapshotTime := info.ModTime().UTC()
	if snapshotDatetime != "" {
		snapshotTime, err = time.Parse(time.RFC3339, snapshotDatetime)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[error] parse --snapshot-datetime: %v\n", err)
			os.Exit(1)
		}
	}

	if snapshotName == "" {
		snapshotName = aamhs.DefaultSnapshotName(artifactPath)
	}
	if snapshotFormat == "" {
		snapshotFormat = aamhs.GuessFormat(artifactPath)
	}

	finalOutputDir := aamhs.ResolveOutputDir(outputDir, artifactPath)
	manifestPath := filepath.Join(finalOutputDir, outputBaseName+".txt")

	var progress func(aamhs.Progress)
	if verbose {
		progress = func(p aamhs.Progress) {
			elapsed := time.Since(p.StartedAt)
			speed := float64(p.BytesProcessed)
			if elapsed > 0 {
				speed = speed / elapsed.Seconds()
			}

			percent := 100.0
			if p.TotalBytes > 0 {
				percent = float64(p.BytesProcessed) * 100 / float64(p.TotalBytes)
			}

			fmt.Fprintf(
				os.Stderr,
				"\r[hash] %s / %s (%.1f%%) | %s/s",
				formatBytes(p.BytesProcessed),
				formatBytes(p.TotalBytes),
				percent,
				formatBytes(int64(speed)),
			)
			if p.BytesProcessed == p.TotalBytes {
				fmt.Fprintln(os.Stderr)
			}
		}
	}

	hashes, totalSize, err := aamhs.ComputeArtifactHashes(artifactPath, aamhs.HashOptions{
		Progress: progress,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] hash artifact: %v\n", err)
		os.Exit(1)
	}

	err = aamhs.WriteManifest(manifestPath, aamhs.ManifestMetadata{
		SnapshotName:      snapshotName,
		SnapshotFormat:    snapshotFormat,
		SnapshotSizeBytes: totalSize,
		SnapshotDateUTC:   snapshotTime,
	}, hashes, overwrite)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] write manifest: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "[ok] wrote %s\n", manifestPath)
	}
}

func formatBytes(size int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	value := float64(size)
	for _, unit := range units {
		if value < 1024 || unit == units[len(units)-1] {
			return fmt.Sprintf("%.1f %s", value, unit)
		}
		value /= 1024
	}
	return fmt.Sprintf("%.1f PB", value)
}
