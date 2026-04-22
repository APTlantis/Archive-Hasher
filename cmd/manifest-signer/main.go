package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/APTlantis/Mirror-Rust-Crates/archive-hasher/aamhs"
)

func main() {
	var (
		keyPath       string
		outputPath    string
		passphraseEnv string
		overwrite     bool
		verbose       bool
	)

	flag.StringVar(&keyPath, "key", "", "Path to an ASCII-armored PGP private key")
	flag.StringVar(&outputPath, "output", "", "Output path for the detached ASCII-armored signature (default: <manifest>.asc)")
	flag.StringVar(&passphraseEnv, "passphrase-env", "", "Environment variable that stores the private key passphrase")
	flag.BoolVar(&overwrite, "overwrite", false, "Overwrite an existing detached signature if present")
	flag.BoolVar(&verbose, "verbose", false, "Print progress information")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: manifest-signer [flags] <manifest>")
		flag.PrintDefaults()
		os.Exit(2)
	}
	if keyPath == "" {
		fmt.Fprintln(os.Stderr, "[error] --key is required")
		os.Exit(2)
	}

	manifestPath, err := filepath.Abs(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] resolve manifest path: %v\n", err)
		os.Exit(1)
	}
	if _, err := os.Stat(manifestPath); err != nil {
		fmt.Fprintf(os.Stderr, "[error] stat manifest: %v\n", err)
		os.Exit(1)
	}

	keyPath, err = filepath.Abs(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] resolve key path: %v\n", err)
		os.Exit(1)
	}

	if outputPath == "" {
		outputPath = aamhs.DefaultSignaturePath(manifestPath)
	} else {
		outputPath, err = filepath.Abs(outputPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[error] resolve output path: %v\n", err)
			os.Exit(1)
		}
	}

	passphrase, err := aamhs.PassphraseFromEnv(passphraseEnv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] load passphrase: %v\n", err)
		os.Exit(1)
	}

	if err := aamhs.SignManifestArmored(manifestPath, keyPath, outputPath, overwrite, passphrase); err != nil {
		fmt.Fprintf(os.Stderr, "[error] sign manifest: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "[ok] wrote %s\n", outputPath)
	}
}
