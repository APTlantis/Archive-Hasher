package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/APTlantis/Mirror-Rust-Crates/archive-hasher/aamhs"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	var (
		keyPath       string
		outputPath    string
		pqKeyPath     string
		pqOutputPath  string
		opensslPath   string
		pqAlgorithm   string
		passphraseEnv string
		overwrite     bool
		verbose       bool
	)

	flags := flag.NewFlagSet("manifest-signer", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&keyPath, "key", "", "Path to an ASCII-armored PGP private key")
	flags.StringVar(&outputPath, "output", "", "Output path for the detached ASCII-armored signature (default: <manifest>.asc)")
	flags.StringVar(&pqKeyPath, "pq-key", "", "Path to an OpenSSL SLH-DSA private key for the PQ detached signature")
	flags.StringVar(&pqOutputPath, "pq-output", "", "Output path for the armored PQ signature envelope (default: <manifest>.sphincs)")
	flags.StringVar(&opensslPath, "openssl", "openssl", "OpenSSL command path for PQ signing")
	flags.StringVar(&pqAlgorithm, "pq-algorithm", aamhs.DefaultPQSignatureAlgorithm, "PQ signature algorithm")
	flags.StringVar(&passphraseEnv, "passphrase-env", "", "Environment variable that stores the PGP private key passphrase")
	flags.BoolVar(&overwrite, "overwrite", false, "Overwrite existing detached signatures if present")
	flags.BoolVar(&verbose, "verbose", false, "Print progress information")
	if err := flags.Parse(args); err != nil {
		return err
	}

	if flags.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: manifest-signer [flags] <manifest>")
		flags.PrintDefaults()
		return fmt.Errorf("invalid arguments")
	}
	if keyPath == "" {
		fmt.Fprintln(stderr, "[error] --key is required")
		return fmt.Errorf("--key is required")
	}

	manifestPath, err := filepath.Abs(flags.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "[error] resolve manifest path: %v\n", err)
		return err
	}
	if _, err := os.Stat(manifestPath); err != nil {
		fmt.Fprintf(stderr, "[error] stat manifest: %v\n", err)
		return err
	}

	keyPath, err = filepath.Abs(keyPath)
	if err != nil {
		fmt.Fprintf(stderr, "[error] resolve key path: %v\n", err)
		return err
	}

	if outputPath == "" {
		outputPath = aamhs.DefaultSignaturePath(manifestPath)
	} else {
		outputPath, err = filepath.Abs(outputPath)
		if err != nil {
			fmt.Fprintf(stderr, "[error] resolve output path: %v\n", err)
			return err
		}
	}

	if pqKeyPath != "" {
		pqKeyPath, err = filepath.Abs(pqKeyPath)
		if err != nil {
			fmt.Fprintf(stderr, "[error] resolve PQ key path: %v\n", err)
			return err
		}

		if pqOutputPath == "" {
			pqOutputPath = aamhs.DefaultPQSignaturePath(manifestPath)
		} else {
			pqOutputPath, err = filepath.Abs(pqOutputPath)
			if err != nil {
				fmt.Fprintf(stderr, "[error] resolve PQ output path: %v\n", err)
				return err
			}
		}
	}

	if strings.HasPrefix(opensslPath, "-") {
		err := fmt.Errorf("--openssl requires a command path, got %q", opensslPath)
		fmt.Fprintf(stderr, "[error] %v\n", err)
		return err
	}

	passphrase, err := aamhs.PassphraseFromEnv(passphraseEnv)
	if err != nil {
		fmt.Fprintf(stderr, "[error] load passphrase: %v\n", err)
		return err
	}

	if err := aamhs.EnsureCanWrite(outputPath, overwrite); err != nil {
		fmt.Fprintf(stderr, "[error] check PGP signature output: %v\n", err)
		return err
	}
	if pqKeyPath != "" {
		if err := aamhs.EnsureCanWrite(pqOutputPath, overwrite); err != nil {
			fmt.Fprintf(stderr, "[error] check PQ signature output: %v\n", err)
			return err
		}
	}

	if err := aamhs.SignManifestArmored(manifestPath, keyPath, outputPath, overwrite, passphrase); err != nil {
		fmt.Fprintf(stderr, "[error] sign manifest: %v\n", err)
		return err
	}

	if verbose {
		fmt.Fprintf(stderr, "[ok] wrote %s\n", outputPath)
	}

	if pqKeyPath != "" {
		pqSigner := aamhs.NewOpenSSLPQSigner(opensslPath, pqAlgorithm)
		if err := pqSigner.SignManifest(manifestPath, pqKeyPath, pqOutputPath, overwrite); err != nil {
			fmt.Fprintf(stderr, "[error] sign manifest with PQ key: %v\n", err)
			return err
		}
		if verbose {
			fmt.Fprintf(stderr, "[ok] wrote %s\n", pqOutputPath)
		}
	}

	_, _ = fmt.Fprint(stdout, "")
	return nil
}
