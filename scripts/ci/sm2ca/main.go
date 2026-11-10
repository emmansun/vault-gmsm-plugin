// Command sm2ca issues an SM2 certificate chain for a PEM encoded certificate
// request. The CI walkthrough uses it to stand in for the CA that signs the
// request the plugin produces, since the plugin itself only ever holds the key.
//
// Usage:
//
//	sm2ca -csr request.pem -out chain.pem [-days 365] [-ca-name "test ca"]
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/emmansun/vault-gmsm-plugin/internal/testca"
)

func main() {
	csrPath := flag.String("csr", "", "PEM encoded certificate request to sign")
	outPath := flag.String("out", "", "file the PEM chain is written to")
	days := flag.Int("days", 365, "validity of the issued certificates in days")
	caName := flag.String("ca-name", "gmsm integration test ca", "common name of the generated CA")
	flag.Parse()

	if err := run(*csrPath, *outPath, *days, *caName); err != nil {
		fmt.Fprintf(os.Stderr, "sm2ca: %v\n", err)
		os.Exit(1)
	}
}

func run(csrPath, outPath string, days int, caName string) error {
	if csrPath == "" || outPath == "" {
		return errors.New("both -csr and -out are required")
	}
	if days <= 0 {
		return errors.New("-days must be positive")
	}

	csrPEM, err := os.ReadFile(csrPath)
	if err != nil {
		return err
	}

	chainPEM, summary, err := testca.IssueChain(csrPEM, time.Duration(days)*24*time.Hour, caName)
	if err != nil {
		return err
	}

	if err := os.WriteFile(outPath, chainPEM, 0o600); err != nil {
		return err
	}

	fmt.Println(summary)

	return nil
}
