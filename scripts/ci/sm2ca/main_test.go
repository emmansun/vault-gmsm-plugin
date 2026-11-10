package main

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

// writeRequest files the PEM request the command is given, so the test does not
// depend on anything outside the module.
func writeRequest(t *testing.T, dir string) string {
	t.Helper()

	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not generate the request key: %v", err)
	}

	der, err := smx509.CreateCertificateRequest(rand.Reader, &smx509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "cli.internal"},
		DNSNames: []string{"cli.internal"},
	}, key)
	if err != nil {
		t.Fatalf("could not create the request: %v", err)
	}

	path := filepath.Join(dir, "request.pem")
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("could not write the request: %v", err)
	}

	return path
}

func TestRunIssuesChain(t *testing.T) {
	dir := t.TempDir()
	requestPath := writeRequest(t, dir)
	chainPath := filepath.Join(dir, "chain.pem")

	if err := run(requestPath, chainPath, 30, "cli test ca"); err != nil {
		t.Fatalf("issuing the chain failed: %v", err)
	}

	raw, err := os.ReadFile(chainPath)
	if err != nil {
		t.Fatalf("the chain was not written: %v", err)
	}

	if count := strings.Count(string(raw), "BEGIN CERTIFICATE"); count != 2 {
		t.Fatalf("expected a leaf and a CA in the output, got %d certificates", count)
	}
}

func TestRunRejectsBadArguments(t *testing.T) {
	dir := t.TempDir()
	requestPath := writeRequest(t, dir)
	chainPath := filepath.Join(dir, "chain.pem")

	cases := []struct {
		name string
		csr  string
		out  string
		days int
		want string
	}{
		{
			name: "no request",
			csr:  "",
			out:  chainPath,
			days: 1,
			want: "-csr and -out are required",
		},
		{
			name: "no output",
			csr:  requestPath,
			out:  "",
			days: 1,
			want: "-csr and -out are required",
		},
		{
			name: "validity of zero days",
			csr:  requestPath,
			out:  chainPath,
			days: 0,
			want: "-days must be positive",
		},
		{
			// The message of a missing file is platform specific, so only the
			// failure itself is asserted here.
			name: "missing request file",
			csr:  filepath.Join(dir, "absent.pem"),
			out:  chainPath,
			days: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := run(tc.csr, tc.out, tc.days, "cli test ca")
			if err == nil {
				t.Fatal("the command accepted arguments it should have rejected")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("the error does not mention %q: %v", tc.want, err)
			}
			if _, statErr := os.Stat(chainPath); statErr == nil {
				t.Fatal("a rejected run still wrote a chain")
			}
		})
	}
}
