package pki

import (
	"bytes"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/smx509"
)

// TestSubjectKeyIDIsSM3OfPublicKey recomputes the identifier from the encoded
// public key instead of trusting the function under test: if the two ever
// disagree, every certificate that carries the identifier is wrong.
func TestSubjectKeyIDIsSM3OfPublicKey(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not generate a key: %v", err)
	}

	got, err := subjectKeyID(&key.PublicKey)
	if err != nil {
		t.Fatalf("subjectKeyID failed: %v", err)
	}

	spki, err := smx509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("could not marshal the public key: %v", err)
	}

	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spki, &info); err != nil {
		t.Fatalf("could not unpack the public key: %v", err)
	}

	sum := sm3.Sum(info.PublicKey.Bytes)
	want := sum[:20]

	if !bytes.Equal(got, want) {
		t.Fatalf("identifier is %x, want %x", got, want)
	}
	if len(got) != 20 {
		t.Fatalf("identifier is %d bytes, want 20", len(got))
	}
}

func TestSubjectKeyIDDiffersPerKey(t *testing.T) {
	first, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not generate the first key: %v", err)
	}
	second, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not generate the second key: %v", err)
	}

	firstID, err := subjectKeyID(&first.PublicKey)
	if err != nil {
		t.Fatalf("subjectKeyID failed: %v", err)
	}
	secondID, err := subjectKeyID(&second.PublicKey)
	if err != nil {
		t.Fatalf("subjectKeyID failed: %v", err)
	}

	if bytes.Equal(firstID, secondID) {
		t.Fatal("two different keys produced the same identifier")
	}
}

func TestNormalizeSerial(t *testing.T) {
	cases := map[string]string{
		"3af1":         "3af1",
		"3AF1":         "3af1",
		"3A:F1":        "3af1",
		"3a-f1":        "3af1",
		" 3a f1 ":      "3af1",
		"3a:f1:00:01":  "3af10001",
		" 00:01:02:03": "00010203",
		"abc":          "0abc",
	}

	for raw, want := range cases {
		got, err := normalizeSerial(raw)
		if err != nil {
			t.Fatalf("normalizeSerial(%q) failed: %v", raw, err)
		}
		if got != want {
			t.Fatalf("normalizeSerial(%q) is %q, want %q", raw, got, want)
		}
	}

	for _, raw := range []string{"", "   ", "3a:zz", "0x3a"} {
		if _, err := normalizeSerial(raw); err == nil {
			t.Fatalf("normalizeSerial(%q) accepted an invalid serial", raw)
		}
	}
}

func TestFormatSerial(t *testing.T) {
	cases := map[string]string{
		"3af1":     "3A:F1",
		"3af10001": "3A:F1:00:01",
		"0a":       "0A",
	}

	for serial, want := range cases {
		if got := formatSerial(serial); got != want {
			t.Fatalf("formatSerial(%q) is %q, want %q", serial, got, want)
		}
	}
}

// TestSerialRoundTrip checks that the display form is accepted back as input,
// which is what makes the serial of a listing usable in cert/:serial.
func TestSerialRoundTrip(t *testing.T) {
	serial, err := newSerial()
	if err != nil {
		t.Fatalf("newSerial failed: %v", err)
	}

	stored := serialHex(serial)
	displayed := formatSerial(stored)

	back, err := normalizeSerial(displayed)
	if err != nil {
		t.Fatalf("the displayed serial %q was refused: %v", displayed, err)
	}
	if back != stored {
		t.Fatalf("the serial came back as %q, want %q", back, stored)
	}

	if parsed, ok := new(big.Int).SetString(back, 16); !ok || parsed.Cmp(serial) != 0 {
		t.Fatalf("the serial value changed on the way back")
	}
}

func TestNewSerialIsUniqueAndPositive(t *testing.T) {
	seen := make(map[string]struct{}, 256)

	for i := 0; i < 256; i++ {
		serial, err := newSerial()
		if err != nil {
			t.Fatalf("newSerial failed: %v", err)
		}
		if serial.Sign() <= 0 {
			t.Fatalf("newSerial returned %s, which is not positive", serial)
		}
		if serial.BitLen() > 128 {
			t.Fatalf("newSerial returned %d bits, which is more than 128", serial.BitLen())
		}

		key := serialHex(serial)
		if _, ok := seen[key]; ok {
			t.Fatalf("newSerial returned %s twice", key)
		}
		seen[key] = struct{}{}
	}
}
