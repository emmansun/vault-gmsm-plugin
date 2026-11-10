package gmsm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	"github.com/hashicorp/vault/sdk/logical"
)

// newImportTestKey returns an SM2 key together with the two PEM encodings the
// import path accepts: PKCS#8 and SEC 1.
func newImportTestKey(t *testing.T) (*sm2.PrivateKey, string, string) {
	t.Helper()

	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not generate an SM2 key: %v", err)
	}

	pkcs8, err := smx509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("could not marshal the private key as PKCS#8: %v", err)
	}

	sec1, err := smx509.MarshalECPrivateKey(&priv.PrivateKey)
	if err != nil {
		t.Fatalf("could not marshal the private key as SEC 1: %v", err)
	}

	// export/signing-key emits exactly this older form, so importing it back is
	// the round trip the plugin has to support.
	sec1PEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}))

	return priv, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})), sec1PEM
}

func publicKeyPEM(t *testing.T, priv *sm2.PrivateKey) string {
	t.Helper()

	der, err := smx509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("could not marshal the public key: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// importPath and importVersionPath name the two endpoints under test, so a case
// cannot drift onto the create path by accident.
func importPath(name string) string {
	return "keys/" + name + "/import"
}

func importVersionPath(name string) string {
	return "keys/" + name + "/import_version"
}

func importRequest(b *backend, s logical.Storage, op logical.Operation, path string, data map[string]interface{}) (*logical.Response, error) {
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: op,
		Path:      path,
		Storage:   s,
		Data:      data,
	})
}

func requestOK(t *testing.T, b *backend, s logical.Storage, op logical.Operation, path string, data map[string]interface{}) *logical.Response {
	t.Helper()

	resp, err := importRequest(b, s, op, path, data)
	if resp != nil && resp.IsError() {
		t.Fatalf("request to %q returned an error: %v", path, resp.Error())
	}
	if err != nil {
		t.Fatalf("request to %q failed: %v", path, err)
	}

	return resp
}

func importOK(t *testing.T, b *backend, s logical.Storage, path string, data map[string]interface{}) *logical.Response {
	t.Helper()

	return requestOK(t, b, s, logical.UpdateOperation, path, data)
}

// importRead is the read counterpart; export/... only answers reads.
func importRead(t *testing.T, b *backend, s logical.Storage, path string) *logical.Response {
	t.Helper()

	return requestOK(t, b, s, logical.ReadOperation, path, nil)
}

func importErr(t *testing.T, b *backend, s logical.Storage, path string, data map[string]interface{}) string {
	t.Helper()

	resp, err := importRequest(b, s, logical.UpdateOperation, path, data)

	var got string
	switch {
	case resp != nil && resp.IsError():
		got = resp.Error().Error()
	case err != nil:
		got = err.Error()
	}
	if got == "" {
		t.Fatalf("expected the request to %q to fail", path)
	}

	return got
}

func importExpectErr(t *testing.T, b *backend, s logical.Storage, path string, data map[string]interface{}, want string) {
	t.Helper()

	if got := importErr(t, b, s, path, data); !strings.Contains(got, want) {
		t.Fatalf("expected the error to mention %q, got %q", want, got)
	}
}

func importSign(t *testing.T, b *backend, s logical.Storage, name, input string) string {
	t.Helper()

	resp := importOK(t, b, s, "sign/"+name, map[string]interface{}{
		"input": base64.StdEncoding.EncodeToString([]byte(input)),
	})

	sig, ok := resp.Data["signature"].(string)
	if !ok || sig == "" {
		t.Fatalf("sign answered without a signature: %v", resp.Data)
	}

	return sig
}

func TestImportSM2PrivateKey(t *testing.T) {
	for _, encoding := range []string{"PKCS#8", "SEC 1"} {
		t.Run(encoding, func(t *testing.T) {
			b, storage := createBackendWithStorage(t)

			// The key pair belongs to the test, so the public key that ends up in
			// the policy proves the material was imported and not generated.
			priv, pkcs8, sec1 := newImportTestKey(t)
			material := pkcs8
			if encoding == "SEC 1" {
				material = sec1
			}

			resp := importOK(t, b, storage, importPath("imported"), map[string]interface{}{
				"type":        "sm2",
				"private_key": material,
				"exportable":  true,
			})

			if got := resp.Data["type"]; got != "sm2" {
				t.Fatalf("expected the imported key to be sm2, got %v", got)
			}
			if got := resp.Data["imported_key"]; got != true {
				t.Fatalf("expected the key to report itself as imported, got %v", got)
			}
			if got := resp.Data["latest_version"]; got != 1 {
				t.Fatalf("expected the import to create version 1, got %v", got)
			}

			keys, ok := resp.Data["keys"].(map[string]map[string]interface{})
			if !ok {
				t.Fatalf("expected the read shape to carry per version details, got %T", resp.Data["keys"])
			}
			publicKey, _ := keys["1"]["public_key"].(string)
			if publicKey != publicKeyPEM(t, priv) {
				t.Fatalf("the imported key does not hold the public key that belongs to the material")
			}

			// Signing works with the imported material and verifies against the
			// public key of the same version.
			input := base64.StdEncoding.EncodeToString([]byte("imported key"))
			sig := importSign(t, b, storage, "imported", "imported key")
			verify := importOK(t, b, storage, "verify/imported", map[string]interface{}{
				"input":     input,
				"signature": sig,
			})
			if valid, _ := verify.Data["valid"].(bool); !valid {
				t.Fatalf("a signature made with the imported key did not verify")
			}
		})
	}
}

func TestImportSM2PublicKeyOnly(t *testing.T) {
	b, storage := createBackendWithStorage(t)
	priv, _, _ := newImportTestKey(t)

	importOK(t, b, storage, importPath("public-only"), map[string]interface{}{
		"type":       "sm2",
		"public_key": publicKeyPEM(t, priv),
	})

	// Signing needs the private half, which is not there.
	importExpectErr(t, b, storage, "sign/public-only", map[string]interface{}{
		"input": base64.StdEncoding.EncodeToString([]byte("message")),
	}, "does not contain a private part")

	// A signature made outside Vault with the matching private key verifies.
	digest, err := sm2.CalculateSM2Hash(&priv.PublicKey, []byte("message"), nil)
	if err != nil {
		t.Fatalf("could not hash the message: %v", err)
	}
	der, err := sm2.SignASN1(rand.Reader, priv, digest, nil)
	if err != nil {
		t.Fatalf("could not sign the digest: %v", err)
	}

	verify := importOK(t, b, storage, "verify/public-only", map[string]interface{}{
		"input":     base64.StdEncoding.EncodeToString([]byte("message")),
		"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(der),
	})
	if valid, _ := verify.Data["valid"].(bool); !valid {
		t.Fatalf("a signature made outside Vault did not verify against the imported public key")
	}

	// Encryption only needs the public key; decryption then fails.
	encrypted := importOK(t, b, storage, "encrypt/public-only", map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString([]byte("secret")),
	})
	ciphertext, _ := encrypted.Data["ciphertext"].(string)
	if ciphertext == "" {
		t.Fatalf("encryption with a public-only key returned no ciphertext")
	}

	if got := importErr(t, b, storage, "decrypt/public-only", map[string]interface{}{
		"ciphertext": ciphertext,
	}); !strings.Contains(got, "does not contain a private part") {
		t.Fatalf("expected decryption to need the private half, got %q", got)
	}
}

func TestImportRejectsExistingKey(t *testing.T) {
	b, storage := createBackendWithStorage(t)
	_, pkcs8, _ := newImportTestKey(t)

	importOK(t, b, storage, importPath("imported"), map[string]interface{}{
		"type":        "sm2",
		"private_key": pkcs8,
	})

	importExpectErr(t, b, storage, importPath("imported"), map[string]interface{}{
		"type":        "sm2",
		"private_key": pkcs8,
	}, "already exists")

	// A key made by Vault is equally off limits.
	importOK(t, b, storage, "keys/generated", map[string]interface{}{
		"type": "sm2",
	})
	importExpectErr(t, b, storage, importPath("generated"), map[string]interface{}{
		"type":        "sm2",
		"private_key": pkcs8,
	}, "already exists")
}

func TestImportVersionAppendsVersion(t *testing.T) {
	b, storage := createBackendWithStorage(t)

	_, first, _ := newImportTestKey(t)
	_, second, _ := newImportTestKey(t)

	importOK(t, b, storage, importPath("imported"), map[string]interface{}{
		"type":        "sm2",
		"private_key": first,
	})
	firstSignature := importSign(t, b, storage, "imported", "message")

	resp := importOK(t, b, storage, importVersionPath("imported"), map[string]interface{}{
		"private_key": second,
	})
	if got := resp.Data["latest_version"]; got != 2 {
		t.Fatalf("expected a second version, got %v", got)
	}

	// The signature made with the first version still verifies, and one made
	// with the second is separate from it.
	verify := importOK(t, b, storage, "verify/imported", map[string]interface{}{
		"input":     base64.StdEncoding.EncodeToString([]byte("message")),
		"signature": firstSignature,
	})
	if valid, _ := verify.Data["valid"].(bool); !valid {
		t.Fatalf("the signature of the first version stopped verifying after the import")
	}

	secondSignature := importSign(t, b, storage, "imported", "message")
	if !strings.HasPrefix(secondSignature, "vault:v2:") {
		t.Fatalf("expected the new signature to come from version 2, got %s", secondSignature)
	}
}

func TestImportVersionRejectsVaultGeneratedKey(t *testing.T) {
	b, storage := createBackendWithStorage(t)
	_, pkcs8, _ := newImportTestKey(t)

	importOK(t, b, storage, "keys/generated", map[string]interface{}{
		"type": "sm2",
	})

	importExpectErr(t, b, storage, importVersionPath("generated"), map[string]interface{}{
		"private_key": pkcs8,
	}, "generated by Vault")

	importExpectErr(t, b, storage, importVersionPath("missing"), map[string]interface{}{
		"private_key": pkcs8,
	}, "not found")
}

func TestImportVersionStopsAfterRotation(t *testing.T) {
	b, storage := createBackendWithStorage(t)
	_, first, _ := newImportTestKey(t)
	_, second, _ := newImportTestKey(t)

	// Rotation of an imported key is refused unless the import allowed it.
	importOK(t, b, storage, importPath("fixed"), map[string]interface{}{
		"type":        "sm2",
		"private_key": first,
	})
	importExpectErr(t, b, storage, "keys/fixed/rotate", nil, "rotation is not allowed")

	importOK(t, b, storage, importPath("rotating"), map[string]interface{}{
		"type":           "sm2",
		"private_key":    first,
		"allow_rotation": true,
	})

	// import_version works up to the first Vault-side rotation.
	importOK(t, b, storage, importVersionPath("rotating"), map[string]interface{}{
		"private_key": second,
	})
	importOK(t, b, storage, "keys/rotating/rotate", nil)

	importExpectErr(t, b, storage, importVersionPath("rotating"), map[string]interface{}{
		"private_key": second,
	}, "no longer accepts imported material")
}

func TestImportVersionCompletesPublicOnlyVersion(t *testing.T) {
	b, storage := createBackendWithStorage(t)
	priv, pkcs8, _ := newImportTestKey(t)

	importOK(t, b, storage, importPath("late-private"), map[string]interface{}{
		"type":       "sm2",
		"public_key": publicKeyPEM(t, priv),
	})
	importExpectErr(t, b, storage, "sign/late-private", map[string]interface{}{
		"input": base64.StdEncoding.EncodeToString([]byte("message")),
	}, "does not contain a private part")

	// Completing the version keeps the version count, it does not add one.
	resp := importOK(t, b, storage, importVersionPath("late-private"), map[string]interface{}{
		"private_key": pkcs8,
		"version":     1,
	})
	if got := resp.Data["latest_version"]; got != 1 {
		t.Fatalf("expected the completion to stay on version 1, got %v", got)
	}

	sig := importSign(t, b, storage, "late-private", "message")
	verify := importOK(t, b, storage, "verify/late-private", map[string]interface{}{
		"input":     base64.StdEncoding.EncodeToString([]byte("message")),
		"signature": sig,
	})
	if valid, _ := verify.Data["valid"].(bool); !valid {
		t.Fatalf("signing with the completed version did not verify")
	}

	// A version that already holds a private key cannot be replaced.
	importExpectErr(t, b, storage, importVersionPath("late-private"), map[string]interface{}{
		"private_key": pkcs8,
		"version":     1,
	}, "cannot be updated")

	// A public key can also arrive as a new version, and the matching private
	// key then completes it without naming the version.
	otherPriv, otherPKCS8, _ := newImportTestKey(t)
	importOK(t, b, storage, importVersionPath("late-private"), map[string]interface{}{
		"public_key": publicKeyPEM(t, otherPriv),
	})
	resp = importOK(t, b, storage, importVersionPath("late-private"), map[string]interface{}{
		"private_key": otherPKCS8,
	})
	if got := resp.Data["latest_version"]; got != 2 {
		t.Fatalf("expected the unversioned completion to stay on version 2, got %v", got)
	}
}

func TestImportAutoRotationNeedsAllowRotation(t *testing.T) {
	b, storage := createBackendWithStorage(t)
	_, pkcs8, _ := newImportTestKey(t)

	// A period without allow_rotation would describe a rotation that can never
	// happen, so the import refuses it.
	importExpectErr(t, b, storage, importPath("fixed"), map[string]interface{}{
		"type":               "sm2",
		"private_key":        pkcs8,
		"auto_rotate_period": 3600,
	}, "requires allow_rotation")

	importOK(t, b, storage, importPath("fixed"), map[string]interface{}{
		"type":        "sm2",
		"private_key": pkcs8,
	})
	importExpectErr(t, b, storage, "keys/fixed/config", map[string]interface{}{
		"auto_rotate_period": 3600,
	}, "cannot be rotated automatically")

	// Once rotation is allowed, the period is usable and config can change it.
	importOK(t, b, storage, importPath("rotating"), map[string]interface{}{
		"type":               "sm2",
		"private_key":        pkcs8,
		"allow_rotation":     true,
		"auto_rotate_period": 3600,
	})
	importOK(t, b, storage, "keys/rotating/config", map[string]interface{}{
		"auto_rotate_period": 7200,
	})

	resp := importRead(t, b, storage, "keys/rotating")
	if got := resp.Data["auto_rotate_period"]; got != int64(7200) {
		t.Fatalf("expected the auto rotate period to be 7200, got %v", got)
	}
	if got := resp.Data["imported_key_allow_rotation"]; got != true {
		t.Fatalf("expected the key to allow rotation, got %v", got)
	}
}

func TestImportSymmetricKeys(t *testing.T) {
	b, storage := createBackendWithStorage(t)

	sm4Key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	resp := importOK(t, b, storage, importPath("sm4"), map[string]interface{}{
		"type":       "sm4-gcm96",
		"key":        sm4Key,
		"exportable": true,
	})
	if got := resp.Data["type"]; got != "sm4-gcm96" {
		t.Fatalf("expected an sm4-gcm96 key, got %v", got)
	}

	// The imported material has to be the one that decrypts what it encrypts.
	encrypted := importOK(t, b, storage, "encrypt/sm4", map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString([]byte("secret")),
	})
	ciphertext, _ := encrypted.Data["ciphertext"].(string)
	decrypted := importOK(t, b, storage, "decrypt/sm4", map[string]interface{}{
		"ciphertext": ciphertext,
	})
	if got, _ := decrypted.Data["plaintext"].(string); got != base64.StdEncoding.EncodeToString([]byte("secret")) {
		t.Fatalf("the imported key did not round trip, got %v", decrypted.Data)
	}

	// Exporting hands back exactly the bytes that were imported.
	exported := importRead(t, b, storage, "export/encryption-key/sm4/latest")
	keys, _ := exported.Data["keys"].(map[string]string)
	if keys["1"] != sm4Key {
		t.Fatalf("expected export to return the imported material, got %q", keys["1"])
	}

	hmacKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 64)))
	importOK(t, b, storage, importPath("hmac"), map[string]interface{}{
		"type": "hmac",
		"key":  hmacKey,
	})
	hmacResp := importOK(t, b, storage, "hmac/hmac", map[string]interface{}{
		"input": base64.StdEncoding.EncodeToString([]byte("message")),
	})
	if mac, _ := hmacResp.Data["hmac"].(string); mac == "" {
		t.Fatalf("an imported hmac key produced no hmac")
	}
}

func TestImportRejectsInvalidRequests(t *testing.T) {
	b, storage := createBackendWithStorage(t)
	_, pkcs8, _ := newImportTestKey(t)

	wrongLength := base64.StdEncoding.EncodeToString([]byte("too short"))

	// A PKCS#8 container can hold any algorithm, so the parser has to reject a
	// key that is not on the SM2 curve instead of importing it as one.
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate a P-256 key: %v", err)
	}
	p256DER, err := smx509.MarshalPKCS8PrivateKey(p256Key)
	if err != nil {
		t.Fatalf("could not marshal the P-256 key: %v", err)
	}
	p256PEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p256DER}))

	tests := []struct {
		name string
		data map[string]interface{}
		want string
	}{
		{
			name: "no material",
			data: map[string]interface{}{"type": "sm2"},
			want: "one of private_key, public_key or key is required",
		},
		{
			name: "two kinds of material",
			data: map[string]interface{}{"type": "sm2", "private_key": pkcs8, "public_key": "x"},
			want: "only one of",
		},
		{
			name: "missing type",
			data: map[string]interface{}{"private_key": pkcs8},
			want: "type is required",
		},
		{
			name: "unknown type",
			data: map[string]interface{}{"type": "aes256-gcm96", "key": wrongLength},
			want: "unknown key type",
		},
		{
			name: "sm4-cmac",
			data: map[string]interface{}{"type": "sm4-cmac", "key": wrongLength},
			want: "sm4-cmac keys are not supported",
		},
		{
			name: "managed key",
			data: map[string]interface{}{"type": "managed_key", "key": wrongLength},
			want: "managed keys are not imported",
		},
		{
			name: "symmetric material for sm2",
			data: map[string]interface{}{"type": "sm2", "key": wrongLength},
			want: "only used for sm4-gcm96 and hmac",
		},
		{
			name: "private key for a symmetric type",
			data: map[string]interface{}{"type": "sm4-gcm96", "private_key": pkcs8},
			want: "only used for sm2",
		},
		{
			name: "material that is not base64",
			data: map[string]interface{}{"type": "sm4-gcm96", "key": "not base64!"},
			want: "must be base64 encoded",
		},
		{
			name: "sm4 key of the wrong length",
			data: map[string]interface{}{"type": "sm4-gcm96", "key": wrongLength},
			want: "invalid key size",
		},
		{
			name: "public key that is not PEM",
			data: map[string]interface{}{"type": "sm2", "public_key": "not a pem"},
			want: "must be a PEM encoded public key",
		},
		{
			name: "private key that is not PEM",
			data: map[string]interface{}{"type": "sm2", "private_key": "not a pem"},
			want: "error parsing private key",
		},
		{
			name: "private key on another curve",
			data: map[string]interface{}{"type": "sm2", "private_key": p256PEM},
			want: "error parsing private key",
		},
		{
			name: "auto rotate without allow_rotation",
			data: map[string]interface{}{"type": "sm2", "private_key": pkcs8, "auto_rotate_period": 3600},
			want: "requires allow_rotation",
		},
		{
			name: "auto rotate below an hour",
			data: map[string]interface{}{"type": "sm2", "private_key": pkcs8, "allow_rotation": true, "auto_rotate_period": 60},
			want: "at least an hour",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Each case gets its own name so an earlier success cannot turn a
			// later case into an "already exists" answer.
			data := map[string]interface{}{}
			for k, v := range test.data {
				data[k] = v
			}
			path := importPath(strings.ReplaceAll(test.name, " ", "-"))

			importExpectErr(t, b, storage, path, data, test.want)
		})
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	b, storage := createBackendWithStorage(t)

	importOK(t, b, storage, "keys/original", map[string]interface{}{
		"type":       "sm2",
		"exportable": true,
	})
	importSign(t, b, storage, "original", "message")

	exported := importRead(t, b, storage, "export/signing-key/original/latest")
	keys, _ := exported.Data["keys"].(map[string]string)
	exportedKey := keys["1"]
	if exportedKey == "" {
		t.Fatalf("export returned no key material")
	}

	// What export hands out has to be accepted by import unchanged.
	importOK(t, b, storage, importPath("copy"), map[string]interface{}{
		"type":        "sm2",
		"private_key": exportedKey,
	})

	original := importRead(t, b, storage, "keys/original")
	copied := importRead(t, b, storage, "keys/copy")
	originalKeys, _ := original.Data["keys"].(map[string]map[string]interface{})
	copiedKeys, _ := copied.Data["keys"].(map[string]map[string]interface{})
	if originalKeys["1"]["public_key"] != copiedKeys["1"]["public_key"] {
		t.Fatalf("the re-imported key does not hold the public key of the original")
	}

	// And the copy produces signatures the original accepts, which is the point
	// of moving a key between mounts.
	copiedSignature := importSign(t, b, storage, "copy", "message")
	verify := importOK(t, b, storage, "verify/original", map[string]interface{}{
		"input":     base64.StdEncoding.EncodeToString([]byte("message")),
		"signature": copiedSignature,
	})
	if valid, _ := verify.Data["valid"].(bool); !valid {
		t.Fatalf("a signature from the re-imported key did not verify against the original")
	}
}
