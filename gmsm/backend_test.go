package gmsm

import (
	"context"
	cryptoRand "crypto/rand"
	"encoding/base64"
	"math/rand"
	"path"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/keysutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

const (
	testPlaintext = "The quick brown fox"
)

func createBackendWithStorage(t testing.TB) (*backend, logical.Storage) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	b, _ := Backend(context.Background(), config)
	if b == nil {
		t.Fatalf("failed to create backend")
	}
	err := b.Backend.Setup(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	return b, config.StorageView
}

func createBackendWithSysView(t testing.TB) (*backend, logical.Storage) {
	sysView := logical.TestSystemView()
	storage := &logical.InmemStorage{}

	conf := &logical.BackendConfig{
		StorageView: storage,
		System:      sysView,
	}

	b, _ := Backend(context.Background(), conf)
	if b == nil {
		t.Fatal("failed to create backend")
	}

	err := b.Backend.Setup(context.Background(), conf)
	if err != nil {
		t.Fatal(err)
	}

	return b, storage
}

func createBackendWithSysViewWithStorage(t testing.TB, s logical.Storage) *backend {
	sysView := logical.TestSystemView()

	conf := &logical.BackendConfig{
		StorageView: s,
		System:      sysView,
	}

	b, _ := Backend(context.Background(), conf)
	if b == nil {
		t.Fatal("failed to create backend")
	}

	err := b.Backend.Setup(context.Background(), conf)
	if err != nil {
		t.Fatal(err)
	}

	return b
}

func createBackendWithForceNoCacheWithSysViewWithStorage(t testing.TB, s logical.Storage) *backend {
	sysView := logical.TestSystemView()
	sysView.CachingDisabledVal = true

	conf := &logical.BackendConfig{
		StorageView: s,
		System:      sysView,
	}

	b, _ := Backend(context.Background(), conf)
	if b == nil {
		t.Fatal("failed to create backend")
	}

	err := b.Backend.Setup(context.Background(), conf)
	if err != nil {
		t.Fatal(err)
	}

	return b
}

func Test_SM2(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t)

	keyReq := &logical.Request{
		Path:      "keys/sm2",
		Operation: logical.UpdateOperation,
		Data: map[string]interface{}{
			"type": "ecdsa-sm2",
		},
		Storage: storage,
	}

	resp, err = b.HandleRequest(context.Background(), keyReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v\nresp: %#v", err, resp)
	}

	plaintext := "dGhlIHF1aWNrIGJyb3duIGZveA==" // "the quick brown fox"

	encryptReq := &logical.Request{
		Path:      "encrypt/sm2",
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Data: map[string]interface{}{
			"plaintext": plaintext,
		},
	}

	resp, err = b.HandleRequest(context.Background(), encryptReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v\nresp: %#v", err, resp)
	}

	ciphertext1 := resp.Data["ciphertext"].(string)

	decryptReq := &logical.Request{
		Path:      "decrypt/sm2",
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Data: map[string]interface{}{
			"ciphertext": ciphertext1,
		},
	}

	resp, err = b.HandleRequest(context.Background(), decryptReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v\nresp: %#v", err, resp)
	}

	decryptedPlaintext := resp.Data["plaintext"]
	if plaintext != decryptedPlaintext {
		t.Fatalf("bad: plaintext; expected: %q\nactual: %q", plaintext, decryptedPlaintext)
	}

	// Rotate the key
	rotateReq := &logical.Request{
		Path:      "keys/sm2/rotate",
		Operation: logical.UpdateOperation,
		Storage:   storage,
	}
	resp, err = b.HandleRequest(context.Background(), rotateReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v\nresp: %#v", err, resp)
	}

	// Encrypt again
	resp, err = b.HandleRequest(context.Background(), encryptReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v\nresp: %#v", err, resp)
	}
	ciphertext2 := resp.Data["ciphertext"].(string)

	if ciphertext1 == ciphertext2 {
		t.Fatalf("expected different ciphertexts")
	}

	// See if the older ciphertext can still be decrypted
	resp, err = b.HandleRequest(context.Background(), decryptReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v\nresp: %#v", err, resp)
	}
	if resp.Data["plaintext"].(string) != plaintext {
		t.Fatal("failed to decrypt old ciphertext after rotating the key")
	}

	// Decrypt the new ciphertext
	decryptReq.Data = map[string]interface{}{
		"ciphertext": ciphertext2,
	}
	resp, err = b.HandleRequest(context.Background(), decryptReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v\nresp: %#v", err, resp)
	}
	if resp.Data["plaintext"].(string) != plaintext {
		t.Fatal("failed to decrypt ciphertext after rotating the key")
	}

	signReq := &logical.Request{
		Path:      "sign/sm2",
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Data: map[string]interface{}{
			"input": plaintext,
		},
	}
	resp, err = b.HandleRequest(context.Background(), signReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v\nresp: %#v", err, resp)
	}
	signature := resp.Data["signature"].(string)

	verifyReq := &logical.Request{
		Path:      "verify/sm2",
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Data: map[string]interface{}{
			"input":     plaintext,
			"signature": signature,
		},
	}

	resp, err = b.HandleRequest(context.Background(), verifyReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v\nresp: %#v", err, resp)
	}
	if !resp.Data["valid"].(bool) {
		t.Fatalf("failed to verify the RSA signature")
	}
}

func TestKeyUpgrade(t *testing.T) {
	key, _ := uuid.GenerateRandomBytes(16)
	p := &Policy{
		Name: "test",
		Key:  key,
		Type: KeyType_SM4_GCM96,
	}

	p.MigrateKeyToKeysMap()

	if p.Key != nil ||
		p.Keys == nil ||
		len(p.Keys) != 1 ||
		!reflect.DeepEqual(p.Keys[strconv.Itoa(1)].Key, key) {
		t.Errorf("bad key migration, result is %#v", p.Keys)
	}
}

func TestDerivedKeyUpgrade(t *testing.T) {
	testDerivedKeyUpgrade(t, KeyType_SM4_GCM96)
}

func testDerivedKeyUpgrade(t *testing.T, keyType KeyType) {
	storage := &logical.InmemStorage{}
	key, _ := uuid.GenerateRandomBytes(32)
	keyContext, _ := uuid.GenerateRandomBytes(32)

	p := &Policy{
		Name:    "test",
		Key:     key,
		Type:    keyType,
		Derived: true,
	}

	p.MigrateKeyToKeysMap()
	p.Upgrade(context.Background(), storage, cryptoRand.Reader) // Need to run the upgrade code to make the migration stick

	if p.KDF != Kdf_hmac_sm3_counter {
		t.Fatalf("bad KDF value by default; counter val is %d, KDF val is %d, policy is %#v", Kdf_hmac_sm3_counter, p.KDF, *p)
	}

	derBytesOld, err := p.GetKey(keyContext, 1, 0)
	if err != nil {
		t.Fatal(err)
	}

	derBytesOld2, err := p.GetKey(keyContext, 1, 0)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(derBytesOld, derBytesOld2) {
		t.Fatal("mismatch of same context alg")
	}

	p.KDF = Kdf_hkdf_sm3
	if p.NeedsUpgrade() {
		t.Fatal("expected no upgrade needed")
	}

	derBytesNew, err := p.GetKey(keyContext, 1, 64)
	if err != nil {
		t.Fatal(err)
	}

	derBytesNew2, err := p.GetKey(keyContext, 1, 64)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(derBytesNew, derBytesNew2) {
		t.Fatal("mismatch of same context alg")
	}

	if reflect.DeepEqual(derBytesOld, derBytesNew) {
		t.Fatal("match of different context alg")
	}
}

func TestConvergentEncryption(t *testing.T) {
	testConvergentEncryptionCommon(t, 0, KeyType_SM4_GCM96)
	testConvergentEncryptionCommon(t, 2, KeyType_SM4_GCM96)
	testConvergentEncryptionCommon(t, 3, KeyType_SM4_GCM96)
}

func testConvergentEncryptionCommon(t *testing.T, ver int, keyType KeyType) {
	b, storage := createBackendWithSysView(t)

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/testkeynonderived",
		Data: map[string]interface{}{
			"derived":               false,
			"convergent_encryption": true,
			"type":                  keyType.String(),
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if !resp.IsError() {
		t.Fatalf("bad: expected error response, got %#v", *resp)
	}

	req = &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/testkey",
		Data: map[string]interface{}{
			"derived":               true,
			"convergent_encryption": true,
			"type":                  keyType.String(),
		},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	require.NotNil(t, resp, "expected populated request")

	p, err := keysutil.LoadPolicy(context.Background(), storage, path.Join("policy", "testkey"))
	if err != nil {
		t.Fatal(err)
	}
	if p == nil {
		t.Fatal("got nil policy")
	}

	if ver > 2 {
		p.ConvergentVersion = -1
	} else {
		p.ConvergentVersion = ver
	}
	err = p.Persist(context.Background(), storage)
	if err != nil {
		t.Fatal(err)
	}
	b.invalidate(context.Background(), "policy/testkey")

	if ver < 3 {
		// There will be an embedded key version of 3, so specifically clear it
		key := p.Keys[strconv.Itoa(p.LatestVersion)]
		key.ConvergentVersion = 0
		p.Keys[strconv.Itoa(p.LatestVersion)] = key
		err = p.Persist(context.Background(), storage)
		if err != nil {
			t.Fatal(err)
		}
		b.invalidate(context.Background(), "policy/testkey")

		// Verify it
		p, err = keysutil.LoadPolicy(context.Background(), storage, path.Join(p.StoragePrefix, "policy", "testkey"))
		if err != nil {
			t.Fatal(err)
		}
		if p == nil {
			t.Fatal("got nil policy")
		}
		if p.ConvergentVersion != ver {
			t.Fatalf("bad convergent version %d", p.ConvergentVersion)
		}
		key = p.Keys[strconv.Itoa(p.LatestVersion)]
		if key.ConvergentVersion != 0 {
			t.Fatalf("bad convergent key version %d", key.ConvergentVersion)
		}
	}

	// First, test using an invalid length of nonce -- this is only used for v1 convergent
	req.Path = "encrypt/testkey"
	if ver < 2 {
		req.Data = map[string]interface{}{
			"plaintext": "emlwIHphcA==", // "zip zap"
			"nonce":     "Zm9vIGJhcg==", // "foo bar"
			"context":   "pWZ6t/im3AORd0lVYE0zBdKpX6Bl3/SvFtoVTPWbdkzjG788XmMAnOlxandSdd7S",
		}
		resp, err = b.HandleRequest(context.Background(), req)
		if err == nil {
			t.Fatalf("expected error, got nil, version is %d", ver)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if !resp.IsError() {
			t.Fatalf("expected error response, got %#v", *resp)
		}

		// Ensure we fail if we do not provide a nonce
		req.Data = map[string]interface{}{
			"plaintext": "emlwIHphcA==", // "zip zap"
			"context":   "pWZ6t/im3AORd0lVYE0zBdKpX6Bl3/SvFtoVTPWbdkzjG788XmMAnOlxandSdd7S",
		}
		resp, err = b.HandleRequest(context.Background(), req)
		if err == nil && (resp == nil || !resp.IsError()) {
			t.Fatal("expected error response")
		}
	}

	// Now test encrypting the same value twice
	req.Data = map[string]interface{}{
		"plaintext": "emlwIHphcA==", // "zip zap"
		"context":   "pWZ6t/im3AORd0lVYE0zBdKpX6Bl3/SvFtoVTPWbdkzjG788XmMAnOlxandSdd7S",
	}
	if ver == 0 {
		req.Data["nonce"] = "b25ldHdvdGhyZWVl" // "onetwothreee"
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.IsError() {
		t.Fatalf("got error response: %#v", *resp)
	}
	ciphertext1 := resp.Data["ciphertext"].(string)

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.IsError() {
		t.Fatalf("got error response: %#v", *resp)
	}
	ciphertext2 := resp.Data["ciphertext"].(string)

	if ciphertext1 != ciphertext2 {
		t.Fatalf("expected the same ciphertext but got %s and %s", ciphertext1, ciphertext2)
	}

	// For sanity, also check a different nonce value...
	req.Data = map[string]interface{}{
		"plaintext": "emlwIHphcA==", // "zip zap"
		"context":   "pWZ6t/im3AORd0lVYE0zBdKpX6Bl3/SvFtoVTPWbdkzjG788XmMAnOlxandSdd7S",
	}
	if ver == 0 {
		req.Data["nonce"] = "dHdvdGhyZWVmb3Vy" // "twothreefour"
	} else {
		req.Data["context"] = "pWZ6t/im3AORd0lVYE0zBdKpX6Bl3/SvFtoVTPWbdkzjG788XmMAnOldandSdd7S"
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.IsError() {
		t.Fatalf("got error response: %#v", *resp)
	}
	ciphertext3 := resp.Data["ciphertext"].(string)

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.IsError() {
		t.Fatalf("got error response: %#v", *resp)
	}
	ciphertext4 := resp.Data["ciphertext"].(string)

	if ciphertext3 != ciphertext4 {
		t.Fatalf("expected the same ciphertext but got %s and %s", ciphertext3, ciphertext4)
	}
	if ciphertext1 == ciphertext3 {
		t.Fatalf("expected different ciphertexts")
	}

	// ...and a different context value
	req.Data = map[string]interface{}{
		"plaintext": "emlwIHphcA==", // "zip zap"
		"context":   "qV4h9iQyvn+raODOer4JNAsOhkXBwdT4HZ677Ql4KLqXSU+Jk4C/fXBWbv6xkSYT",
	}
	if ver == 0 {
		req.Data["nonce"] = "dHdvdGhyZWVmb3Vy" // "twothreefour"
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.IsError() {
		t.Fatalf("got error response: %#v", *resp)
	}
	ciphertext5 := resp.Data["ciphertext"].(string)

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.IsError() {
		t.Fatalf("got error response: %#v", *resp)
	}
	ciphertext6 := resp.Data["ciphertext"].(string)

	if ciphertext5 != ciphertext6 {
		t.Fatalf("expected the same ciphertext but got %s and %s", ciphertext5, ciphertext6)
	}
	if ciphertext1 == ciphertext5 {
		t.Fatalf("expected different ciphertexts")
	}
	if ciphertext3 == ciphertext5 {
		t.Fatalf("expected different ciphertexts")
	}

	// If running version 2, check upgrade handling
	if ver == 2 {
		curr, err := keysutil.LoadPolicy(context.Background(), storage, path.Join(p.StoragePrefix, "policy", "testkey"))
		if err != nil {
			t.Fatal(err)
		}
		if curr == nil {
			t.Fatal("got nil policy")
		}
		if curr.ConvergentVersion != 2 {
			t.Fatalf("bad convergent version %d", curr.ConvergentVersion)
		}
		key := curr.Keys[strconv.Itoa(curr.LatestVersion)]
		if key.ConvergentVersion != 0 {
			t.Fatalf("bad convergent key version %d", key.ConvergentVersion)
		}

		curr.ConvergentVersion = 3
		err = curr.Persist(context.Background(), storage)
		if err != nil {
			t.Fatal(err)
		}
		b.invalidate(context.Background(), "policy/testkey")

		// Different algorithm, should be different value
		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if resp.IsError() {
			t.Fatalf("got error response: %#v", *resp)
		}
		ciphertext7 := resp.Data["ciphertext"].(string)

		// Now do it via key-specified version
		if len(curr.Keys) != 1 {
			t.Fatalf("unexpected length of keys %d", len(curr.Keys))
		}
		key = curr.Keys[strconv.Itoa(curr.LatestVersion)]
		key.ConvergentVersion = 3
		curr.Keys[strconv.Itoa(curr.LatestVersion)] = key
		curr.ConvergentVersion = 2
		err = curr.Persist(context.Background(), storage)
		if err != nil {
			t.Fatal(err)
		}
		b.invalidate(context.Background(), "policy/testkey")

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if resp.IsError() {
			t.Fatalf("got error response: %#v", *resp)
		}
		ciphertext8 := resp.Data["ciphertext"].(string)

		if ciphertext7 != ciphertext8 {
			t.Fatalf("expected the same ciphertext but got %s and %s", ciphertext7, ciphertext8)
		}
		if ciphertext6 == ciphertext7 {
			t.Fatalf("expected different ciphertexts")
		}
		if ciphertext3 == ciphertext7 {
			t.Fatalf("expected different ciphertexts")
		}
	}

	// Finally, check operations on empty values
	// First, check without setting a plaintext at all
	req.Data = map[string]interface{}{
		"context": "pWZ6t/im3AORd0lVYE0zBdKpX6Bl3/SvFtoVTPWbdkzjG788XmMAnOlxandSdd7S",
	}
	if ver == 0 {
		req.Data["nonce"] = "dHdvdGhyZWVmb3Vy" // "twothreefour"
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if !resp.IsError() {
		t.Fatalf("expected error response, got: %#v", *resp)
	}

	// Now set plaintext to empty
	req.Data = map[string]interface{}{
		"plaintext": "",
		"context":   "pWZ6t/im3AORd0lVYE0zBdKpX6Bl3/SvFtoVTPWbdkzjG788XmMAnOlxandSdd7S",
	}
	if ver == 0 {
		req.Data["nonce"] = "dHdvdGhyZWVmb3Vy" // "twothreefour"
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.IsError() {
		t.Fatalf("got error response: %#v", *resp)
	}
	ciphertext7 := resp.Data["ciphertext"].(string)

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.IsError() {
		t.Fatalf("got error response: %#v", *resp)
	}
	ciphertext8 := resp.Data["ciphertext"].(string)

	if ciphertext7 != ciphertext8 {
		t.Fatalf("expected the same ciphertext but got %s and %s", ciphertext7, ciphertext8)
	}
}

func TestPolicyFuzzing(t *testing.T) {
	var be *backend
	sysView := logical.TestSystemView()
	sysView.CachingDisabledVal = true
	conf := &logical.BackendConfig{
		System: sysView,
	}

	be, _ = Backend(context.Background(), conf)
	be.Setup(context.Background(), conf)
	testPolicyFuzzingCommon(t, be)

	sysView.CachingDisabledVal = true
	be, _ = Backend(context.Background(), conf)
	be.Setup(context.Background(), conf)
	testPolicyFuzzingCommon(t, be)
}

func testPolicyFuzzingCommon(t *testing.T, be *backend) {
	storage := &logical.InmemStorage{}
	wg := sync.WaitGroup{}

	funcs := []string{"encrypt", "decrypt", "rotate", "change_min_version"}
	// keys := []string{"test1", "test2", "test3", "test4", "test5"}
	keys := []string{"test1", "test2", "test3"}

	// This is the goroutine loop
	doFuzzy := func(id int) {
		// Check for panics, otherwise notify we're done
		defer func() {
			wg.Done()
		}()

		// Holds the latest encrypted value for each key
		latestEncryptedText := map[string]string{}

		startTime := time.Now()
		req := &logical.Request{
			Storage: storage,
			Data:    map[string]interface{}{},
		}
		fd := &framework.FieldData{}

		var chosenFunc, chosenKey string

		// t.Errorf("Starting %d", id)
		for {
			// Stop after 10 seconds
			if time.Now().Sub(startTime) > 10*time.Second {
				return
			}

			// Pick a function and a key
			chosenFunc = funcs[rand.Int()%len(funcs)]
			chosenKey = keys[rand.Int()%len(keys)]

			fd.Raw = map[string]interface{}{
				"name": chosenKey,
			}
			fd.Schema = be.pathKeys().Fields

			// Try to write the key to make sure it exists
			_, err := be.pathPolicyWrite(context.Background(), req, fd)
			if err != nil {
				t.Errorf("got an error: %v", err)
			}

			switch chosenFunc {
			// Encrypt our plaintext and store the result
			case "encrypt":
				// t.Errorf("%s, %s, %d", chosenFunc, chosenKey, id)
				fd.Raw["plaintext"] = base64.StdEncoding.EncodeToString([]byte(testPlaintext))
				fd.Schema = be.pathEncrypt().Fields
				resp, err := be.pathEncryptWrite(context.Background(), req, fd)
				if err != nil {
					t.Errorf("got an error: %v, resp is %#v", err, *resp)
				}
				latestEncryptedText[chosenKey] = resp.Data["ciphertext"].(string)

			// Rotate to a new key version
			case "rotate":
				// t.Errorf("%s, %s, %d", chosenFunc, chosenKey, id)
				fd.Schema = be.pathRotate().Fields
				resp, err := be.pathRotateWrite(context.Background(), req, fd)
				if err != nil {
					t.Errorf("got an error: %v, resp is %#v, chosenKey is %s", err, *resp, chosenKey)
				}

			// Decrypt the ciphertext and compare the result
			case "decrypt":
				// t.Errorf("%s, %s, %d", chosenFunc, chosenKey, id)
				ct := latestEncryptedText[chosenKey]
				if ct == "" {
					continue
				}

				fd.Raw["ciphertext"] = ct
				fd.Schema = be.pathDecrypt().Fields
				resp, err := be.pathDecryptWrite(context.Background(), req, fd)
				if err != nil {
					// This could well happen since the min version is jumping around
					if resp.Data["error"].(string) == keysutil.ErrTooOld {
						continue
					}
					t.Errorf("got an error: %v, resp is %#v, ciphertext was %s, chosenKey is %s, id is %d", err, *resp, ct, chosenKey, id)
				}
				ptb64, ok := resp.Data["plaintext"].(string)
				if !ok {
					t.Errorf("no plaintext found, response was %#v", *resp)
					return
				}
				pt, err := base64.StdEncoding.DecodeString(ptb64)
				if err != nil {
					t.Errorf("got an error decoding base64 plaintext: %v", err)
					return
				}
				if string(pt) != testPlaintext {
					t.Errorf("got bad plaintext back: %s", pt)
				}

			// Change the min version, which also tests the archive functionality
			case "change_min_version":
				// t.Errorf("%s, %s, %d", chosenFunc, chosenKey, id)
				resp, err := be.pathPolicyRead(context.Background(), req, fd)
				if err != nil {
					t.Errorf("got an error reading policy %s: %v", chosenKey, err)
				}
				latestVersion := resp.Data["latest_version"].(int)

				// keys start at version 1 so we want [1, latestVersion] not [0, latestVersion)
				setVersion := (rand.Int() % latestVersion) + 1
				fd.Raw["min_decryption_version"] = setVersion
				fd.Schema = be.pathKeysConfig().Fields
				resp, err = be.pathConfigWrite(context.Background(), req, fd)
				if err != nil {
					t.Errorf("got an error setting min decryption version: %v", err)
				}
			}
		}
	}

	// Spawn 1000 of these workers for 10 seconds
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go doFuzzy(i)
	}

	// Wait for them all to finish
	wg.Wait()
}

func TestBadInput(t *testing.T) {
	b, storage := createBackendWithSysView(t)

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	require.NotNil(t, resp, "expected populated request")

	req.Path = "decrypt/test"
	req.Data = map[string]interface{}{
		"ciphertext": "vault:v1:abcd",
	}

	_, err = b.HandleRequest(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
}
