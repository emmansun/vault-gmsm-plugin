package gmsm

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func Test_BatchDecryption(t *testing.T) {
	var resp *logical.Response
	var err error

	b, s := createBackendWithStorage(t)

	batchEncryptionInput := []interface{}{
		map[string]interface{}{"plaintext": "", "reference": "foo"},     // empty string
		map[string]interface{}{"plaintext": "Cg==", "reference": "bar"}, // newline
		map[string]interface{}{"plaintext": "dGhlIHF1aWNrIGJyb3duIGZveA==", "reference": "baz"},
	}
	batchEncryptionData := map[string]interface{}{
		"batch_input": batchEncryptionInput,
	}

	batchEncryptionReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "encrypt/upserted_key",
		Storage:   s,
		Data:      batchEncryptionData,
	}
	resp, err = b.HandleRequest(context.Background(), batchEncryptionReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	batchResponseItems := resp.Data["batch_results"].([]EncryptBatchResponseItem)
	batchDecryptionInput := make([]interface{}, len(batchResponseItems))
	for i, item := range batchResponseItems {
		batchDecryptionInput[i] = map[string]interface{}{"ciphertext": item.Ciphertext, "reference": item.Reference}
	}
	batchDecryptionData := map[string]interface{}{
		"batch_input": batchDecryptionInput,
	}

	batchDecryptionReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "decrypt/upserted_key",
		Storage:   s,
		Data:      batchDecryptionData,
	}
	resp, err = b.HandleRequest(context.Background(), batchDecryptionReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	batchDecryptionResponseItems := resp.Data["batch_results"].([]DecryptBatchResponseItem)
	expectedResult := "[{\"plaintext\":\"\",\"reference\":\"foo\"},{\"plaintext\":\"Cg==\",\"reference\":\"bar\"},{\"plaintext\":\"dGhlIHF1aWNrIGJyb3duIGZveA==\",\"reference\":\"baz\"}]"

	jsonResponse, err := json.Marshal(batchDecryptionResponseItems)
	if err != nil || string(jsonResponse) != expectedResult {
		t.Fatalf("bad: expected json response [%s]", jsonResponse)
	}
}

func Test_BatchDecryption_DerivedKey(t *testing.T) {
	var resp *logical.Response
	var err error

	b, s := createBackendWithStorage(t)

	policyData := map[string]interface{}{
		"derived": true,
	}

	policyReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "keys/existing_key",
		Storage:   s,
		Data:      policyData,
	}

	resp, err = b.HandleRequest(context.Background(), policyReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	batchInput := []interface{}{
		map[string]interface{}{"plaintext": "dGhlIHF1aWNrIGJyb3duIGZveA==", "context": "dGVzdGNvbnRleHQ="},
		map[string]interface{}{"plaintext": "dGhlIHF1aWNrIGJyb3duIGZveA==", "context": "dGVzdGNvbnRleHQ="},
	}

	batchData := map[string]interface{}{
		"batch_input": batchInput,
	}
	batchReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "encrypt/existing_key",
		Storage:   s,
		Data:      batchData,
	}
	resp, err = b.HandleRequest(context.Background(), batchReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	batchDecryptionInputItems := resp.Data["batch_results"].([]EncryptBatchResponseItem)

	batchDecryptionInput := make([]interface{}, len(batchDecryptionInputItems))
	for i, item := range batchDecryptionInputItems {
		batchDecryptionInput[i] = map[string]interface{}{"ciphertext": item.Ciphertext, "context": "dGVzdGNvbnRleHQ="}
	}

	batchDecryptionData := map[string]interface{}{
		"batch_input": batchDecryptionInput,
	}

	batchDecryptionReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "decrypt/existing_key",
		Storage:   s,
		Data:      batchDecryptionData,
	}
	resp, err = b.HandleRequest(context.Background(), batchDecryptionReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	batchDecryptionResponseItems := resp.Data["batch_results"].([]DecryptBatchResponseItem)

	plaintext := "dGhlIHF1aWNrIGJyb3duIGZveA=="
	for _, item := range batchDecryptionResponseItems {
		if item.Plaintext != plaintext {
			t.Fatalf("bad: plaintext. Expected: %q, Actual: %q", plaintext, item.Plaintext)
		}
	}
}
