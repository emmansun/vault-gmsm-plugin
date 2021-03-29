package gmsm

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/emmansun/gmsm/sm3"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/helper/keysutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
)

// BatchRequestSignItem represents a request item for batch processing.
// A map type allows us to distinguish between empty and missing values.
type batchRequestSignItem map[string]string

// BatchResponseSignItem represents a response item for batch processing
type batchResponseSignItem struct {
	// signature for the input present in the corresponding batch
	// request item
	Signature string `json:"signature,omitempty" mapstructure:"signature"`

	// The key version to be used for encryption
	KeyVersion int `json:"key_version" mapstructure:"key_version"`

	PublicKey []byte `json:"publickey,omitempty" mapstructure:"publickey"`

	// Error, if set represents a failure encountered while encrypting a
	// corresponding batch request item
	Error string `json:"error,omitempty" mapstructure:"error"`

	// The return paths through WriteSign in some cases are (nil, err) and others
	// (logical.ErrorResponse(..),nil), and others (logical.ErrorResponse(..),err).
	// For batch processing to successfully mimic previous handling for simple 'input',
	// both output values are needed - though 'err' should never be serialized.
	err error
}

// BatchRequestVerifyItem represents a request item for batch processing.
// A map type allows us to distinguish between empty and missing values.
type batchRequestVerifyItem map[string]string

// BatchResponseVerifyItem represents a response item for batch processing
type batchResponseVerifyItem struct {
	// Valid indicates whether signature matches the signature derived from the input string
	Valid bool `json:"valid" mapstructure:"valid"`

	// Error, if set represents a failure encountered while encrypting a
	// corresponding batch request item
	Error string `json:"error,omitempty" mapstructure:"error"`

	// The return paths through WriteSign in some cases are (nil, err) and others
	// (logical.ErrorResponse(..),nil), and others (logical.ErrorResponse(..),err).
	// For batch processing to successfully mimic previous handling for simple 'input',
	// both output values are needed - though 'err' should never be serialized.
	err error
}

func (b *backend) pathSign() *framework.Path {
	return &framework.Path{
		Pattern: "sign/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The key to use",
			},

			"input": {
				Type:        framework.TypeString,
				Description: "The base64-encoded input data",
			},

			"key_version": {
				Type: framework.TypeInt,
				Description: `The version of the key to use for signing.
Must be 0 (for latest) or a value greater than or equal
to the min_encryption_version configured on the key.`,
			},

			"prehashed": {
				Type:        framework.TypeBool,
				Description: `Set to 'true' when the input is already hashed. `,
			},

			"marshaling_algorithm": {
				Type:        framework.TypeString,
				Default:     "asn1",
				Description: `The method by which to marshal the signature. The default is 'asn1' which is used by openssl and X.509. It can also be set to 'jws' which is used for JWT signatures; setting it to this will also cause the encoding of the signature to be url-safe base64 instead of using standard base64 encoding. Currently only valid for ECDSA P-256 key types".`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathSignWrite,
		},

		HelpSynopsis:    pathSignHelpSyn,
		HelpDescription: pathSignHelpDesc,
	}
}

func (b *backend) pathVerify() *framework.Path {
	return &framework.Path{
		Pattern: "verify/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "The key to use",
			},

			"signature": {
				Type:        framework.TypeString,
				Description: "The signature, including vault header/key version",
			},

			"input": {
				Type:        framework.TypeString,
				Description: "The base64-encoded input data to verify",
			},

			"prehashed": {
				Type:        framework.TypeBool,
				Description: `Set to 'true' when the input is already hashed. `,
			},

			"marshaling_algorithm": {
				Type:        framework.TypeString,
				Default:     "asn1",
				Description: `The method by which to unmarshal the signature when verifying. The default is 'asn1' which is used by openssl and X.509; can also be set to 'jws' which is used for JWT signatures in which case the signature is also expected to be url-safe base64 encoding instead of standard base64 encoding. Currently only valid for ECDSA P-256 key types".`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathVerifyWrite,
		},

		HelpSynopsis:    pathVerifyHelpSyn,
		HelpDescription: pathVerifyHelpDesc,
	}
}

func (b *backend) pathSignWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	ver := d.Get("key_version").(int)

	marshalingStr := d.Get("marshaling_algorithm").(string)
	marshaling, ok := keysutil.MarshalingTypeMap[marshalingStr]
	if !ok {
		return logical.ErrorResponse(fmt.Sprintf("invalid marshaling type %q", marshalingStr)), logical.ErrInvalidRequest
	}

	prehashed := d.Get("prehashed").(bool)

	// Get the policy
	p, _, err := b.lm.GetPolicy(ctx, PolicyRequest{
		Storage: req.Storage,
		Name:    name,
	}, b.GetRandomReader())
	if err != nil {
		return nil, err
	}
	if p == nil {
		return logical.ErrorResponse("encryption key not found"), logical.ErrInvalidRequest
	}
	if !b.System().CachingDisabled() {
		p.Lock(false)
	}

	if !p.Type.SigningSupported() {
		p.Unlock()
		return logical.ErrorResponse(fmt.Sprintf("key type %v does not support signing", p.Type)), logical.ErrInvalidRequest
	}

	batchInputRaw := d.Raw["batch_input"]
	var batchInputItems []batchRequestSignItem
	if batchInputRaw != nil {
		err = mapstructure.Decode(batchInputRaw, &batchInputItems)
		if err != nil {
			p.Unlock()
			return nil, errwrap.Wrapf("failed to parse batch input: {{err}}", err)
		}

		if len(batchInputItems) == 0 {
			p.Unlock()
			return logical.ErrorResponse("missing batch input to process"), logical.ErrInvalidRequest
		}
	} else {
		// use empty string if input is missing - not an error
		batchInputItems = make([]batchRequestSignItem, 1)
		batchInputItems[0] = batchRequestSignItem{
			"input": d.Get("input").(string),
		}
	}

	response := make([]batchResponseSignItem, len(batchInputItems))

	for i, item := range batchInputItems {

		rawInput, ok := item["input"]
		if !ok {
			response[i].Error = "missing input"
			response[i].err = logical.ErrInvalidRequest
			continue
		}

		input, err := base64.StdEncoding.DecodeString(rawInput)
		if err != nil {
			response[i].Error = fmt.Sprintf("unable to decode input as base64: %s", err)
			response[i].err = logical.ErrInvalidRequest
			continue
		}

		if p.Type.HashSignatureInput() && !prehashed {
			var hf = sm3.New()
			hf.Write(input)
			input = hf.Sum(nil)
		}

		sig, err := p.Sign(ver, input, marshaling)
		if err != nil {
			if batchInputRaw != nil {
				response[i].Error = err.Error()
			}
			response[i].err = err
		} else if sig == nil {
			response[i].err = fmt.Errorf("signature could not be computed")
		} else {
			keyVersion := ver
			if keyVersion == 0 {
				keyVersion = p.LatestVersion
			}

			response[i].Signature = sig.Signature
			response[i].PublicKey = sig.PublicKey
			response[i].KeyVersion = keyVersion
		}
	}

	// Generate the response
	resp := &logical.Response{}
	if batchInputRaw != nil {
		resp.Data = map[string]interface{}{
			"batch_results": response,
		}
	} else {
		if response[0].Error != "" || response[0].err != nil {
			p.Unlock()
			if response[0].Error != "" {
				return logical.ErrorResponse(response[0].Error), response[0].err
			}

			return nil, response[0].err
		}

		resp.Data = map[string]interface{}{
			"signature":   response[0].Signature,
			"key_version": response[0].KeyVersion,
		}

		if len(response[0].PublicKey) > 0 {
			resp.Data["public_key"] = response[0].PublicKey
		}
	}

	p.Unlock()
	return resp, nil
}

func (b *backend) pathVerifyWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	batchInputRaw := d.Raw["batch_input"]
	var batchInputItems []batchRequestVerifyItem
	if batchInputRaw != nil {
		err := mapstructure.Decode(batchInputRaw, &batchInputItems)
		if err != nil {
			return nil, errwrap.Wrapf("failed to parse batch input: {{err}}", err)
		}

		if len(batchInputItems) == 0 {
			return logical.ErrorResponse("missing batch input to process"), logical.ErrInvalidRequest
		}
	} else {
		// use empty string if input is missing - not an error
		inputB64 := d.Get("input").(string)

		batchInputItems = make([]batchRequestVerifyItem, 1)
		batchInputItems[0] = batchRequestVerifyItem{
			"input": inputB64,
		}
		if sig, ok := d.GetOk("signature"); ok {
			batchInputItems[0]["signature"] = sig.(string)
		}
	}

	// For simplicity, 'signature' and 'hmac' cannot be mixed across batch_input elements.
	// If one batch_input item is 'signature', they all must be 'signature'.
	// If one batch_input item is 'hmac', they all must be 'hmac'.
	sigFound := false
	missing := false
	for _, v := range batchInputItems {
		if _, ok := v["signature"]; ok {
			sigFound = true
		} else {
			missing = true
		}
	}

	switch {
	case batchInputRaw == nil && !sigFound:
		return logical.ErrorResponse("no 'signature' was given to verify"), logical.ErrInvalidRequest

	case missing && sigFound:
		return logical.ErrorResponse("some elements of batch_input are missing 'signature'"), logical.ErrInvalidRequest

	case missing:
		return logical.ErrorResponse("no batch_input elements have 'signature'"), logical.ErrInvalidRequest
	}

	name := d.Get("name").(string)

	marshalingStr := d.Get("marshaling_algorithm").(string)
	marshaling, ok := keysutil.MarshalingTypeMap[marshalingStr]
	if !ok {
		return logical.ErrorResponse(fmt.Sprintf("invalid marshaling type %q", marshalingStr)), logical.ErrInvalidRequest
	}

	prehashed := d.Get("prehashed").(bool)

	// Get the policy
	p, _, err := b.lm.GetPolicy(ctx, PolicyRequest{
		Storage: req.Storage,
		Name:    name,
	}, b.GetRandomReader())
	if err != nil {
		return nil, err
	}
	if p == nil {
		return logical.ErrorResponse("encryption key not found"), logical.ErrInvalidRequest
	}
	if !b.System().CachingDisabled() {
		p.Lock(false)
	}

	if !p.Type.SigningSupported() {
		p.Unlock()
		return logical.ErrorResponse(fmt.Sprintf("key type %v does not support verification", p.Type)), logical.ErrInvalidRequest
	}

	response := make([]batchResponseVerifyItem, len(batchInputItems))

	for i, item := range batchInputItems {

		rawInput, ok := item["input"]
		if !ok {
			response[i].Error = "missing input"
			response[i].err = logical.ErrInvalidRequest
			continue
		}

		input, err := base64.StdEncoding.DecodeString(rawInput)
		if err != nil {
			response[i].Error = fmt.Sprintf("unable to decode input as base64: %s", err)
			response[i].err = logical.ErrInvalidRequest
			continue
		}

		sig, ok := item["signature"]
		if !ok {
			response[i].Error = "missing signature"
			response[i].err = logical.ErrInvalidRequest
			continue
		}

		if p.Type.HashSignatureInput() && !prehashed {
			hf := sm3.New()
			hf.Write(input)
			input = hf.Sum(nil)
		}

		valid, err := p.VerifySignature(input, marshaling, sig)
		if err != nil {
			switch err.(type) {
			case errutil.UserError:
				response[i].Error = err.Error()
				response[i].err = logical.ErrInvalidRequest
			default:
				if batchInputRaw != nil {
					response[i].Error = err.Error()
				}
				response[i].err = err
			}
		} else {
			response[i].Valid = valid
		}
	}

	// Generate the response
	resp := &logical.Response{}
	if batchInputRaw != nil {
		resp.Data = map[string]interface{}{
			"batch_results": response,
		}
	} else {
		if response[0].Error != "" || response[0].err != nil {
			p.Unlock()
			if response[0].Error != "" {
				return logical.ErrorResponse(response[0].Error), response[0].err
			}
			return nil, response[0].err
		}
		resp.Data = map[string]interface{}{
			"valid": response[0].Valid,
		}
	}

	p.Unlock()
	return resp, nil
}

const pathSignHelpSyn = `Generate a signature for input data using the named key`

const pathSignHelpDesc = `
Generates a signature of the input data using the named key and SM3 hash algorithm.
`
const pathVerifyHelpSyn = `Verify a signature or HMAC for input data created using the named key`

const pathVerifyHelpDesc = `
Verifies a signature or HMAC of the input data using the named key and SM3 hash algorithm.
`
