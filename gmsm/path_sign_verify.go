package gmsm

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
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

	// Reference is an arbitrary caller supplied string value that will be placed on the
	// batch response to ease correlation between inputs and outputs
	Reference string `json:"reference" mapstructure:"reference"`
}

// BatchRequestVerifyItem represents a request item for batch processing.
// A map type allows us to distinguish between empty and missing values.
type batchRequestVerifyItem map[string]interface{}

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

	// Reference is an arbitrary caller supplied string value that will be placed on the
	// batch response to ease correlation between inputs and outputs
	Reference string `json:"reference" mapstructure:"reference"`
}

const defaultHashAlgorithm = "sm3"

func (b *backend) pathSign() *framework.Path {
	return &framework.Path{
		Pattern: "sign/" + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "sign",
		},
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

			"batch_input": {
				Type: framework.TypeSlice,
				Description: `Specifies a list of items for processing. When this parameter is set,
any supplied 'input' parameters will be ignored. Responses are returned in the
'batch_results' array component of the 'data' element of the response. Any batch output will
preserve the order of the batch input`,
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
		Pattern: "verify/" + framework.GenericNameRegex("name") + framework.OptionalParamRegex("urlalgorithm"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "verify",
			OperationSuffix: "|with-algorithm",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The key to use",
			},

			"signature": {
				Type:        framework.TypeString,
				Description: "The signature, including vault header/key version",
			},

			"hmac": {
				Type:        framework.TypeString,
				Description: "The HMAC, including vault header/key version",
			},

			"cmac": {
				Type:        framework.TypeString,
				Description: "The CMAC, including vault header/key version",
			},

			"input": {
				Type:        framework.TypeString,
				Description: "The base64-encoded input data to verify",
			},

			"urlalgorithm": {
				Type:        framework.TypeString,
				Description: `Hash algorithm to use (POST URL parameter)`,
			},

			"hash_algorithm": {
				Type:    framework.TypeString,
				Default: defaultHashAlgorithm,
				Description: `Hash algorithm to use (POST body parameter). Valid values are:

* sm3
* none

Defaults to "sm3". Not valid for all key types. See note about
none on signing path.`,
			},			

			"algorithm": {
				Type:        framework.TypeString,
				Default:     defaultHashAlgorithm,
				Description: `Deprecated: use "hash_algorithm" instead.`,
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

			"batch_input": {
				Type: framework.TypeSlice,
				Description: `Specifies a list of items for processing. When this parameter is set,
any supplied  'input', 'hmac', 'cmac' or 'signature' parameters will be ignored. Responses are returned in the
'batch_results' array component of the 'data' element of the response. Any batch output will
preserve the order of the batch input`,
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
	p, _, err := b.GetPolicy(ctx, PolicyRequest{
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

	defer p.Unlock()

	if !p.Type.SigningSupported() {
		return logical.ErrorResponse(fmt.Sprintf("key type %v does not support signing", p.Type)), logical.ErrInvalidRequest
	}

	batchInputRaw := d.Raw["batch_input"]
	var batchInputItems []batchRequestSignItem
	if batchInputRaw != nil {
		err = mapstructure.Decode(batchInputRaw, &batchInputItems)
		if err != nil {
			return nil, fmt.Errorf("failed to parse batch input: %w", err)
		}

		if len(batchInputItems) == 0 {
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

		var managedKeyParameters keysutil.ManagedKeyParameters
		if p.Type == KeyType_MANAGED_KEY {
			managedKeySystemView, ok := b.System().(logical.ManagedKeySystemView)
			if !ok {
				return nil, errors.New("unsupported system view")
			}

			managedKeyParameters = keysutil.ManagedKeyParameters{
				ManagedKeySystemView: managedKeySystemView,
				BackendUUID:          b.backendUUID,
				Context:              ctx,
			}
		}

		sig, err := p.SignWithOptions(ver, nil, input, &SigningOptions{Prehashed: prehashed, Marshaling: marshaling, ManagedKeyParams: managedKeyParameters})
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
		// Copy the references
		for i := range batchInputItems {
			response[i].Reference = batchInputItems[i]["reference"]
		}
		resp.Data = map[string]interface{}{
			"batch_results": response,
		}
	} else {
		if response[0].Error != "" || response[0].err != nil {
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

	return resp, nil
}

func (b *backend) pathVerifyWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	batchInputRaw := d.Raw["batch_input"]
	var batchInputItems []batchRequestVerifyItem
	if batchInputRaw != nil {
		err := mapstructure.Decode(batchInputRaw, &batchInputItems)
		if err != nil {
			return nil, fmt.Errorf("failed to parse batch input: %w", err)
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
		if hmac, ok := d.GetOk("hmac"); ok {
			batchInputItems[0]["hmac"] = hmac.(string)
		}
		if cmac, ok := d.GetOk("cmac"); ok {
			batchInputItems[0]["cmac"] = cmac.(string)
		}
		if sig, ok := d.GetOk("signature"); ok {
			batchInputItems[0]["signature"] = sig.(string)
		}
	}

	// For simplicity, 'signature' and 'hmac' cannot be mixed across batch_input elements.
	// If one batch_input item is 'signature', they all must be 'signature'.
	// If one batch_input item is 'hmac', they all must be 'hmac'.
	sigFound := false
	hmacFound := false
	cmacFound := false
	missing := false
	for _, v := range batchInputItems {
		if _, ok := v["signature"]; ok {
			sigFound = true
		} else if _, ok := v["hmac"]; ok {
			hmacFound = true
		} else if _, ok := v["cmac"]; ok {
			cmacFound = true
		} else {
			missing = true
		}
	}

	optionsSet := numBooleansTrue(sigFound, hmacFound, cmacFound)

	switch {
	case batchInputRaw == nil && optionsSet > 1:
		return logical.ErrorResponse("provide one of 'signature', 'hmac' or 'cmac'"), logical.ErrInvalidRequest

	case batchInputRaw == nil && optionsSet == 0:
		return logical.ErrorResponse("missing 'signature', 'hmac' or 'cmac' were given to verify"), logical.ErrInvalidRequest

	case optionsSet > 1:
		return logical.ErrorResponse("elements of batch_input must all provide either 'signature', 'hmac' or 'cmac'"), logical.ErrInvalidRequest

	case missing && sigFound:
		return logical.ErrorResponse("some elements of batch_input are missing 'signature'"), logical.ErrInvalidRequest

	case missing && hmacFound:
		return logical.ErrorResponse("some elements of batch_input are missing 'hmac'"), logical.ErrInvalidRequest

	case missing && cmacFound:
		return logical.ErrorResponse("some elements of batch_input are missing 'cmac'"), logical.ErrInvalidRequest

	case optionsSet == 0:
		return logical.ErrorResponse("no batch_input elements have 'signature', 'hmac' or 'cmac'"), logical.ErrInvalidRequest

	case hmacFound:
		return b.pathHMACVerify(ctx, req, d)

	case cmacFound:
		return b.pathCMACVerify(ctx, req, d)

	}

	name := d.Get("name").(string)

	marshalingStr := d.Get("marshaling_algorithm").(string)
	marshaling, ok := keysutil.MarshalingTypeMap[marshalingStr]
	if !ok {
		return logical.ErrorResponse(fmt.Sprintf("invalid marshaling type %q", marshalingStr)), logical.ErrInvalidRequest
	}

	prehashed := d.Get("prehashed").(bool)

	// Get the policy
	p, _, err := b.GetPolicy(ctx, PolicyRequest{
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
	defer p.Unlock()

	if !p.Type.SigningSupported() {
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

		strInput, err := parseutil.ParseString(rawInput)
		if err != nil {
			response[i].Error = fmt.Sprintf("unable to decode input as base64: %s", err)
			response[i].err = logical.ErrInvalidRequest
			continue
		}

		input, err := base64.StdEncoding.DecodeString(strInput)
		if err != nil {
			response[i].Error = fmt.Sprintf("unable to decode input as base64: %s", err)
			response[i].err = logical.ErrInvalidRequest
			continue
		}

		sigRaw, ok := item["signature"].(string)
		if !ok {
			response[i].Error = "missing signature"
			response[i].err = logical.ErrInvalidRequest
			continue
		}
		sig, err := parseutil.ParseString(sigRaw)
		if err != nil {
			response[i].Error = fmt.Sprintf("failed to parse signature as a string: %s", err)
			response[i].err = logical.ErrInvalidRequest
			continue
		}

		var managedKeyParameters keysutil.ManagedKeyParameters
		if p.Type == KeyType_MANAGED_KEY {
			managedKeySystemView, ok := b.System().(logical.ManagedKeySystemView)
			if !ok {
				return nil, errors.New("unsupported system view")
			}

			managedKeyParameters = keysutil.ManagedKeyParameters{
				ManagedKeySystemView: managedKeySystemView,
				BackendUUID:          b.backendUUID,
				Context:              ctx,
			}
		}

		valid, err := p.VerifySignatureWithOptions(nil, input, sig, &SigningOptions{Prehashed: prehashed, Marshaling: marshaling, ManagedKeyParams: managedKeyParameters})
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
		// Copy the references
		for i := range batchInputItems {
			if ref, err := parseutil.ParseString(batchInputItems[i]["reference"]); err == nil {
				response[i].Reference = ref
			}
		}
		resp.Data = map[string]interface{}{
			"batch_results": response,
		}
	} else {
		if response[0].Error != "" || response[0].err != nil {
			if response[0].Error != "" {
				return logical.ErrorResponse(response[0].Error), response[0].err
			}
			return nil, response[0].err
		}
		resp.Data = map[string]interface{}{
			"valid": response[0].Valid,
		}
	}

	return resp, nil
}

func numBooleansTrue(bools ...bool) int {
	numSet := 0
	for _, value := range bools {
		if value {
			numSet++
		}
	}
	return numSet
}

const pathSignHelpSyn = `Generate a signature for input data using the named key`

const pathSignHelpDesc = `
Generates a signature of the input data using the named key and SM2 sign algorithm.
`
const pathVerifyHelpSyn = `Verify a signature or HMAC for input data created using the named key`

const pathVerifyHelpDesc = `
Verifies a signature or HMAC of the input data using the named key and SM3 hash algorithm.
`
