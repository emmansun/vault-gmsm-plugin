package gmsm

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"

	"github.com/emmansun/gmsm/sm3"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathHash() *framework.Path {
	return &framework.Path{
		Pattern: "hash" + framework.OptionalParamRegex("urlalgorithm"),
		Fields: map[string]*framework.FieldSchema{
			"input": {
				Type:        framework.TypeString,
				Description: "The base64-encoded input data",
			},

			"algorithm": {
				Type:    framework.TypeString,
				Default: "sm3",
				Description: `Algorithm to use (POST body parameter). Valid values are:
* sm3
Defaults to "sm3".`,
			},

			"urlalgorithm": {
				Type:        framework.TypeString,
				Description: `Algorithm to use (POST URL parameter)`,
			},

			"format": {
				Type:        framework.TypeString,
				Default:     "hex",
				Description: `Encoding format to use. Can be "hex" or "base64". Defaults to "hex".`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathHashWrite,
		},

		HelpSynopsis:    pathHashHelpSyn,
		HelpDescription: pathHashHelpDesc,
	}
}

func (b *backend) pathHashWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	inputB64 := d.Get("input").(string)
	format := d.Get("format").(string)
	algorithm := d.Get("urlalgorithm").(string)
	if algorithm == "" {
		algorithm = d.Get("algorithm").(string)
	}

	input, err := base64.StdEncoding.DecodeString(inputB64)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("unable to decode input as base64: %s", err)), logical.ErrInvalidRequest
	}

	switch format {
	case "hex":
	case "base64":
	default:
		return logical.ErrorResponse(fmt.Sprintf("unsupported encoding format %s; must be \"hex\" or \"base64\"", format)), nil
	}

	var hf hash.Hash
	switch algorithm {
	case "sm3":
		hf = sm3.New()
	default:
		return logical.ErrorResponse(fmt.Sprintf("unsupported algorithm %s", algorithm)), nil
	}
	hf.Write(input)
	retBytes := hf.Sum(nil)

	var retStr string
	switch format {
	case "hex":
		retStr = hex.EncodeToString(retBytes)
	case "base64":
		retStr = base64.StdEncoding.EncodeToString(retBytes)
	}

	// Generate the response
	resp := &logical.Response{
		Data: map[string]interface{}{
			"sum": retStr,
		},
	}
	return resp, nil
}

const pathHashHelpSyn = `Generate a hash sum for input data`

const pathHashHelpDesc = `
Generates a hash sum of the given algorithm against the given input data.
`
