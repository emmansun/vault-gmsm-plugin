// Package pki implements a certificate authority for SM2 keys.
//
// It is a plugin of its own rather than a set of paths inside the gmsm backend.
// A CA holds an issuer, roles, issued certificates, revocations and a CRL; that
// is state the data-in-transit backend deliberately does not have, and keeping
// the two apart keeps their storage, seal wrapping and backup stories separate.
// The API follows the PKI secrets engine of HashiCorp Vault so that scripts and
// documentation port, with the differences listed in docs/pki.md.
package pki

import (
	"context"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	operationPrefix = "pki-gmsm"

	version = "v0.1.0"
)

const backendHelp = `
The pki-gmsm backend issues SM2 certificates from a certificate authority it
holds in the mount. The authority is either generated here as a self-signed
root, adopted from a bundle, or completed from a certificate signed elsewhere;
a mount can hold several of them, and root/rotate adds one beside the others.
`

// Factory is the entry point Vault calls to create the backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := Backend(ctx, conf)
	if err != nil {
		return nil, err
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// Backend builds the backend without setting it up, which is what the tests and
// the plugin binary need in that order.
func Backend(ctx context.Context, conf *logical.BackendConfig) (*backend, error) {
	var b backend
	b.Backend = &framework.Backend{
		Help: backendHelp,

		// Only the key material is sensitive. The issuer certificate, the roles,
		// the issued certificates and the revocations are all data the operator
		// is allowed to read through the API.
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{keyPrefix},

			// A client asks a responder about a certificate it was handed; it
			// holds no token of this Vault, which is the point of the endpoint.
			Unauthenticated: []string{"ocsp", "ocsp/*"},
		},

		Paths: []*framework.Path{
			// Fixed paths are registered before the patterns they extend, and
			// every one of them ends in "$" so that "ca" cannot capture "ca/pem".
			b.pathRootGenerate(),
			b.pathRootRotate(),
			b.pathRootSignIntermediate(),
			b.pathRootDelete(),
			b.pathIntermediateGenerate(),
			b.pathIntermediateSetSigned(),
			b.pathCA(),
			b.pathCAPEM(),
			b.pathCAChain(),
			b.pathIssuersList(),
			b.pathIssuerDefault(),
			b.pathIssuerCRLRotate(),
			b.pathIssuerCRLPEM(),
			b.pathIssuerCRLDER(),
			b.pathIssuerCRL(),
			b.pathIssuer(),
			b.pathRoles(),
			b.pathRolesList(),
			b.pathIssue(),
			b.pathSign(),
			b.pathRevoke(),
			b.pathCert(),
			b.pathCertsList(),
			b.pathCRL(),
			b.pathCRLPEM(),
			b.pathCRLDER(),
			b.pathCRLRotate(),
			b.pathOCSP(),
			b.pathOCSPRequest(),
			b.pathConfigCA(),
			b.pathConfigURLs(),
			b.pathTidy(),
		},

		BackendType:    logical.TypeLogical,
		RunningVersion: version,
	}

	return &b, nil
}

type backend struct {
	*framework.Backend

	// caMu serialises the operations that read a record, decide, and write it
	// back: creating the issuer, revoking a certificate and rebuilding the CRL.
	// Vault sends writes to the active node only, so one lock per mount is
	// enough and cheaper to reason about than a lock per record.
	caMu sync.Mutex
}
