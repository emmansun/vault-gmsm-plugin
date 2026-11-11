package pki

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathOCSP takes the request in a field and answers with the DER response.
//
// RFC 6960 also allows the request to be the body of the POST, and Vault does
// hand the raw body to a backend of its own. It never reaches a plugin: what
// crosses the plugin boundary is the request data, not the HTTP request. So the
// request travels base64-encoded, in a field here and in the path below.
func (b *backend) pathOCSP() *framework.Path {
	return &framework.Path{
		Pattern: "ocsp$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "query",
			OperationSuffix: "ocsp",
		},

		Fields: map[string]*framework.FieldSchema{
			"request": {
				Type:        framework.TypeString,
				Description: "Base64 encoding of a DER OCSP request, asking about one certificate.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathOCSPWrite,
		},

		HelpSynopsis:    pathOCSPHelpSyn,
		HelpDescription: pathOCSPHelpDesc,
	}
}

// pathOCSPRequest answers the GET form of the same request, with the encoding
// in the path. A client that escapes the base64 alphabet into a URL arrives
// here, which is why the captured value is unescaped before it is decoded.
func (b *backend) pathOCSPRequest() *framework.Path {
	return &framework.Path{
		Pattern: "ocsp/" + framework.MatchAllRegex("request"),

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "query",
			OperationSuffix: "ocsp",
		},

		Fields: map[string]*framework.FieldSchema{
			"request": {
				Type:        framework.TypeString,
				Description: "Base64 encoding of a DER OCSP request, asking about one certificate.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathOCSPRead,
		},

		HelpSynopsis:    pathOCSPHelpSyn,
		HelpDescription: pathOCSPHelpDesc,
	}
}

func (b *backend) pathOCSPWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return b.answerOCSP(ctx, req, d.Get("request").(string)), nil
}

func (b *backend) pathOCSPRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	encoded := strings.TrimSpace(d.Get("request").(string))
	if unescaped, err := url.PathUnescape(encoded); err == nil {
		encoded = unescaped
	}

	return b.answerOCSP(ctx, req, encoded), nil
}

// answerOCSP turns whatever a client sent into a response of the protocol, so
// that a client which is refused can tell that apart from a responder that is
// not there. A JSON error would reach it as neither.
func (b *backend) answerOCSP(ctx context.Context, req *logical.Request, encoded string) *logical.Response {
	der, err := decodeOCSPRequest(encoded)
	if err != nil {
		return b.ocspFailure(http.StatusBadRequest, ocspMalformed, err)
	}

	request, err := parseOCSPRequest(der)
	if err != nil {
		return b.ocspFailure(http.StatusBadRequest, ocspMalformed, err)
	}

	issuer, err := b.ocspIssuer(ctx, req.Storage, request)
	if err != nil {
		return b.ocspFailure(http.StatusInternalServerError, ocspInternal, err)
	}
	if issuer == nil {
		return b.ocspFailure(http.StatusUnauthorized, ocspUnauthorized,
			errors.New("no authority of this mount signed the certificate the request names"))
	}
	if err := issuer.checkUsage(usageOCSP, "answer status queries"); err != nil {
		return b.ocspFailure(http.StatusUnauthorized, ocspUnauthorized, err)
	}

	body, err := b.signOCSPResponse(ctx, req.Storage, issuer, request)
	if err != nil {
		return b.ocspFailure(http.StatusInternalServerError, ocspInternal, err)
	}

	return ocspResponse(http.StatusOK, body)
}

// ocspFailure answers in the protocol and keeps the reason where an operator
// can find it. The endpoint is unauthenticated and may be polled by every
// client of the CA, so the reason is a debug line rather than a response header.
func (b *backend) ocspFailure(code int, status ocspResponseStatus, cause error) *logical.Response {
	b.Logger().Debug("ocsp: " + cause.Error())

	return ocspResponse(code, ocspErrorResponse(status))
}

func ocspResponse(code int, body []byte) *logical.Response {
	return &logical.Response{Data: map[string]interface{}{
		logical.HTTPContentType: ocspContentType,
		logical.HTTPStatusCode:  code,
		logical.HTTPRawBody:     body,
	}}
}

// decodeOCSPRequest reads the base64 a client sent, with the bound stated in
// the message so that an oversized request is not mistaken for a broken one.
func decodeOCSPRequest(encoded string) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, errors.New("no request was sent")
	}

	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("the request is not base64: %w", err)
	}
	if len(der) > ocspMaxRequest {
		return nil, fmt.Errorf("the request is %d bytes long, more than the %d this responder reads",
			len(der), ocspMaxRequest)
	}

	return der, nil
}

// ocspIssuer finds the authority a request was made about. It answers with
// nothing when none of them matches, which the caller reports as unauthorized:
// a responder cannot vouch for a certificate it did not sign.
func (b *backend) ocspIssuer(ctx context.Context, s logical.Storage, request *ocspRequest) (*issuerEntry, error) {
	issuers, err := b.issuers(ctx, s)
	if err != nil {
		return nil, err
	}

	for _, issuer := range issuers {
		cert, err := issuer.certificate()
		if err != nil {
			return nil, err
		}

		matches, err := ocspIssuerMatches(cert, request)
		if err != nil {
			return nil, err
		}
		if matches {
			return issuer, nil
		}
	}

	return nil, nil
}

// signOCSPResponse answers with the authority that signed the certificate the
// request names. Answering signs but changes nothing, so it holds the read lock
// and waits only for a change of the authority it is answering about.
func (b *backend) signOCSPResponse(ctx context.Context, s logical.Storage, issuer *issuerEntry, request *ocspRequest) ([]byte, error) {
	b.caMu.RLock()
	defer b.caMu.RUnlock()

	cert, err := issuer.certificate()
	if err != nil {
		return nil, err
	}

	signer, err := b.issuerSigner(ctx, s, issuer)
	if err != nil {
		return nil, err
	}
	defer b.closeSigner(signer)

	answer, err := b.ocspStatus(ctx, s, issuer, request.certID.SerialNumber)
	if err != nil {
		return nil, err
	}

	config, err := b.crlConfig(ctx, s)
	if err != nil {
		return nil, err
	}

	return signOCSPResponse(request.certID, cert, signer, answer, config.ocspLifetime())
}

// ocspStatus says what the mount knows about one serial. The certificate record
// decides whether the authority in question issued it at all; only then does the
// revocation say it is no longer good. A serial of another authority is unknown
// here, because the list that would report its revocation belongs to that one.
func (b *backend) ocspStatus(ctx context.Context, s logical.Storage, issuer *issuerEntry, serial *big.Int) (ocspAnswer, error) {
	key := serialHex(serial)

	defaultID, err := b.issuerID(ctx, s)
	if err != nil {
		return ocspAnswer{}, err
	}

	record, err := b.certificateRecord(ctx, s, key)
	if err != nil {
		return ocspAnswer{}, err
	}
	if record == nil || !belongsToIssuer(record.IssuerID, issuer.ID, defaultID) {
		return ocspAnswer{status: ocspUnknown}, nil
	}

	revocation, err := b.revocationRecord(ctx, s, key)
	if err != nil {
		return ocspAnswer{}, err
	}
	if revocation == nil || !belongsToIssuer(revocation.IssuerID, issuer.ID, defaultID) {
		return ocspAnswer{status: ocspGood}, nil
	}

	return ocspAnswer{status: ocspRevoked, revokedAt: time.Unix(revocation.RevocationTime, 0), reason: revocation.Reason}, nil
}

const pathOCSPHelpSyn = `Ask whether a certificate this mount issued is still good`

const pathOCSPHelpDesc = `
Answers the OCSP request it is given, in the protocol of RFC 6960, with a
response signed by the authority that issued the certificate. The answer is
good, revoked or unknown; a certificate of an authority this mount does not
hold is not answered at all.

The request is DER, and it travels base64-encoded: in the request field of a
write, or in the path of a read. Vault hands the raw body of a request to a
backend of its own, but not to a plugin, so a client that only sends DER as the
body of a POST cannot be served here.
`
