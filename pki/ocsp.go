package pki

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/smx509"
)

// The responder speaks the protocol of RFC 6960 by itself rather than through
// golang.org/x/crypto/ocsp. That package hashes the whole subjectPublicKeyInfo
// where the RFC asks for the key inside it, so a request built with it names an
// issuer that nothing else recognises, and it knows no SM3. What an SM2
// authority signs has to be checkable by the clients it serves.
const (
	// ocspContentType is what a response is served as, whatever it answers.
	ocspContentType = "application/ocsp-response"

	// ocspValidity is how long an answer is good for. Stating it is what lets a
	// client stop trusting an answer it cannot refresh.
	ocspValidity = 12 * time.Hour

	// ocspMaxRequest bounds what is read: a request about one certificate is
	// under a hundred bytes, and a request about more is not answered here.
	ocspMaxRequest = 2048
)

// The statuses of a response that does not answer the question it was asked.
// The numbers are the ones of RFC 6960 section 4.2.1.
const (
	ocspMalformed    ocspResponseStatus = 1
	ocspInternal     ocspResponseStatus = 2
	ocspUnauthorized ocspResponseStatus = 6
)

// The three answers a certificate status allows. The numbers are the tags of
// the CertStatus choice, which is how the answer is written out as well.
const (
	ocspGood = iota
	ocspRevoked
	ocspUnknown
)

var (
	// oidOCSPBasic names a response that carries a signed answer rather than
	// only a status.
	oidOCSPBasic = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}

	// oidSM2WithSM3 is what the authority signs every answer with.
	oidSM2WithSM3 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}

	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidSM3    = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401}
)

type ocspResponseStatus int

// certID is the question a request asks: which authority issued the
// certificate, named by two digests of it, and which serial it carries.
type certID struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	KeyHash       []byte
	SerialNumber  *big.Int
}

// ocspRequest is a request this responder can answer. A signature on it is
// dropped: it says who is asking, and the answer does not depend on that.
type ocspRequest struct {
	certID certID

	// hash is the digest the client used for the two identifiers above, so the
	// authority it holds has to be hashed the same way before comparing.
	hash func() hash.Hash
}

type tbsRequest struct {
	Version int `asn1:"optional,explicit,tag:0,default:0"`

	// RequestorName is a GeneralName, which is a choice of its own; it is kept
	// as it is rather than read, because a request that names who is asking is
	// answered the same way as one that does not.
	RequestorName asn1.RawValue `asn1:"optional,explicit,tag:1"`

	RequestList []struct {
		Cert certID
	}
}

type requestEnvelope struct {
	TBSRequest tbsRequest
	Signature  asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

// parseOCSPRequest reads a DER request. Only the first request of a message
// with exactly one is answered, because a responder that picks one of several
// leaves the client guessing which.
func parseOCSPRequest(der []byte) (*ocspRequest, error) {
	if len(der) == 0 {
		return nil, errors.New("the request is empty")
	}

	var envelope requestEnvelope
	rest, err := asn1.Unmarshal(der, &envelope)
	if err != nil {
		return nil, fmt.Errorf("the request is not an OCSP request: %w", err)
	}
	if len(rest) > 0 {
		return nil, errors.New("the request carries data after its end")
	}

	switch count := len(envelope.TBSRequest.RequestList); count {
	case 0:
		return nil, errors.New("the request names no certificate")
	case 1:
	default:
		return nil, fmt.Errorf("the request names %d certificates; this responder answers one at a time", count)
	}

	id := envelope.TBSRequest.RequestList[0].Cert
	newHash, ok := ocspHashFor(id.HashAlgorithm.Algorithm)
	if !ok {
		return nil, fmt.Errorf("the request asks for a %v digest, which this responder does not compute",
			id.HashAlgorithm.Algorithm)
	}
	if id.SerialNumber == nil {
		return nil, errors.New("the request names no serial number")
	}

	return &ocspRequest{certID: id, hash: newHash}, nil
}

// ocspHashFor maps the digest a client named to one this mount can compute. The
// list is the one a client is likely to use; SM3 is there because a client of
// this CA is an SM2 one.
func ocspHashFor(oid asn1.ObjectIdentifier) (func() hash.Hash, bool) {
	switch {
	case oid.Equal(oidSHA1):
		return sha1.New, true
	case oid.Equal(oidSHA256):
		return sha256.New, true
	case oid.Equal(oidSHA384):
		return sha512.New384, true
	case oid.Equal(oidSHA512):
		return sha512.New, true
	case oid.Equal(oidSM3):
		return sm3.New, true
	}

	return nil, false
}

// ocspIssuerMatches says whether a request was made about this authority. Both
// identifiers have to agree: the same serial may exist under another authority,
// and answering for it here would vouch for a certificate this one did not
// sign.
func ocspIssuerMatches(authority *smx509.Certificate, request *ocspRequest) (bool, error) {
	// RFC 6960 hashes the key itself, which is the content of the
	// subjectPublicKey bit string, not the whole structure it sits in.
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(authority.RawSubjectPublicKeyInfo, &info); err != nil {
		return false, fmt.Errorf("could not read the public key of the authority: %w", err)
	}

	digest := request.hash()
	digest.Write(info.PublicKey.RightAlign())
	keyHash := digest.Sum(nil)

	digest.Reset()
	digest.Write(authority.RawSubject)
	nameHash := digest.Sum(nil)

	return bytes.Equal(request.certID.NameHash, nameHash) && bytes.Equal(request.certID.KeyHash, keyHash), nil
}

// ocspAnswer is what the mount knows about one serial.
type ocspAnswer struct {
	status    int
	revokedAt time.Time
}

// singleResponse is one answered certificate. The status is written out by hand
// because it is a choice rather than a field, and good and unknown have no
// content at all.
type singleResponse struct {
	CertID     certID
	CertStatus asn1.RawValue
	ThisUpdate time.Time `asn1:"generalized"`
	NextUpdate time.Time `asn1:"optional,explicit,tag:0,generalized"`
}

type responseData struct {
	ResponderID asn1.RawValue
	ProducedAt  time.Time `asn1:"generalized"`
	Responses   []singleResponse
}

type responseBytes struct {
	Type     asn1.ObjectIdentifier
	Response []byte
}

type basicResponse struct {
	TBSResponse        asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
}

type responseEnvelope struct {
	Status        asn1.Enumerated
	ResponseBytes asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

// signOCSPResponse writes the answer to one request and signs it with the
// authority the request named.
func signOCSPResponse(id certID, authority *smx509.Certificate, signer *sm2.PrivateKey, answer ocspAnswer) ([]byte, error) {
	status, err := ocspCertStatus(answer)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	data := responseData{
		// The responder is the authority itself, named rather than keyed, so a
		// client that holds the certificate it was issued under already holds
		// the key that checks this signature.
		ResponderID: asn1.RawValue{Class: 2, Tag: 1, IsCompound: true, Bytes: authority.RawSubject},
		ProducedAt:  now,
		Responses: []singleResponse{{
			CertID:     id,
			CertStatus: status,
			ThisUpdate: now,
			NextUpdate: now.Add(ocspValidity),
		}},
	}

	tbs, err := asn1.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("could not encode the answer: %w", err)
	}

	// The signature covers the encoded answer as it stands, so the bytes are
	// kept instead of being encoded again: SM2 signs the message it is handed,
	// and a second encoding would be a different one.
	signature, err := crypto.SignMessage(signer, rand.Reader, tbs, sm2.DefaultSM2SignerOpts)
	if err != nil {
		return nil, fmt.Errorf("could not sign the answer: %w", err)
	}

	basic, err := asn1.Marshal(basicResponse{
		TBSResponse:        asn1.RawValue{FullBytes: tbs},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSM2WithSM3, Parameters: asn1.NullRawValue},
		Signature:          asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
	if err != nil {
		return nil, fmt.Errorf("could not encode the signed answer: %w", err)
	}

	content, err := asn1.Marshal(responseBytes{Type: oidOCSPBasic, Response: basic})
	if err != nil {
		return nil, fmt.Errorf("could not encode the answer of the responder: %w", err)
	}

	return asn1.Marshal(responseEnvelope{
		ResponseBytes: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: content},
	})
}

// ocspCertStatus encodes the choice the answer falls on. Revoked is the only
// alternative with content: the time the revocation was recorded. The reason is
// left out, because this mount records a time and nothing else.
func ocspCertStatus(answer ocspAnswer) (asn1.RawValue, error) {
	switch answer.status {
	case ocspGood:
		return asn1.RawValue{Class: 2, Tag: 0}, nil
	case ocspUnknown:
		return asn1.RawValue{Class: 2, Tag: 2}, nil
	}

	info, err := asn1.Marshal(struct {
		Time time.Time `asn1:"generalized"`
	}{answer.revokedAt.UTC()})
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("could not encode the revocation time: %w", err)
	}

	return asn1.RawValue{Class: 2, Tag: 1, IsCompound: true, Bytes: info}, nil
}

// ocspErrorResponse is the whole message when a request cannot be answered. It
// carries no signature: the status is the message.
func ocspErrorResponse(status ocspResponseStatus) []byte {
	der, err := asn1.Marshal(responseEnvelope{Status: asn1.Enumerated(status)})
	if err != nil {
		// Encoding a number cannot fail, and an empty body is what a client
		// reads as a responder that broke, which is what happened.
		return nil
	}

	return der
}
