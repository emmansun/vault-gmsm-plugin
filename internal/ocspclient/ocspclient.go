// Package ocspclient asks an OCSP responder about a certificate and reads the
// answer it gets back.
//
// It is written by hand for the same reason the responder is: the OCSP package
// in golang.org/x/crypto hashes the whole subjectPublicKeyInfo where RFC 6960
// hashes the key inside it, and knows no SM3, so it can speak neither to nor for
// an SM2 authority. The tests of the backend and the CI walkthrough share this
// client, because an answer is only worth something when code other than the
// code that wrote it can read it.
package ocspclient

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/smx509"
)

// The statuses a response may carry. The numbers are the ones of RFC 6960
// section 4.2.1.
const (
	Successful       = 0
	MalformedRequest = 1
	InternalError    = 2
	Unauthorized     = 6
)

// CertStatus is what a responder knows about one certificate.
type CertStatus int

// The three answers a certificate status allows.
const (
	CertGood CertStatus = iota
	CertRevoked
	CertUnknown
)

func (s CertStatus) String() string {
	switch s {
	case CertGood:
		return "good"
	case CertRevoked:
		return "revoked"
	case CertUnknown:
		return "unknown"
	}

	return fmt.Sprintf("status(%d)", int(s))
}

var (
	oidBasic      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
	oidSM2WithSM3 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}
	oidSM3        = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401}
)

// Request builds the DER request that asks about one serial, naming the
// authority that should have issued it. Both identifiers are SM3 digests, which
// is the digest a client of an SM2 authority has.
func Request(serial *big.Int, issuer *smx509.Certificate) ([]byte, error) {
	if issuer == nil {
		return nil, errors.New("no authority was named")
	}
	if serial == nil || serial.Sign() < 0 {
		return nil, errors.New("the serial number is not a positive number")
	}

	key, err := publicKeyBits(issuer)
	if err != nil {
		return nil, err
	}

	digest := sm3.New()
	digest.Write(issuer.RawSubject)
	nameHash := digest.Sum(nil)

	digest.Reset()
	digest.Write(key)
	keyHash := digest.Sum(nil)

	return asn1.Marshal(ocspRequest{TBSRequest: tbsRequest{
		RequestList: []requestEntry{{Cert: certID{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSM3, Parameters: asn1.NullRawValue},
			NameHash:      nameHash,
			KeyHash:       keyHash,
			SerialNumber:  serial,
		}}},
	}})
}

// publicKeyBits returns the key as the bit string of subjectPublicKeyInfo holds
// it, which is what RFC 6960 digests for issuerKeyHash.
func publicKeyBits(cert *smx509.Certificate) ([]byte, error) {
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &info); err != nil {
		return nil, fmt.Errorf("could not read the public key of the authority: %w", err)
	}

	return info.PublicKey.RightAlign(), nil
}

// Response is an answer as a client reads it. The bytes the signature covers are
// kept out of sight, so that Verify can check them without reading the answer
// twice.
type Response struct {
	Status int

	// The fields below describe the one certificate that was asked about. They
	// are zero when Status is not Successful.

	CertStatus CertStatus
	Serial     *big.Int
	RevokedAt  time.Time

	// RevocationReason is the code of RFC 5280 the certificate was revoked
	// with, and zero when the responder did not state one.
	RevocationReason int

	ProducedAt time.Time
	ThisUpdate time.Time
	NextUpdate time.Time

	tbs         []byte
	signature   []byte
	sigAlg      pkix.AlgorithmIdentifier
	responderID asn1.RawValue
}

// Parse reads an answer without checking its signature, which is what a client
// that only wants to know what a responder said needs.
func Parse(der []byte) (*Response, error) {
	var envelope responseEnvelope
	rest, err := asn1.Unmarshal(der, &envelope)
	if err != nil {
		return nil, fmt.Errorf("the answer is not an OCSP response: %w", err)
	}
	if len(rest) > 0 {
		return nil, errors.New("the answer carries data after its end")
	}

	response := &Response{Status: int(envelope.Status)}
	if envelope.Status != Successful {
		return response, nil
	}

	if len(envelope.ResponseBytes.Bytes) == 0 {
		return nil, errors.New("an answer that claims success carries nothing")
	}
	var bytes responseBytes
	if _, err := asn1.Unmarshal(envelope.ResponseBytes.Bytes, &bytes); err != nil {
		return nil, fmt.Errorf("could not read the answer of the responder: %w", err)
	}
	if !bytes.Type.Equal(oidBasic) {
		return nil, fmt.Errorf("the answer is of type %v, which this client does not read", bytes.Type)
	}

	var basic basicResponse
	if rest, err := asn1.Unmarshal(bytes.Response, &basic); err != nil {
		return nil, fmt.Errorf("could not read the signed answer: %w", err)
	} else if len(rest) > 0 {
		return nil, errors.New("the signed answer carries data after its end")
	}

	var data responseData
	if _, err := asn1.Unmarshal(basic.TBSResponse.FullBytes, &data); err != nil {
		return nil, fmt.Errorf("could not read the body of the answer: %w", err)
	}
	if len(data.Responses) != 1 {
		return nil, fmt.Errorf("the responder answered about %d certificates, want one", len(data.Responses))
	}

	answer := data.Responses[0]
	if err := response.readStatus(answer.CertStatus); err != nil {
		return nil, err
	}

	response.Serial = answer.CertID.SerialNumber
	response.ProducedAt = data.ProducedAt
	response.ThisUpdate = answer.ThisUpdate
	response.NextUpdate = answer.NextUpdate
	response.tbs = basic.TBSResponse.FullBytes
	response.signature = basic.Signature.Bytes
	response.sigAlg = basic.SignatureAlgorithm
	response.responderID = data.ResponderID

	return response, nil
}

// Verify reads an answer and checks that it was signed by the authority it is
// checked against. A refusal carries no signature, and is returned as it is:
// what such an answer says is its status.
func Verify(der []byte, issuer *smx509.Certificate) (*Response, error) {
	response, err := Parse(der)
	if err != nil {
		return nil, err
	}
	if response.Status != Successful {
		return response, nil
	}

	if !response.sigAlg.Algorithm.Equal(oidSM2WithSM3) {
		return nil, fmt.Errorf("the answer is signed with %v, want %v", response.sigAlg.Algorithm, oidSM2WithSM3)
	}

	// The responder names itself with the subject of the authority, which is a
	// choice of its own, so it is compared as it stands.
	if response.responderID.Class != asn1.ClassContextSpecific || response.responderID.Tag != 1 ||
		!bytes.Equal(response.responderID.Bytes, issuer.RawSubject) {
		return nil, errors.New("the answer was not given under the authority it was checked against")
	}

	key, ok := issuer.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("the authority carries a %T, not an SM2 key", issuer.PublicKey)
	}
	if !sm2.VerifyASN1WithSM2(key, nil, response.tbs, response.signature) {
		return nil, errors.New("the signature of the answer does not verify")
	}

	return response, nil
}

// readStatus reads the choice that says whether the certificate is good,
// revoked or unknown. Revoked is the only alternative with content.
func (r *Response) readStatus(status asn1.RawValue) error {
	if status.Class != asn1.ClassContextSpecific {
		return fmt.Errorf("the certificate status is of class %d", status.Class)
	}

	switch status.Tag {
	case 0:
		r.CertStatus = CertGood
	case 1:
		r.CertStatus = CertRevoked
		var info struct {
			Time   time.Time       `asn1:"generalized"`
			Reason asn1.Enumerated `asn1:"explicit,tag:0,optional"`
		}
		if _, err := asn1.Unmarshal(status.Bytes, &info); err != nil {
			return fmt.Errorf("could not read the time of the revocation: %w", err)
		}
		r.RevokedAt = info.Time
		r.RevocationReason = int(info.Reason)
	case 2:
		r.CertStatus = CertUnknown
	default:
		return fmt.Errorf("the certificate status has tag %d", status.Tag)
	}

	return nil
}

// The wire types are written out rather than borrowed, because the ones in
// golang.org/x/crypto/ocsp name the fields of the RFC differently enough that a
// copy would read as a second dialect of the same protocol.

type certID struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	KeyHash       []byte
	SerialNumber  *big.Int
}

type requestEntry struct {
	Cert certID
}

type tbsRequest struct {
	RequestList []requestEntry
}

type ocspRequest struct {
	TBSRequest tbsRequest
}

type responseEnvelope struct {
	Status        asn1.Enumerated
	ResponseBytes asn1.RawValue `asn1:"optional,explicit,tag:0"`
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

type responseData struct {
	ResponderID asn1.RawValue
	ProducedAt  time.Time `asn1:"generalized"`
	Responses   []singleResponse
}

type singleResponse struct {
	CertID     certID
	CertStatus asn1.RawValue
	ThisUpdate time.Time `asn1:"generalized"`
	NextUpdate time.Time `asn1:"optional,explicit,tag:0,generalized"`
}
