// Package cms reads the parts of a CMS SignedData (RFC 5652) the extractor needs: each signer's
// digest algorithm and messageDigest, the encapsulated content, and an RFC 3161 TSTInfo. It also
// builds the content-detached copy of an enveloping signature.
//
// Not used: github.com/digitorus/pkcs7, which silently returns zero signers for SignedData v5 with
// OCSP responses as otherRevocationInfo — the structure of ASiC-E CAdES-LTA
// and of our own evidence tokens.
package cms

import (
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/TrustBeat/trustbeat-signature/internal/ber"
)

var (
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OIDTSTInfo       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
)

// SignedData is a parsed ContentInfo wrapping SignedData. Every node keeps its original bytes.
type SignedData struct {
	Raw          []byte
	contentType  *ber.Node // ContentInfo.contentType
	signedData   *ber.Node
	encap        *ber.Node
	Version      int
	EContentType asn1.ObjectIdentifier
	// EContent is the encapsulated content, nil when the signature is detached.
	EContent []byte
	Signers  []Signer
}

// Signer is one SignerInfo.
type Signer struct {
	DigestAlgorithm asn1.ObjectIdentifier
	// MessageDigest is the signed messageDigest attribute; nil when there are no signed attributes.
	MessageDigest  []byte
	HasSignedAttrs bool
}

// Parse reads a DER or BER ContentInfo containing SignedData. Zero padding after it is allowed
// (PDF /Contents).
func Parse(b []byte) (*SignedData, error) {
	ci, err := ber.ParseAll(b)
	if err != nil {
		return nil, err
	}
	if !ci.Is(ber.ClassUniversal, ber.TagSequence) || len(ci.Children) < 2 {
		return nil, errors.New("cms: not a ContentInfo")
	}
	ct, err := ci.Child(0).OID()
	if err != nil || !ct.Equal(oidSignedData) {
		return nil, errors.New("cms: content type is not SignedData")
	}
	wrap := ci.Child(1)
	if !wrap.Is(ber.ClassContext, 0) || len(wrap.Children) != 1 {
		return nil, errors.New("cms: bad [0] content")
	}
	sd := wrap.Child(0)
	if !sd.Is(ber.ClassUniversal, ber.TagSequence) || len(sd.Children) < 4 {
		return nil, errors.New("cms: bad SignedData")
	}
	v, err := sd.Child(0).Int()
	if err != nil {
		return nil, fmt.Errorf("cms: version: %w", err)
	}
	out := &SignedData{Raw: ci.Raw, contentType: ci.Child(0), signedData: sd, encap: sd.Child(2), Version: int(v.Int64())}
	if !out.encap.Is(ber.ClassUniversal, ber.TagSequence) || len(out.encap.Children) == 0 {
		return nil, errors.New("cms: bad EncapsulatedContentInfo")
	}
	if out.EContentType, err = out.encap.Child(0).OID(); err != nil {
		return nil, err
	}
	if e := out.encap.Child(1); e != nil {
		if !e.Is(ber.ClassContext, 0) || len(e.Children) != 1 {
			return nil, errors.New("cms: bad eContent")
		}
		out.EContent = e.Child(0).Bytes()
		if out.EContent == nil {
			out.EContent = []byte{}
		}
	}
	infos := sd.Children[len(sd.Children)-1]
	if !infos.Is(ber.ClassUniversal, ber.TagSet) {
		return nil, errors.New("cms: signerInfos is not a SET")
	}
	for i, si := range infos.Children {
		s, err := parseSigner(si)
		if err != nil {
			return nil, fmt.Errorf("cms: signer %d: %w", i, err)
		}
		out.Signers = append(out.Signers, s)
	}
	if len(out.Signers) == 0 {
		return nil, errors.New("cms: no signers")
	}
	return out, nil
}

func parseSigner(si *ber.Node) (Signer, error) {
	var s Signer
	if !si.Is(ber.ClassUniversal, ber.TagSequence) || len(si.Children) < 5 {
		return s, errors.New("bad SignerInfo")
	}
	alg, err := algorithm(si.Child(2))
	if err != nil {
		return s, err
	}
	s.DigestAlgorithm = alg
	if a := si.Child(3); a.Is(ber.ClassContext, 0) {
		s.HasSignedAttrs = true
		for _, attr := range a.Children {
			t, err := attr.Child(0).OID()
			if err != nil {
				return s, err
			}
			if t.Equal(oidMessageDigest) {
				vals := attr.Child(1)
				if vals == nil || len(vals.Children) != 1 || !vals.Child(0).Is(ber.ClassUniversal, ber.TagOctetString) {
					return s, errors.New("bad messageDigest attribute")
				}
				s.MessageDigest = vals.Child(0).Bytes()
			}
		}
	}
	return s, nil
}

func algorithm(n *ber.Node) (asn1.ObjectIdentifier, error) {
	if !n.Is(ber.ClassUniversal, ber.TagSequence) || len(n.Children) == 0 {
		return nil, errors.New("bad AlgorithmIdentifier")
	}
	return n.Child(0).OID()
}

// Detached returns the content-detached copy of an enveloping signature: the same ContentInfo
// with eContent removed. Every other element — certificates, CRLs, signerInfos, and so the
// signatures themselves — is copied byte-exact; only the three wrappers around the removed field
// get new (DER) lengths.
func (s *SignedData) Detached() []byte {
	if s.EContent == nil {
		return s.Raw
	}
	encap := ber.Encode(0x30, s.encap.Child(0).Raw)
	var body []byte
	for i, c := range s.signedData.Children {
		if i == 2 {
			body = append(body, encap...)
		} else {
			body = append(body, c.Raw...)
		}
	}
	sd := ber.Encode(0x30, body)
	return ber.Encode(0x30, append(append([]byte{}, s.contentType.Raw...), ber.Encode(0xa0, sd)...))
}

// SignerInfosRaw is the original encoding of the signerInfos SET (for tests of Detached).
func (s *SignedData) SignerInfosRaw() []byte {
	return s.signedData.Children[len(s.signedData.Children)-1].Raw
}

// MessageImprint is the hashed message of an RFC 3161 TSTInfo.
type MessageImprint struct {
	Algorithm asn1.ObjectIdentifier
	Digest    []byte
}

// TimestampImprint reads the messageImprint from a timestamp token's encapsulated TSTInfo.
func (s *SignedData) TimestampImprint() (MessageImprint, error) {
	var m MessageImprint
	if !s.EContentType.Equal(OIDTSTInfo) || s.EContent == nil {
		return m, errors.New("cms: not a timestamp token")
	}
	tst, err := ber.ParseAll(s.EContent)
	if err != nil {
		return m, err
	}
	mi := tst.Child(2)
	if !tst.Is(ber.ClassUniversal, ber.TagSequence) || !mi.Is(ber.ClassUniversal, ber.TagSequence) || len(mi.Children) != 2 {
		return m, errors.New("cms: bad TSTInfo")
	}
	if m.Algorithm, err = algorithm(mi.Child(0)); err != nil {
		return m, err
	}
	m.Digest = mi.Child(1).Bytes()
	return m, nil
}
