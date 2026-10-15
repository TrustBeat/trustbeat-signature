package extract

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Errors of VerifyXMLSignatureValue. ErrXMLUnsupported means it could not be checked here (an
// algorithm or curve Go does not offer, such as brainpool), not that it is wrong.
var (
	ErrXMLUnsupported  = errors.New("not supported by this verifier")
	ErrXMLBadSignature = errors.New("the SignatureValue does not verify")
)

var xmlSignatureMethods = map[string]struct {
	hash crypto.Hash
	kind string // rsa | rsa-pss | ecdsa
}{
	"http://www.w3.org/2000/09/xmldsig#rsa-sha1":             {crypto.SHA1, "rsa"},
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha224":      {crypto.SHA224, "rsa"},
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":      {crypto.SHA256, "rsa"},
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":      {crypto.SHA384, "rsa"},
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":      {crypto.SHA512, "rsa"},
	"http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1": {crypto.SHA256, "rsa-pss"},
	"http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1": {crypto.SHA384, "rsa-pss"},
	"http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1": {crypto.SHA512, "rsa-pss"},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1":      {crypto.SHA1, "ecdsa"},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224":    {crypto.SHA224, "ecdsa"},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256":    {crypto.SHA256, "ecdsa"},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384":    {crypto.SHA384, "ecdsa"},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512":    {crypto.SHA512, "ecdsa"},
}

// VerifyXMLSignatureValue checks an XML signature's SignatureValue over its canonical SignedInfo with
// a certificate from its KeyInfo — without following its references (their digests are the binding,
// checked separately). sig is a signature as preserved: a whole document whose top ds:Signature is the
// one to check. Returns the certificate that verified it.
func VerifyXMLSignatureValue(sig []byte) (*x509.Certificate, error) {
	x, err := loadXML(sig)
	if err != nil {
		return nil, err
	}
	tops := topSignatures(x.doc.Root())
	if len(tops) != 1 {
		return nil, fmt.Errorf("%d top-level signatures, want 1", len(tops))
	}
	s := tops[0]
	si := dsChild(s, "SignedInfo")
	sv := dsChild(s, "SignatureValue")
	if si == nil || sv == nil {
		return nil, errors.New("no SignedInfo or SignatureValue")
	}
	sm := dsChild(si, "SignatureMethod")
	if sm == nil {
		return nil, errors.New("no SignatureMethod")
	}
	alg := sm.SelectAttrValue("Algorithm", "")
	m, ok := xmlSignatureMethods[alg]
	if !ok {
		return nil, fmt.Errorf("%w: signature method %s", ErrXMLUnsupported, alg)
	}
	if !m.hash.Available() {
		return nil, fmt.Errorf("%w: hash %v", ErrXMLUnsupported, m.hash)
	}
	c14n, err := canonicalSignedInfo(si)
	if err != nil {
		return nil, err
	}
	value, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(sv.Text()), ""))
	if err != nil {
		return nil, fmt.Errorf("SignatureValue is not base64: %v", err)
	}
	h := m.hash.New()
	h.Write(c14n)
	digest := h.Sum(nil)

	var certs []*x509.Certificate
	unparsed := 0
	if ki := dsChild(s, "KeyInfo"); ki != nil {
		for _, xd := range dsChildren(ki, "X509Data") {
			for _, xc := range dsChildren(xd, "X509Certificate") {
				der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(xc.Text()), ""))
				if err != nil {
					continue
				}
				c, err := x509.ParseCertificate(der)
				if err != nil {
					unparsed++
					continue
				}
				certs = append(certs, c)
			}
		}
	}
	for _, c := range certs {
		if verifyWith(c, m.kind, m.hash, digest, value) {
			return c, nil
		}
	}
	switch {
	case len(certs) == 0 && unparsed > 0:
		return nil, fmt.Errorf("%w: the KeyInfo certificate does not parse here", ErrXMLUnsupported)
	case len(certs) == 0:
		return nil, fmt.Errorf("%w: KeyInfo holds no certificate", ErrXMLUnsupported)
	}
	return nil, ErrXMLBadSignature
}

func verifyWith(c *x509.Certificate, kind string, h crypto.Hash, digest, value []byte) bool {
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		switch kind {
		case "rsa":
			return rsa.VerifyPKCS1v15(pub, h, digest, value) == nil
		case "rsa-pss":
			return rsa.VerifyPSS(pub, h, digest, value, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: h}) == nil
		}
	case *ecdsa.PublicKey:
		// XML-DSig ECDSA values are r || s, each the size of the curve order (RFC 4050 / 6931).
		if kind != "ecdsa" || len(value)%2 != 0 {
			return false
		}
		n := len(value) / 2
		r, s := new(big.Int).SetBytes(value[:n]), new(big.Int).SetBytes(value[n:])
		return ecdsa.Verify(pub, digest, r, s)
	}
	return false
}
