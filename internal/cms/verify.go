package cms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	_ "crypto/sha1" // registers the hashes a signature may name
	_ "crypto/sha256"
	_ "crypto/sha512"

	_ "golang.org/x/crypto/sha3"

	"github.com/TrustBeat/trustbeat-signature/internal/ber"
)

// Verification errors. ErrUnsupported means the signature could not be checked here (an algorithm or
// curve Go does not offer, such as brainpool), not that it is wrong.
var (
	ErrNoCertificate = errors.New("the signer's certificate is not in the CMS")
	ErrUnsupported   = errors.New("not supported by this verifier")
	ErrBadSignature  = errors.New("the signature does not verify")
)

var (
	oidRSA          = "1.2.840.113549.1.1.1"
	oidRSAPSS       = "1.2.840.113549.1.1.10"
	oidECPublicKey  = "1.2.840.10045.2.1"
	oidEd25519      = "1.3.101.112"
	signatureHashes = map[string]crypto.Hash{
		"1.2.840.113549.1.1.5":  crypto.SHA1,   // sha1WithRSAEncryption
		"1.2.840.113549.1.1.14": crypto.SHA224, // sha224WithRSAEncryption
		"1.2.840.113549.1.1.11": crypto.SHA256,
		"1.2.840.113549.1.1.12": crypto.SHA384,
		"1.2.840.113549.1.1.13": crypto.SHA512,
		"1.2.840.10045.4.1":     crypto.SHA1, // ecdsa-with-SHA1
		"1.2.840.10045.4.3.1":   crypto.SHA224,
		"1.2.840.10045.4.3.2":   crypto.SHA256,
		"1.2.840.10045.4.3.3":   crypto.SHA384,
		"1.2.840.10045.4.3.4":   crypto.SHA512,
	}
	digestHashes = map[string]crypto.Hash{
		"1.3.14.3.2.26":           crypto.SHA1,
		"2.16.840.1.101.3.4.2.4":  crypto.SHA224,
		"2.16.840.1.101.3.4.2.1":  crypto.SHA256,
		"2.16.840.1.101.3.4.2.2":  crypto.SHA384,
		"2.16.840.1.101.3.4.2.3":  crypto.SHA512,
		"2.16.840.1.101.3.4.2.8":  crypto.SHA3_256,
		"2.16.840.1.101.3.4.2.9":  crypto.SHA3_384,
		"2.16.840.1.101.3.4.2.10": crypto.SHA3_512,
	}
)

// Certificates returns the DER certificates of the SignedData's certificates field, in order.
// Entries that are not plain X.509 certificates (attribute certificates, other formats) are skipped.
func (s *SignedData) Certificates() [][]byte {
	var out [][]byte
	for _, c := range s.signedData.Children[3 : len(s.signedData.Children)-1] {
		if c.Is(ber.ClassContext, 0) {
			for _, cert := range c.Children {
				if cert.Is(ber.ClassUniversal, ber.TagSequence) {
					out = append(out, cert.Raw)
				}
			}
		}
	}
	return out
}

// VerifySigner checks signer i's signature over its signed attributes with the certificate the CMS
// carries for it, and returns that certificate. It does not check the certificate itself (chain,
// validity, revocation): that is EU DSS's job. A signer without signed attributes is ErrUnsupported.
func (s *SignedData) VerifySigner(i int) (*x509.Certificate, error) {
	infos := s.signedData.Children[len(s.signedData.Children)-1]
	if i < 0 || i >= len(infos.Children) {
		return nil, fmt.Errorf("cms: no signer %d", i)
	}
	si := infos.Child(i)
	attrs := si.Child(3)
	if !attrs.Is(ber.ClassContext, 0) {
		return nil, fmt.Errorf("%w: signer without signed attributes", ErrUnsupported)
	}
	sigAlg, sigVal := si.Child(4), si.Child(5)
	if sigAlg == nil || sigVal == nil || !sigVal.Is(ber.ClassUniversal, ber.TagOctetString) {
		return nil, errors.New("cms: bad SignerInfo")
	}
	cert, err := s.signerCertificate(si.Child(1))
	if err != nil {
		return nil, err
	}
	digestAlg, err := algorithm(si.Child(2))
	if err != nil {
		return nil, err
	}
	sigOID, err := algorithm(sigAlg)
	if err != nil {
		return nil, err
	}
	// The signature is over the DER of the attributes as a SET OF (tag 0x31), not the [0] IMPLICIT
	// field as stored (RFC 5652 §5.4).
	if len(attrs.Raw) == 0 || attrs.Raw[0] != 0xa0 {
		return nil, errors.New("cms: signed attributes are not [0] IMPLICIT")
	}
	signed := append([]byte{0x31}, attrs.Raw[1:]...)
	if err := verify(cert, sigOID.String(), sigAlg, digestAlg.String(), signed, sigVal.Bytes()); err != nil {
		return cert, err
	}
	// With the content inside (a timestamp token's TSTInfo), the signed messageDigest must be its digest;
	// a detached signature's messageDigest is the caller's binding to check.
	if s.EContent != nil {
		h, ok := digestHashes[digestAlg.String()]
		if !ok || !h.Available() {
			return cert, fmt.Errorf("%w: digest algorithm %s", ErrUnsupported, digestAlg)
		}
		w := h.New()
		w.Write(s.EContent)
		if !bytes.Equal(w.Sum(nil), s.Signers[i].MessageDigest) {
			return cert, fmt.Errorf("%w: messageDigest does not match the encapsulated content", ErrBadSignature)
		}
	}
	return cert, nil
}

func (s *SignedData) signerCertificate(sid *ber.Node) (*x509.Certificate, error) {
	for _, raw := range s.Certificates() {
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			continue
		}
		switch {
		case sid.Is(ber.ClassUniversal, ber.TagSequence) && len(sid.Children) == 2:
			serial, err := sid.Child(1).Int()
			if err == nil && bytes.Equal(sid.Child(0).Raw, c.RawIssuer) && serial.Cmp(c.SerialNumber) == 0 {
				return c, nil
			}
		case sid.Is(ber.ClassContext, 0): // subjectKeyIdentifier
			if bytes.Equal(sid.Bytes(), c.SubjectKeyId) {
				return c, nil
			}
		}
	}
	// A certificate Go cannot parse (e.g. a brainpool key) may be the one: say so rather than "missing".
	for _, raw := range s.Certificates() {
		if _, err := x509.ParseCertificate(raw); err != nil {
			return nil, fmt.Errorf("%w: a certificate in the CMS does not parse here (%v)", ErrUnsupported, err)
		}
	}
	return nil, ErrNoCertificate
}

func verify(cert *x509.Certificate, sigOID string, sigAlg *ber.Node, digestOID string, signed, sig []byte) error {
	h, ok := signatureHashes[sigOID]
	if !ok {
		if h, ok = digestHashes[digestOID]; !ok && sigOID != oidEd25519 {
			return fmt.Errorf("%w: digest algorithm %s", ErrUnsupported, digestOID)
		}
	}
	var digest []byte
	if sigOID != oidEd25519 {
		if !h.Available() {
			return fmt.Errorf("%w: hash %v", ErrUnsupported, h)
		}
		w := h.New()
		w.Write(signed)
		digest = w.Sum(nil)
	}
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		switch {
		case sigOID == oidRSAPSS:
			ph, salt, err := pssParams(sigAlg)
			if err != nil {
				return err
			}
			if ph != h {
				w := ph.New()
				w.Write(signed)
				digest, h = w.Sum(nil), ph
			}
			if rsa.VerifyPSS(pub, h, digest, sig, &rsa.PSSOptions{SaltLength: salt, Hash: h}) != nil {
				return ErrBadSignature
			}
		case sigOID == oidRSA || signatureHashes[sigOID] != 0:
			if rsa.VerifyPKCS1v15(pub, h, digest, sig) != nil {
				return ErrBadSignature
			}
		default:
			return fmt.Errorf("%w: signature algorithm %s", ErrUnsupported, sigOID)
		}
	case *ecdsa.PublicKey:
		if sigOID != oidECPublicKey && signatureHashes[sigOID] == 0 {
			return fmt.Errorf("%w: signature algorithm %s", ErrUnsupported, sigOID)
		}
		if !ecdsa.VerifyASN1(pub, digest, sig) {
			return ErrBadSignature
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, signed, sig) {
			return ErrBadSignature
		}
	default:
		return fmt.Errorf("%w: public key %T", ErrUnsupported, cert.PublicKey)
	}
	return nil
}

// pssParams reads RSASSA-PSS-params (RFC 4055): hash (default SHA-1) and salt length (default 20).
func pssParams(alg *ber.Node) (crypto.Hash, int, error) {
	h, salt := crypto.SHA1, 20
	p := alg.Child(1)
	if p == nil || !p.Is(ber.ClassUniversal, ber.TagSequence) {
		return h, salt, nil
	}
	for _, f := range p.Children {
		switch {
		case f.Is(ber.ClassContext, 0) && len(f.Children) == 1:
			oid, err := algorithm(f.Child(0))
			if err != nil {
				return 0, 0, err
			}
			var ok bool
			if h, ok = digestHashes[oid.String()]; !ok {
				return 0, 0, fmt.Errorf("%w: PSS hash %s", ErrUnsupported, oid)
			}
		case f.Is(ber.ClassContext, 2) && len(f.Children) == 1:
			n, err := f.Child(0).Int()
			if err != nil {
				return 0, 0, err
			}
			salt = int(n.Int64())
		}
	}
	return h, salt, nil
}

// TimestampInfo reads an RFC 3161 token's message imprint and genTime.
func (s *SignedData) TimestampInfo() (MessageImprint, time.Time, error) {
	m, err := s.TimestampImprint()
	if err != nil {
		return m, time.Time{}, err
	}
	tst, _ := ber.ParseAll(s.EContent)
	g := tst.Child(4)
	if g == nil || !g.Is(ber.ClassUniversal, 24) {
		return m, time.Time{}, errors.New("cms: TSTInfo has no genTime")
	}
	var t time.Time
	if _, err := asn1.UnmarshalWithParams(g.Raw, &t, "generalized"); err != nil {
		return m, time.Time{}, fmt.Errorf("cms: genTime: %w", err)
	}
	return m, t, nil
}
