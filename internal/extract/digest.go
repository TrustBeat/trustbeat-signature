package extract

import (
	"crypto"
	_ "crypto/sha1" // registers the hashes signatures may name
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/hex"
	"hash"

	"golang.org/x/crypto/sha3"
)

// Digest algorithms a signature may use for its binding digests, by OID (CMS) and URI (XML-DSig).
// SHA-1 is accepted because old signatures use it; the record states the algorithm.
var hashByOID = map[string]func() hash.Hash{
	"1.3.14.3.2.26":           crypto.SHA1.New,
	"2.16.840.1.101.3.4.2.4":  sha256.New224,
	"2.16.840.1.101.3.4.2.1":  sha256.New,
	"2.16.840.1.101.3.4.2.2":  sha512.New384,
	"2.16.840.1.101.3.4.2.3":  sha512.New,
	"2.16.840.1.101.3.4.2.7":  sha3.New224,
	"2.16.840.1.101.3.4.2.8":  sha3.New256,
	"2.16.840.1.101.3.4.2.9":  sha3.New384,
	"2.16.840.1.101.3.4.2.10": sha3.New512,
}

var hashByURI = map[string]func() hash.Hash{
	"http://www.w3.org/2000/09/xmldsig#sha1":          crypto.SHA1.New,
	"http://www.w3.org/2001/04/xmldsig-more#sha224":   sha256.New224,
	"http://www.w3.org/2001/04/xmlenc#sha256":         sha256.New,
	"http://www.w3.org/2001/04/xmldsig-more#sha384":   sha512.New384,
	"http://www.w3.org/2001/04/xmlenc#sha512":         sha512.New,
	"http://www.w3.org/2007/05/xmldsig-more#sha3-224": sha3.New224,
	"http://www.w3.org/2007/05/xmldsig-more#sha3-256": sha3.New256,
	"http://www.w3.org/2007/05/xmldsig-more#sha3-384": sha3.New384,
	"http://www.w3.org/2007/05/xmldsig-more#sha3-512": sha3.New512,
}

func digestOID(oid asn1.ObjectIdentifier, b []byte) ([]byte, error) {
	f, ok := hashByOID[oid.String()]
	if !ok {
		return nil, refuse(ReasonUnsupported, "digest algorithm %s", oid)
	}
	h := f()
	h.Write(b)
	return h.Sum(nil), nil
}

func digestURI(uri string, b []byte) ([]byte, error) {
	f, ok := hashByURI[uri]
	if !ok {
		return nil, refuse(ReasonUnsupported, "digest algorithm %s", uri)
	}
	h := f()
	h.Write(b)
	return h.Sum(nil), nil
}

func sum(f func() hash.Hash, b []byte) string {
	h := f()
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// fileDigests are the digests reported for every file (P7: append-only list, algorithm agility).
// FileDigests are a file's SHA-256, SHA-512 and SHA3-512.
func FileDigests(b []byte) Digests { return fileDigests(b) }

func fileDigests(b []byte) Digests {
	return Digests{SHA256: sum(sha256.New, b), SHA512: sum(sha512.New, b), SHA3_512: sum(sha3.New512, b)}
}

func hexs(b []byte) string { return hex.EncodeToString(b) }
