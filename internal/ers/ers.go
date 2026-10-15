// Package ers verifies an RFC 4998 evidence record over a data object known by its SHA-256, the
// way TrustBeat writes them: one ArchiveTimeStampChain, its first ArchiveTimeStamp over the data,
// each later one a time-stamp renewal (§5.2) over the previous time-stamp. It mirrors the server's
// EvidenceRecordCheck and is tested against the same records.
//
// Checked: the reduced hash tree folds to each token's message imprint; each token's CMS signature
// verifies with the TSA certificate it carries; the stamps are in time order. Not checked: the TSA
// certificates' chains, revocation and qualification — EU DSS or the BSI ERVerifyTool on the same
// file do that.
package ers

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/TrustBeat/trustbeat-signature/internal/ber"
	"github.com/TrustBeat/trustbeat-signature/internal/cms"
)

var oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

// Stamp is one verified ArchiveTimeStamp.
type Stamp struct {
	Index   int       `json:"index"`
	GenTime time.Time `json:"gen_time"`
	// TSA is the subject of the certificate the token was signed with, if it carries one.
	TSA string `json:"tsa,omitempty"`
	// Covers is the hex value the stamp's tree starts from: the data's hash, or the previous token's.
	Covers string `json:"covers"`
	// SignatureValid: the token's signature verifies with its TSA certificate.
	SignatureValid bool `json:"signature_valid"`
	// SignatureNote explains a signature that could not be verified.
	SignatureNote string `json:"signature_note,omitempty"`
}

// Verify checks ers over dataHash (SHA-256). An error means the record does not prove dataHash.
func Verify(ers, dataHash []byte) ([]Stamp, error) {
	er, err := ber.ParseAll(ers)
	if err != nil || !er.Is(ber.ClassUniversal, ber.TagSequence) || len(er.Children) < 3 {
		return nil, errors.New("not an RFC 4998 evidence record")
	}
	algs := er.Child(1)
	if !algs.Is(ber.ClassUniversal, ber.TagSequence) || len(algs.Children) == 0 {
		return nil, errors.New("evidence record: bad digestAlgorithms")
	}
	for _, a := range algs.Children {
		if oid, err := a.Child(0).OID(); err != nil || !oid.Equal(oidSHA256) {
			return nil, errors.New("only SHA-256 evidence records are supported")
		}
	}
	seq := er.Children[len(er.Children)-1]
	if !seq.Is(ber.ClassUniversal, ber.TagSequence) {
		return nil, errors.New("evidence record: bad ArchiveTimeStampSequence")
	}
	if len(seq.Children) != 1 {
		return nil, fmt.Errorf("%d ArchiveTimeStamp chains: hash-tree renewal (RFC 4998 §5.3) is not supported", len(seq.Children))
	}
	chain := seq.Child(0)
	if len(chain.Children) == 0 {
		return nil, errors.New("the evidence record holds no ArchiveTimeStamp")
	}
	var out []Stamp
	covered := dataHash
	for i, ats := range chain.Children {
		s, token, err := stamp(ats, i, covered)
		if err != nil {
			return nil, err
		}
		if len(out) > 0 && s.GenTime.Before(out[len(out)-1].GenTime) {
			return nil, fmt.Errorf("ArchiveTimeStamp %d is older than the one it renews", i)
		}
		out = append(out, s)
		h := sha256.Sum256(token)
		covered = h[:]
	}
	return out, nil
}

// stamp verifies one ArchiveTimeStamp ::= SEQUENCE { digestAlgorithm [0] OPTIONAL, attributes [1]
// OPTIONAL, reducedHashtree [2] OPTIONAL, timeStamp ContentInfo } and returns the token's DER.
func stamp(ats *ber.Node, i int, covered []byte) (Stamp, []byte, error) {
	what := fmt.Sprintf("ArchiveTimeStamp %d", i)
	s := Stamp{Index: i, Covers: hex.EncodeToString(covered)}
	if !ats.Is(ber.ClassUniversal, ber.TagSequence) || len(ats.Children) == 0 {
		return s, nil, fmt.Errorf("%s: malformed", what)
	}
	var reduced [][][]byte
	for _, f := range ats.Children[:len(ats.Children)-1] {
		switch {
		case f.Is(ber.ClassContext, 0):
			oid, err := algOID(f)
			if err != nil || !oid.Equal(oidSHA256) {
				return s, nil, fmt.Errorf("%s: digest algorithm is not SHA-256", what)
			}
		case f.Is(ber.ClassContext, 2):
			for _, pht := range f.Children {
				var values [][]byte
				for _, v := range pht.Children {
					if !v.Is(ber.ClassUniversal, ber.TagOctetString) {
						return s, nil, fmt.Errorf("%s: bad reduced hash tree", what)
					}
					values = append(values, v.Bytes())
				}
				reduced = append(reduced, values)
			}
		}
	}
	token := ats.Children[len(ats.Children)-1]
	sd, err := cms.Parse(token.Raw)
	if err != nil {
		return s, nil, fmt.Errorf("%s: timestamp token does not parse: %v", what, err)
	}
	mi, gen, err := sd.TimestampInfo()
	if err != nil {
		return s, nil, fmt.Errorf("%s: %v", what, err)
	}
	if !mi.Algorithm.Equal(oidSHA256) {
		return s, nil, fmt.Errorf("%s: message imprint is not SHA-256", what)
	}
	root, err := Fold(covered, reduced)
	if err != nil {
		return s, nil, fmt.Errorf("%s: %v", what, err)
	}
	if !bytes.Equal(root, mi.Digest) {
		return s, nil, fmt.Errorf("%s: the hash tree leads to %x, the timestamp covers %x", what, root, mi.Digest)
	}
	s.GenTime = gen
	cert, err := sd.VerifySigner(0)
	if cert != nil {
		s.TSA = subject(cert)
	}
	if err != nil {
		s.SignatureNote = err.Error()
	} else if gen.Before(cert.NotBefore) || gen.After(cert.NotAfter) {
		// As Bouncy Castle: a token signed outside its certificate's validity does not verify.
		s.SignatureNote = "the token was signed outside its TSA certificate's validity"
	} else {
		s.SignatureValid = true
	}
	return s, token.Raw, nil
}

// algOID reads the AlgorithmIdentifier inside an explicit or implicit [0] wrapper.
func algOID(f *ber.Node) (asn1.ObjectIdentifier, error) {
	if len(f.Children) == 1 && f.Child(0).Is(ber.ClassUniversal, ber.TagSequence) {
		return f.Child(0).Child(0).OID()
	}
	if len(f.Children) > 0 {
		return f.Child(0).OID()
	}
	return nil, errors.New("empty")
}

// Fold is RFC 4998 §4.3 over SHA-256: the first list must hold the data's hash; each list, with the
// value computed from the list below added, is sorted in binary ascending order, concatenated and
// hashed. A first list holding only the data's hash is that hash (a leaf, as Bouncy Castle writes it).
func Fold(dataHash []byte, reduced [][][]byte) ([]byte, error) {
	if len(reduced) == 0 {
		return dataHash, nil
	}
	if !has(reduced[0], dataHash) {
		return nil, errors.New("the data hash is not in the first list of the reduced hash tree")
	}
	current := dataHash
	for k, values := range reduced {
		members := append([][]byte{}, values...)
		if !has(values, current) {
			members = append(members, current)
		}
		if k == 0 && len(members) == 1 {
			continue
		}
		sort.Slice(members, func(a, b int) bool { return bytes.Compare(members[a], members[b]) < 0 })
		h := sha256.Sum256(bytes.Join(members, nil))
		current = h[:]
	}
	return current, nil
}

func has(xs [][]byte, h []byte) bool {
	for _, x := range xs {
		if bytes.Equal(x, h) {
			return true
		}
	}
	return false
}

func subject(c *x509.Certificate) string { return c.Subject.String() }
