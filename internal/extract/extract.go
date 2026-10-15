// Package extract turns a signed file into a Submission: the signatures, cut out of the file
// without re-encoding, the digests that bind them to the signed data — each checked against the
// data in hand — and the file's own digests. The signed data itself is never part of it.
//
// Every expectation is tested against the DSS oracle in testdata.
package extract

import (
	"bytes"
	"encoding/base64"
	"path"
	"strings"

	"github.com/TrustBeat/trustbeat-signature/internal/cms"
)

// Formats reported in Submission.Container.Format.
const (
	FormatPAdES = "PAdES"
	FormatXAdES = "XAdES"
	FormatCAdES = "CAdES"
	FormatASiCE = "ASiC-E"
	FormatASiCS = "ASiC-S"
)

// Input is one signed file and the detached data files given with it (by base name).
type Input struct {
	Name  string
	Bytes []byte
	Data  map[string][]byte
}

// Extract builds the submission for in, or returns a *Refusal (or another error for I/O).
func Extract(in Input, tool Tool) (*Submission, error) {
	sub := &Submission{
		SubmissionVersion: SubmissionVersion,
		Extractor:         tool,
		Container:         FileInfo{Name: path.Base(in.Name), SizeBytes: int64(len(in.Bytes)), Digests: fileDigests(in.Bytes)},
		DataObjects:       []FileInfo{},
		Signatures:        []Signature{},
		Timestamps:        []Timestamp{},
	}
	var err error
	switch detect(in.Bytes) {
	case FormatPAdES:
		sub.Container.Format = FormatPAdES
		err = extractPDF(in, sub)
	case "zip":
		err = extractASiC(in, sub)
	case FormatXAdES:
		sub.Container.Format = FormatXAdES
		err = extractXMLFile(in, sub)
	case FormatCAdES:
		sub.Container.Format = FormatCAdES
		err = extractCAdES(in, sub)
	default:
		return nil, refuse(ReasonUnsupported, "not a PDF, XML, CMS or ASiC (ZIP) file")
	}
	if err != nil {
		return nil, err
	}
	if len(sub.Signatures) == 0 {
		return nil, refuse(ReasonUnsigned, "no signature found in %s", sub.Container.Name)
	}
	return sub, nil
}

func detect(b []byte) string {
	head := b
	if len(head) > 1024 {
		head = head[:1024]
	}
	// CMS before the PDF header search: an enveloping .p7m often carries a PDF.
	switch {
	case bytes.HasPrefix(b, []byte("PK\x03\x04")):
		return "zip"
	case len(b) > 0 && b[0] == 0x30:
		return FormatCAdES
	case bytes.Contains(head, []byte("%PDF-")):
		return FormatPAdES
	}
	t := bytes.TrimLeft(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")), " \t\r\n")
	if bytes.HasPrefix(t, []byte("<")) {
		return FormatXAdES
	}
	return ""
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func intp(i int) *int    { return &i }
func boolp(b bool) *bool { return &b }

// cmsBindings checks every signer's messageDigest against content and returns the bindings.
func cmsBindings(sd *cms.SignedData, kind, target string, content []byte) ([]Binding, error) {
	var out []Binding
	for i, s := range sd.Signers {
		if !s.HasSignedAttrs {
			return nil, refuse(ReasonUnsupported, "signer %d has no signed attributes (no messageDigest to bind)", i)
		}
		if s.MessageDigest == nil {
			return nil, refuse(ReasonMalformed, "signer %d has no messageDigest attribute", i)
		}
		d, err := digestOID(s.DigestAlgorithm, content)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(d, s.MessageDigest) {
			return nil, refuse(ReasonDigestMismatch, "%s: signer %d messageDigest does not match the data", target, i)
		}
		out = append(out, Binding{Kind: kind, Signer: intp(i), Target: target, Alg: s.DigestAlgorithm.String(), Digest: hexs(s.MessageDigest), Checked: true})
	}
	return out, nil
}

// extractCAdES handles a CMS file: enveloping (.p7m, content inside) or detached (.p7s + --data).
func extractCAdES(in Input, sub *Submission) error {
	sd, err := cms.Parse(in.Bytes)
	if err != nil {
		return malformed(err, "CMS")
	}
	sig := Signature{Format: FormatCAdES, Source: sub.Container.Name}
	var content []byte
	var name string
	if sd.EContent != nil {
		content = sd.EContent
		name = strings.TrimSuffix(sub.Container.Name, path.Ext(sub.Container.Name))
		sig.SignatureB64 = b64(sd.Detached())
		sig.Derived = []string{"content-detached"}
	} else {
		if len(in.Data) == 0 {
			return refuse(ReasonMissingData, "%s is a detached signature: give the signed file with --data", sub.Container.Name)
		}
		if len(in.Data) > 1 {
			return refuse(ReasonUnsupported, "a detached CMS signature signs one file; %d were given", len(in.Data))
		}
		for n, b := range in.Data {
			name, content = n, b
		}
		sig.SignatureB64 = b64(sd.Raw)
	}
	if sig.Binding, err = cmsBindings(sd, "content", name, content); err != nil {
		return err
	}
	sub.DataObjects = append(sub.DataObjects, FileInfo{Name: name, SizeBytes: int64(len(content)), Digests: fileDigests(content)})
	sub.Signatures = append(sub.Signatures, sig)
	return nil
}
