package extract

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/digitorus/pdf"

	"github.com/TrustBeat/trustbeat-signature/internal/cms"
)

// pdfSig is one signature dictionary reached from the AcroForm fields.
type pdfSig struct {
	field     string
	subFilter string
	typ       string
	byteRange []int64
	contents  []byte
}

// extractPDF finds every signature and document timestamp, checks that its /ByteRange leaves out
// exactly /Contents, cuts the CMS out of /Contents (zero padding removed, BER kept as is) and
// checks each messageDigest / message imprint against the signed byte range.
func extractPDF(in Input, sub *Submission) error {
	raw := in.Bytes
	sigs, err := pdfSignaturesFromFields(raw)
	if err != nil {
		if _, ok := AsRefusal(err); ok {
			return err
		}
		// The object parser rejects some files PDFBox and DSS read (fixture
		// pades-five-signatures-document-timestamp: "xref Prev does not point to xref").
		sigs = scanSignatures(raw)
		sub.Notes = append(sub.Notes, "PDF cross-reference table not readable; signature dictionaries found by /ByteRange")
	}
	for _, s := range sigs {
		br := s.byteRange
		signed, err := signedRange(raw, br)
		if err != nil {
			return err
		}
		sd, err := cms.Parse(s.contents)
		if err != nil {
			return malformed(err, fmt.Sprintf("PDF signature %q /Contents", s.field))
		}
		whole := br[2]+br[3] == int64(len(raw))
		source := "pdf#" + s.field
		if s.typ == "DocTimeStamp" || strings.Contains(s.subFilter, "RFC3161") {
			// Classified by /SubFilter: some timestamps carry /Type /Sig (fixture pades-two-qes-sk).
			mi, err := sd.TimestampImprint()
			if err != nil {
				return malformed(err, fmt.Sprintf("PDF document timestamp %q", s.field))
			}
			d, err := digestOID(mi.Algorithm, signed)
			if err != nil {
				return err
			}
			if !bytes.Equal(d, mi.Digest) {
				return refuse(ReasonDigestMismatch, "document timestamp %q does not cover the signed byte range", s.field)
			}
			sub.Timestamps = append(sub.Timestamps, Timestamp{
				Kind: "pdf-document-timestamp", Source: source, TokenB64: b64(sd.Raw),
				Binding: []Binding{{Kind: "byte-range", ByteRange: br, CoversWholeFile: boolp(whole),
					Alg: mi.Algorithm.String(), Digest: hexs(mi.Digest), Checked: true}},
			})
			continue
		}
		var bindings []Binding
		switch s.subFilter {
		case "adbe.pkcs7.detached", "ETSI.CAdES.detached":
			if bindings, err = cmsBindings(sd, "byte-range", "", signed); err != nil {
				return err
			}
		case "adbe.pkcs7.sha1":
			// The signer signs an encapsulated SHA-1 digest of the byte range.
			if sd.EContent == nil || !bytes.Equal(sd.EContent, sha1Sum(signed)) {
				return refuse(ReasonDigestMismatch, "signature %q: encapsulated SHA-1 does not match the byte range", s.field)
			}
			if bindings, err = cmsBindings(sd, "content", "sha1(byte-range)", sd.EContent); err != nil {
				return err
			}
			bindings = append(bindings, Binding{Kind: "byte-range", Alg: "1.3.14.3.2.26", Digest: hexs(sd.EContent), Checked: true})
		default:
			return refuse(ReasonUnsupported, "PDF signature %q has /SubFilter %q", s.field, s.subFilter)
		}
		for i := range bindings {
			if bindings[i].Kind == "byte-range" {
				bindings[i].ByteRange = br
				bindings[i].CoversWholeFile = boolp(whole)
			}
		}
		sub.Signatures = append(sub.Signatures, Signature{Format: FormatCAdES, Source: source, SignatureB64: b64(sd.Raw), Binding: bindings})
	}
	if len(sub.Signatures) > 0 && !lastCovered(sub) {
		sub.Notes = append(sub.Notes, "the file was changed after its last signature or document timestamp (incremental update not covered by any signature)")
	}
	return nil
}

func sha1Sum(b []byte) []byte { s := sha1.Sum(b); return s[:] }

func lastCovered(sub *Submission) bool {
	for _, s := range sub.Signatures {
		for _, b := range s.Binding {
			if b.CoversWholeFile != nil && *b.CoversWholeFile {
				return true
			}
		}
	}
	for _, t := range sub.Timestamps {
		for _, b := range t.Binding {
			if b.CoversWholeFile != nil && *b.CoversWholeFile {
				return true
			}
		}
	}
	return false
}

// signedRange checks a /ByteRange — it starts at 0, stays inside the file, and its gap is
// exactly the hex string <…> of /Contents — and returns the bytes it covers.
func signedRange(raw []byte, br []int64) ([]byte, error) {
	n := int64(len(raw))
	if len(br) != 4 || br[0] != 0 || br[1] <= 0 || br[2] <= br[1] || br[3] < 0 || br[2]+br[3] > n {
		return nil, refuse(ReasonMalformed, "PDF /ByteRange %v is not valid for a %d-byte file", br, n)
	}
	if raw[br[1]] != '<' || raw[br[2]-1] != '>' {
		return nil, refuse(ReasonMalformed, "PDF /ByteRange %v does not exclude exactly the /Contents string", br)
	}
	out := make([]byte, 0, br[1]+br[3])
	out = append(out, raw[:br[1]]...)
	return append(out, raw[br[2]:br[2]+br[3]]...), nil
}

func pdfSignaturesFromFields(raw []byte) (sigs []pdfSig, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("PDF reader: %v", r)
		}
	}()
	r, err := pdf.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, err
	}
	if !r.Trailer().Key("Encrypt").IsNull() {
		return nil, refuse(ReasonUnsupported, "encrypted PDF")
	}
	return pdfSignatures(r)
}

var (
	reByteRange = regexp.MustCompile(`/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]`)
	reSubFilter = regexp.MustCompile(`/SubFilter\s*/([^\s/<>\[\]()]+)`)
	reType      = regexp.MustCompile(`/Type\s*/([^\s/<>\[\]()]+)`)
)

// scanSignatures finds signature dictionaries without the cross-reference table. A signature's
// /Contents must lie, uncompressed, in the gap of its /ByteRange, so its dictionary is never in an
// object stream: every /ByteRange whose gap is a hex string is a candidate. /SubFilter and /Type
// are read from the same indirect object (between "obj" and "endobj", outside the gap).
func scanSignatures(raw []byte) []pdfSig {
	var out []pdfSig
	seen := map[string]bool{}
	for _, m := range reByteRange.FindAllSubmatchIndex(raw, -1) {
		br := make([]int64, 4)
		for i := range br {
			br[i], _ = strconv.ParseInt(string(raw[m[2+2*i]:m[3+2*i]]), 10, 64)
		}
		if _, err := signedRange(raw, br); err != nil || seen[fmt.Sprint(br)] {
			continue
		}
		hexText := bytes.Map(func(r rune) rune {
			if strings.ContainsRune(" \t\r\n\f", r) {
				return -1
			}
			return r
		}, raw[br[1]+1:br[2]-1])
		contents := make([]byte, hex.DecodedLen(len(hexText)))
		if _, err := hex.Decode(contents, hexText); err != nil {
			continue
		}
		seen[fmt.Sprint(br)] = true
		lo, hi := int64(m[0]), int64(m[1])
		if br[1] < lo {
			lo = br[1]
		}
		if br[2] > hi {
			hi = br[2]
		}
		start := int64(bytes.LastIndex(raw[:lo], []byte(" obj")))
		end := hi + int64(bytes.Index(raw[hi:], []byte("endobj")))
		if start < 0 || end < hi {
			start, end = lo, hi
		}
		dict := append(append([]byte{}, raw[start:br[1]]...), raw[br[2]:end]...)
		s := pdfSig{byteRange: br, contents: contents}
		if x := reSubFilter.FindSubmatch(dict); x != nil {
			s.subFilter = string(x[1])
		}
		if x := reType.FindSubmatch(dict); x != nil {
			s.typ = string(x[1])
		}
		out = append(out, s)
	}
	sortByRevision(out)
	return out
}

func sortByRevision(out []pdfSig) {
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].byteRange, out[j].byteRange
		return len(a) == 4 && len(b) == 4 && a[2]+a[3] < b[2]+b[3]
	})
}

// pdfSignatures walks the AcroForm field tree (with inherited /FT) and returns each signed
// signature field's value dictionary once, in file order.
func pdfSignatures(r *pdf.Reader) ([]pdfSig, error) {
	var out []pdfSig
	seen := map[string]bool{}
	var walk func(f pdf.Value, name, ft string, depth int) error
	walk = func(f pdf.Value, name, ft string, depth int) error {
		if depth > 32 {
			return refuse(ReasonMalformed, "PDF field tree too deep")
		}
		if t := f.Key("T").Text(); t != "" {
			if name != "" {
				name += "."
			}
			name += t
		}
		if x := f.Key("FT").Name(); x != "" {
			ft = x
		}
		kids := f.Key("Kids")
		for i := 0; i < kids.Len(); i++ {
			if err := walk(kids.Index(i), name, ft, depth+1); err != nil {
				return err
			}
		}
		v := f.Key("V")
		if ft != "Sig" || v.Kind() != pdf.Dict {
			return nil
		}
		brv := v.Key("ByteRange")
		br := make([]int64, brv.Len())
		for i := range br {
			br[i] = brv.Index(i).Int64()
		}
		key := fmt.Sprint(br)
		if seen[key] {
			return nil
		}
		seen[key] = true
		out = append(out, pdfSig{field: name, subFilter: v.Key("SubFilter").Name(), typ: v.Key("Type").Name(),
			byteRange: br, contents: []byte(v.Key("Contents").RawString())})
		return nil
	}
	fields := r.Trailer().Key("Root").Key("AcroForm").Key("Fields")
	for i := 0; i < fields.Len(); i++ {
		if err := walk(fields.Index(i), "", "", 0); err != nil {
			return nil, err
		}
	}
	sortByRevision(out)
	return out, nil
}
