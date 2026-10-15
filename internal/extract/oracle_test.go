package extract

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/TrustBeat/trustbeat-signature/internal/cms"
)

// The DSS oracle: ../../testdata (fixtures + expected/<id>.json written by EU DSS,
// shared/src/test/scala/trustbeat/signaturepreservation/SignatureOracleSpec.scala). Every fixture
// must be accepted or refused exactly as the manifest says, and an accepted one must reproduce the
// golden file: file digests, data objects, every signature and timestamp DSS found, the cut CMS /
// canonical SignedInfo, and every digest DSS reads from a signature as a checked binding.

type manifest struct {
	Fixtures []struct {
		ID        string   `json:"id"`
		File      string   `json:"file"`
		Data      []string `json:"data"`
		Extractor string   `json:"extractor"`
	} `json:"fixtures"`
}

type golden struct {
	File   goldFile   `json:"file"`
	Data   []goldFile `json:"data"`
	Parsed struct {
		Kind          string `json:"kind"`
		PDFSignatures []struct {
			SubFilter       string  `json:"sub_filter"`
			ByteRange       []int64 `json:"byte_range"`
			CoversWholeFile bool    `json:"covers_whole_file"`
			CMS             goldCMS `json:"cms"`
		} `json:"pdf_signatures"`
		CMS           *goldCMS          `json:"cms"`
		XMLSignatures []json.RawMessage `json:"xml_signatures"`
		DataObjects   []goldFile        `json:"data_objects"`
		CMSSignatures []struct {
			Entry string  `json:"entry"`
			CMS   goldCMS `json:"cms"`
		} `json:"cms_signatures"`
	} `json:"parsed"`
	DSS struct {
		Signatures []struct {
			CounterSignature bool `json:"counter_signature"`
			DigestMatchers   []struct {
				Type   string `json:"type"`
				Digest string `json:"digest"`
			} `json:"digest_matchers"`
		} `json:"signatures"`
	} `json:"dss"`
}

type goldFile struct {
	Name    string            `json:"name"`
	Size    int64             `json:"size"`
	Digests map[string]string `json:"digests"`
}

type goldCMS struct {
	SHA256              string            `json:"sha256"`
	EncapsulatedContent map[string]string `json:"encapsulated_content"`
}

type goldXMLSig struct {
	SignedInfo string `json:"signed_info_c14n_sha256"`
	References []struct {
		URI    string `json:"uri"`
		Digest string `json:"digest"`
	} `json:"references"`
}

func corpus(t *testing.T) string {
	p := filepath.Join("..", "..", "testdata")
	if _, err := os.Stat(filepath.Join(p, "fixtures", "manifest.json")); err != nil {
		t.Fatalf("fixture corpus not found: %v", err)
	}
	return p
}

func readJSON(t *testing.T, p string, v any) {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", p, err)
	}
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func unb64(t *testing.T, s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func sameDigests(g map[string]string, d Digests) bool {
	return g["sha256"] == d.SHA256 && g["sha512"] == d.SHA512 && g["sha3-512"] == d.SHA3_512
}

func TestOracleCorpus(t *testing.T) {
	root := corpus(t)
	var m manifest
	readJSON(t, filepath.Join(root, "fixtures", "manifest.json"), &m)
	if len(m.Fixtures) < 40 {
		t.Fatalf("only %d fixtures", len(m.Fixtures))
	}
	for _, f := range m.Fixtures {
		f := f
		t.Run(f.ID, func(t *testing.T) {
			var g golden
			readJSON(t, filepath.Join(root, "expected", f.ID+".json"), &g)
			in := Input{Name: filepath.Base(f.File), Data: map[string][]byte{}}
			var err error
			if in.Bytes, err = os.ReadFile(filepath.Join(root, "fixtures", f.File)); err != nil {
				t.Fatal(err)
			}
			for _, d := range f.Data {
				b, err := os.ReadFile(filepath.Join(root, "fixtures", d))
				if err != nil {
					t.Fatal(err)
				}
				in.Data[filepath.Base(d)] = b
			}
			sub, err := Extract(in, Tool{Name: "test", Version: "0"})
			if f.Extractor != "accept" {
				r, ok := AsRefusal(err)
				if !ok {
					t.Fatalf("want %s, got submission (err=%v)", f.Extractor, err)
				}
				if "refuse:"+r.Reason != f.Extractor {
					t.Fatalf("want %s, got %s: %s", f.Extractor, r.Reason, r.Detail)
				}
				return
			}
			if err != nil {
				t.Fatalf("want accept, got %v", err)
			}
			checkAccepted(t, sub, &g, in.Bytes)
			checkSubmissionFile(t, filepath.Join(root, "submissions", f.ID+".json"), sub)
		})
	}
}

// checkSubmissionFile keeps submissions/<id>.json — the extractor's output, which the server
// is tested with — equal to what the extractor produces. Regenerate with
// SP_SUBMISSIONS_WRITE=1 go test ./... and review the diff.
func checkSubmissionFile(t *testing.T, p string, sub *Submission) {
	t.Helper()
	j, err := json.MarshalIndent(sub, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	j = append(j, '\n')
	if os.Getenv("SP_SUBMISSIONS_WRITE") == "1" {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, j, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil || !bytes.Equal(want, j) {
		t.Errorf("%s differs from the extractor's output (regenerate with SP_SUBMISSIONS_WRITE=1)", filepath.Base(p))
	}
}

func checkAccepted(t *testing.T, sub *Submission, g *golden, file []byte) {
	t.Helper()
	if sub.Container.SizeBytes != g.File.Size || !sameDigests(g.File.Digests, sub.Container.Digests) {
		t.Errorf("container digests differ from the golden file")
	}

	// Data objects.
	wantData := g.Data
	if g.Parsed.Kind == "asic" {
		wantData = g.Parsed.DataObjects
	}
	if g.Parsed.CMS != nil && g.Parsed.CMS.EncapsulatedContent != nil {
		if len(sub.DataObjects) != 1 || !sameDigests(g.Parsed.CMS.EncapsulatedContent, sub.DataObjects[0].Digests) {
			t.Errorf("encapsulated content digests differ")
		}
	} else {
		if len(sub.DataObjects) != len(wantData) {
			t.Fatalf("data objects: got %d, want %d", len(sub.DataObjects), len(wantData))
		}
		for i, w := range wantData {
			if sub.DataObjects[i].Name != w.Name || !sameDigests(w.Digests, sub.DataObjects[i].Digests) {
				t.Errorf("data object %d: got %s, want %s", i, sub.DataObjects[i].Name, w.Name)
			}
		}
	}

	// One submission signature per top-level DSS signature.
	top := 0
	for _, s := range g.DSS.Signatures {
		if !s.CounterSignature {
			top++
		}
	}
	if len(sub.Signatures) != top {
		t.Errorf("signatures: got %d, DSS found %d", len(sub.Signatures), top)
	}

	switch g.Parsed.Kind {
	case "pdf":
		checkPDF(t, sub, g)
	case "xml":
		checkXML(t, sub.Signatures, g.Parsed.XMLSignatures)
	case "cms":
		s := sub.Signatures[0]
		sig := unb64(t, s.SignatureB64)
		if len(s.Derived) == 0 {
			if sha(sig) != g.Parsed.CMS.SHA256 {
				t.Errorf("detached CMS is not the file's CMS byte for byte")
			}
		} else {
			checkDetachedCopy(t, sig, file)
		}
	case "asic":
		checkASiC(t, sub, g)
	}

	// Every digest DSS reads from a top-level signature is a checked binding of the submission.
	have := map[string]bool{}
	for _, s := range sub.Signatures {
		for _, b := range s.Binding {
			if !b.Checked {
				t.Errorf("unchecked binding %+v", b)
			}
			have[b.Digest] = true
		}
	}
	for _, ts := range sub.Timestamps {
		for _, b := range ts.Binding {
			have[b.Digest] = true
		}
	}
	for _, s := range g.DSS.Signatures {
		if s.CounterSignature {
			continue
		}
		for _, mt := range s.DigestMatchers {
			if mt.Digest != "" && !have[mt.Digest] {
				t.Errorf("DSS %s digest %s is not a binding of the submission", mt.Type, mt.Digest)
			}
		}
	}
}

func checkPDF(t *testing.T, sub *Submission, g *golden) {
	byRange := map[string]Binding{}
	sigByRange := map[string][]byte{}
	for _, s := range sub.Signatures {
		for _, b := range s.Binding {
			if b.Kind == "byte-range" {
				k := fmt.Sprint(b.ByteRange)
				byRange[k], sigByRange[k] = b, unb64(t, s.SignatureB64)
			}
		}
	}
	for _, ts := range sub.Timestamps {
		k := fmt.Sprint(ts.Binding[0].ByteRange)
		byRange[k], sigByRange[k] = ts.Binding[0], unb64(t, ts.TokenB64)
	}
	if len(byRange) != len(g.Parsed.PDFSignatures) {
		t.Errorf("PDF: %d signature dictionaries, golden has %d", len(byRange), len(g.Parsed.PDFSignatures))
	}
	for _, p := range g.Parsed.PDFSignatures {
		k := fmt.Sprint(p.ByteRange)
		b, ok := byRange[k]
		if !ok {
			t.Errorf("PDF: byte range %s not extracted", k)
			continue
		}
		if *b.CoversWholeFile != p.CoversWholeFile {
			t.Errorf("PDF %s: covers_whole_file %v, golden %v", k, *b.CoversWholeFile, p.CoversWholeFile)
		}
		if sha(sigByRange[k]) != p.CMS.SHA256 {
			t.Errorf("PDF %s: CMS cut differs from the golden cut", k)
		}
	}
}

func checkXML(t *testing.T, sigs []Signature, raw []json.RawMessage) {
	var want []goldXMLSig
	for _, r := range raw {
		var w goldXMLSig
		if err := json.Unmarshal(r, &w); err != nil {
			t.Fatal(err)
		}
		want = append(want, w)
	}
	if len(sigs) != len(want) {
		t.Fatalf("XML signatures: got %d, golden %d", len(sigs), len(want))
	}
	for i, w := range want {
		s := sigs[i]
		if s.SignedInfoC14NSHA256 != w.SignedInfo {
			t.Errorf("signature %d: canonical SignedInfo differs from Santuario's", i)
		}
		if len(s.Binding) != len(w.References) {
			t.Fatalf("signature %d: %d references, golden %d", i, len(s.Binding), len(w.References))
		}
		for j, r := range w.References {
			if s.Binding[j].Digest != r.Digest {
				t.Errorf("signature %d reference %q: digest differs", i, r.URI)
			}
		}
		// The cut-out signature, parsed on its own, gives the same canonical SignedInfo.
		x, err := loadXML(unb64(t, s.SignatureB64))
		if err != nil {
			t.Fatalf("cut signature %d: %v", i, err)
		}
		c, err := canonicalSignedInfo(dsChild(topSignatures(x.doc.Root())[0], "SignedInfo"))
		if err != nil || sha(c) != w.SignedInfo {
			t.Errorf("cut signature %d: SignedInfo differs (%v)", i, err)
		}
	}
}

// checkDetachedCopy: the copy parses, has no eContent, and its signerInfos — the signatures —
// are byte-identical to the original's.
func checkDetachedCopy(t *testing.T, copy, original []byte) {
	d, err := cms.Parse(copy)
	if err != nil {
		t.Fatalf("content-detached copy does not parse: %v", err)
	}
	o, err := cms.Parse(original)
	if err != nil {
		t.Fatal(err)
	}
	if d.EContent != nil {
		t.Errorf("content-detached copy still has eContent")
	}
	if !bytes.Equal(d.SignerInfosRaw(), o.SignerInfosRaw()) || len(d.Signers) != len(o.Signers) {
		t.Errorf("content-detached copy changed the signerInfos")
	}
	if !d.EContentType.Equal(o.EContentType) || d.Version != o.Version {
		t.Errorf("content-detached copy changed eContentType or version")
	}
}

// TestPDFScanAgreesWithFields: wherever the cross-reference table is readable, the /ByteRange
// scan (the fallback) finds exactly the signature dictionaries the field walk finds.
func TestPDFScanAgreesWithFields(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(corpus(t), "fixtures", "*", "*.pdf"))
	if len(files) < 7 {
		t.Fatalf("only %d PDFs", len(files))
	}
	compared := 0
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		fields, err := pdfSignaturesFromFields(raw)
		if err != nil {
			continue
		}
		compared++
		scanned := scanSignatures(raw)
		if len(scanned) != len(fields) {
			t.Errorf("%s: scan found %d, fields %d", filepath.Base(f), len(scanned), len(fields))
			continue
		}
		for i := range fields {
			a, b := fields[i], scanned[i]
			if fmt.Sprint(a.byteRange) != fmt.Sprint(b.byteRange) || a.subFilter != b.subFilter || !bytes.Equal(a.contents, b.contents) {
				t.Errorf("%s #%d: scan %v %s, fields %v %s", filepath.Base(f), i, b.byteRange, b.subFilter, a.byteRange, a.subFilter)
			}
		}
	}
	if compared < 6 {
		t.Errorf("only %d PDFs readable through their fields", compared)
	}
}

func checkASiC(t *testing.T, sub *Submission, g *golden) {
	var xmlWant []json.RawMessage
	for _, x := range g.Parsed.XMLSignatures {
		var e struct {
			Signatures []json.RawMessage `json:"signatures"`
		}
		if err := json.Unmarshal(x, &e); err != nil {
			t.Fatal(err)
		}
		xmlWant = append(xmlWant, e.Signatures...)
	}
	var xmlSigs []Signature
	cmsBySource := map[string]string{}
	for _, s := range sub.Signatures {
		if s.Format == FormatXAdES {
			xmlSigs = append(xmlSigs, s)
		} else {
			cmsBySource[s.Source] = sha(unb64(t, s.SignatureB64))
		}
	}
	checkXML(t, xmlSigs, xmlWant)
	for _, c := range g.Parsed.CMSSignatures {
		if cmsBySource[c.Entry] != c.CMS.SHA256 {
			t.Errorf("ASiC %s: CMS differs from the container's", c.Entry)
		}
	}
}
