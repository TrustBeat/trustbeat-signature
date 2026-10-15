package extract

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/TrustBeat/trustbeat-signature/internal/cms"
)

func fixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(corpus(t), "fixtures", rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func run(t *testing.T, name string, b []byte, data map[string][]byte) (*Submission, error) {
	t.Helper()
	if data == nil {
		data = map[string][]byte{}
	}
	return Extract(Input{Name: name, Bytes: b, Data: data}, Tool{Name: "test", Version: "0"})
}

func wantRefusal(t *testing.T, err error, reason string) {
	t.Helper()
	r, ok := AsRefusal(err)
	if !ok {
		t.Fatalf("want refusal %s, got %v", reason, err)
	}
	if r.Reason != reason {
		t.Fatalf("want refusal %s, got %s: %s", reason, r.Reason, r.Detail)
	}
}

func flip(b []byte, i int) []byte {
	c := append([]byte{}, b...)
	c[i] ^= 0x01
	return c
}

// ── refusals on changed files ────────────────────────────────────────────────

func TestPDFChangedInsideSignedRangeIsRefused(t *testing.T) {
	b := fixture(t, "pades/Signature-P-BG_BOR-1.pdf")
	// A byte of the first page content, well inside the first byte range.
	_, err := run(t, "x.pdf", flip(b, 200), nil)
	wantRefusal(t, err, ReasonDigestMismatch)
}

func TestEnvelopingCMSWithChangedContentIsRefused(t *testing.T) {
	b := fixture(t, "cades/cades-bes-signeddata-enveloping.p7m")
	sd, err := cms.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(b, sd.EContent)
	if i < 0 || len(sd.EContent) == 0 {
		t.Fatal("content not found")
	}
	_, err = run(t, "x.p7m", flip(b, i), nil)
	wantRefusal(t, err, ReasonDigestMismatch)
}

func TestXAdESReferenceToDuplicatedIdIsRefused(t *testing.T) {
	b := fixture(t, "xades/xades-detached.xml")
	id := regexp.MustCompile(`URI="#([^"]+)"`).FindSubmatch(b)
	if id == nil {
		t.Fatal("no same-document reference")
	}
	// A second element with the referenced Id, ahead of the real one: signature wrapping.
	root := regexp.MustCompile(`<ds:Signature[^>]*>`).FindIndex(b)
	evil := append(append(append([]byte{}, b[:root[1]]...), []byte(`<Wrapped Id="`+string(id[1])+`"/>`)...), b[root[1]:]...)
	_, err := run(t, "x.xml", evil, map[string][]byte{"sample.xml": fixture(t, "xades/sample.xml")})
	wantRefusal(t, err, ReasonMalformed)
	if _, err := run(t, "x.xml", b, map[string][]byte{"sample.xml": fixture(t, "xades/sample.xml")}); err != nil {
		t.Fatalf("unchanged file refused: %v", err)
	}
}

func TestXMLWithDoctypeIsRefused(t *testing.T) {
	b := fixture(t, "xades/xades-detached.xml")
	b = bytes.Replace(b, []byte("?>"), []byte("?><!DOCTYPE x [<!ENTITY e \"x\">]>"), 1)
	_, err := run(t, "x.xml", b, map[string][]byte{"sample.xml": fixture(t, "xades/sample.xml")})
	wantRefusal(t, err, ReasonUnsupported)
}

func TestXMLInUnsupportedEncodingIsRefused(t *testing.T) {
	b := bytes.Replace(fixture(t, "xades/valid-xades.xml"), []byte(`encoding="UTF-8"`), []byte(`encoding="Shift_JIS"`), 1)
	_, err := run(t, "x.xml", b, nil)
	wantRefusal(t, err, ReasonUnsupported)
}

func TestUnsupportedXPathFilterIsRefused(t *testing.T) {
	b := bytes.Replace(fixture(t, "xades/Signature-X-BE_ECON-3.xml"), []byte(`Filter="subtract"`), []byte(`Filter="intersect"`), 1)
	_, err := run(t, "x.xml", b, nil)
	wantRefusal(t, err, ReasonUnsupported)
}

func TestDetachedCMSWithTwoDataFilesIsRefused(t *testing.T) {
	_, err := run(t, "s.p7s", fixture(t, "cades/screenshot.png.signed_qes_detached.p7s"),
		map[string][]byte{"a": []byte("a"), "b": []byte("b")})
	wantRefusal(t, err, ReasonUnsupported)
}

func TestUnreferencedDataFileIsRefused(t *testing.T) {
	_, err := run(t, "x.xml", fixture(t, "xades/xades-detached.xml"), map[string][]byte{
		"sample.xml": fixture(t, "xades/sample.xml"), "other.txt": []byte("x")})
	wantRefusal(t, err, ReasonUnsupported)
}

func TestDataWithASiCIsRefused(t *testing.T) {
	_, err := run(t, "x.asics", fixture(t, "asic-xades/onefile-ok.asics"), map[string][]byte{"a": []byte("a")})
	wantRefusal(t, err, ReasonUnsupported)
}

func TestUnknownFormatIsRefused(t *testing.T) {
	_, err := run(t, "x.bin", []byte("hello, not a signed file"), nil)
	wantRefusal(t, err, ReasonUnsupported)
}

func TestTruncatedFilesAreRefusedNotPanics(t *testing.T) {
	for _, rel := range []string{"pades/Signature-P-BG_BOR-1.pdf", "cades/Signature-C-B-LTA-10.p7m",
		"xades/valid-xades.xml", "asic-xades/Signature-A-EE_AS-19.asice"} {
		b := fixture(t, rel)
		for _, n := range []int{1, 7, len(b) / 3, len(b) / 2, len(b) - 3} {
			_, err := run(t, filepath.Base(rel), b[:n], nil)
			if _, ok := AsRefusal(err); !ok {
				t.Errorf("%s cut at %d: want a refusal, got %v", rel, n, err)
			}
		}
	}
}

// ── what the submission says about derived copies ────────────────────────────

func derivedOf(t *testing.T, rel string, data map[string][]byte) []string {
	t.Helper()
	sub, err := run(t, filepath.Base(rel), fixture(t, rel), data)
	if err != nil {
		t.Fatal(err)
	}
	var all []string
	for _, s := range sub.Signatures {
		all = append(all, s.Derived...)
	}
	return all
}

func TestDerivedMarkers(t *testing.T) {
	cases := []struct {
		rel  string
		want []string
		not  []string
	}{
		{"xades/Signature-X-FR_NOT-3.xml", []string{"namespace-context"}, []string{"content-detached"}},
		{"xades/Signature-X-UK_ASC-2.xml", []string{"namespace-context", "re-encoded-utf8"}, nil},
		{"xades/10963_signed.xml", []string{"content-detached"}, nil},
		{"cades/Signature-C-B-LTA-10.p7m", []string{"content-detached"}, nil},
		{"pades/Signature-P-SK-6.pdf", nil, []string{"content-detached", "namespace-context"}},
		{"xades/xades-lt-with-expired-ocsp-responder.xml", []string{"content-detached"}, []string{"namespace-context"}},
	}
	got := derivedOf(t, "xades/xades-detached.xml", map[string][]byte{"sample.xml": fixture(t, "xades/sample.xml")})
	if len(got) != 0 {
		t.Errorf("detached signature, root element: derived %v, want none", got)
	}
	for _, c := range cases {
		got := derivedOf(t, c.rel, nil)
		for _, w := range c.want {
			if !slices.Contains(got, w) {
				t.Errorf("%s: derived %v lacks %s", c.rel, got, w)
			}
		}
		for _, n := range c.not {
			if slices.Contains(got, n) {
				t.Errorf("%s: derived %v should not contain %s", c.rel, got, n)
			}
		}
	}
}

// The enveloping copy of an XAdES signature carries no content: the base64 document inside
// 10963_signed.xml must not be in the submission.
func TestEnvelopingXAdESCopyHasNoContent(t *testing.T) {
	b := fixture(t, "xades/10963_signed.xml")
	sub, err := run(t, "x.xml", b, nil)
	if err != nil {
		t.Fatal(err)
	}
	cut := unb64(t, sub.Signatures[0].SignatureB64)
	if len(cut) > len(b)/2 {
		t.Errorf("cut is %d of %d bytes: content seems to be kept", len(cut), len(b))
	}
	if strings.Contains(string(cut), "SignedObject-") && strings.Contains(string(cut), "<ds:Object Id=\"SignedObject") {
		t.Errorf("content object kept")
	}
}

func TestPDFNoteWhenChangedAfterLastSignature(t *testing.T) {
	sub, err := run(t, "x.pdf", fixture(t, "pades/modified_after_signature.pdf"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sub.Notes) == 0 {
		t.Error("no note for an incremental update after the last signature")
	}
	sub, err = run(t, "x.pdf", fixture(t, "pades/Signature-P-BG_BOR-1.pdf"), nil)
	if err != nil || len(sub.Notes) != 0 {
		t.Errorf("unexpected notes %v (%v)", sub.Notes, err)
	}
}

func TestSignedRangeValidation(t *testing.T) {
	raw := []byte("0123456789<abcd>0123456789")
	if _, err := signedRange(raw, []int64{0, 10, 16, 10}); err != nil {
		t.Fatalf("valid range refused: %v", err)
	}
	for _, br := range [][]int64{{1, 9, 16, 10}, {0, 9, 16, 10}, {0, 10, 15, 11}, {0, 10, 16, 11}, {0, 10, 16}} {
		if _, err := signedRange(raw, br); err == nil {
			t.Errorf("%v accepted", br)
		}
	}
}

func FuzzExtract(f *testing.F) {
	for _, rel := range []string{"cades/cades-bes-signeddata-enveloping.p7m", "xades/xades-detached.xml",
		"asic-cades/onefile-ok.asics", "unsigned/invoice.xml"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "signature-preservation", "fixtures", rel))
		if err == nil {
			f.Add(b)
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = Extract(Input{Name: "f", Bytes: b, Data: map[string][]byte{}}, Tool{})
	})
}
