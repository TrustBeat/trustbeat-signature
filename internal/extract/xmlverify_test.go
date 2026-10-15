package extract

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every XAdES signature in the corpus submissions, as preserved (cut out, namespace context
// re-declared): its SignatureValue must verify, or be reported as not checkable here (brainpool).
// The server's ServerChecksSpec holds the same check against DSS on the whole file.
func TestVerifyXMLSignatureValueCorpus(t *testing.T) {
	subs, _ := filepath.Glob("../../testdata/submissions/*.json")
	verified, unsupported := 0, 0
	for _, p := range subs {
		b, _ := os.ReadFile(p)
		var sub Submission
		if err := json.Unmarshal(b, &sub); err != nil {
			t.Fatal(err)
		}
		for i, s := range sub.Signatures {
			if s.Format != FormatXAdES {
				continue
			}
			x, _ := base64.StdEncoding.DecodeString(s.SignatureB64)
			_, err := VerifyXMLSignatureValue(x)
			switch {
			case err == nil:
				verified++
			case errors.Is(err, ErrXMLUnsupported):
				unsupported++
				t.Logf("%s/%d: not checked: %v", filepath.Base(p), i, err)
			default:
				t.Errorf("%s/%d: %v", filepath.Base(p), i, err)
			}
		}
	}
	if verified < 15 {
		t.Fatalf("only %d XAdES signatures verified (%d unsupported)", verified, unsupported)
	}
	t.Logf("%d verified, %d not checkable here", verified, unsupported)
}

func TestVerifyXMLSignatureValueRejectsAChange(t *testing.T) {
	b, _ := os.ReadFile("../../testdata/submissions/xades-enveloped-exclusive.json")
	var sub Submission
	if err := json.Unmarshal(b, &sub); err != nil {
		t.Fatal(err)
	}
	x, _ := base64.StdEncoding.DecodeString(sub.Signatures[0].SignatureB64)
	if _, err := VerifyXMLSignatureValue(x); err != nil {
		t.Fatalf("original: %v", err)
	}
	// Change one DigestValue inside SignedInfo: the canonical SignedInfo changes, the value no longer verifies.
	s := string(x)
	i := strings.Index(s, "DigestValue>") + len("DigestValue>")
	c := []byte(s)
	if c[i] == 'A' {
		c[i] = 'B'
	} else {
		c[i] = 'A'
	}
	if _, err := VerifyXMLSignatureValue(c); !errors.Is(err, ErrXMLBadSignature) {
		t.Fatalf("changed SignedInfo: %v", err)
	}
}
