package cms

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every CMS signature in the corpus submissions (PAdES /Contents, CAdES, ASiC CAdES, as the
// extractor cut them) against EU DSS's finding on the whole original file (expected/<id>.json):
// where DSS says the signature is intact, this verifier must agree or say it cannot check
// (ErrUnsupported) — never that it is bad.
func TestVerifySignerAgreesWithDSS(t *testing.T) {
	root := "../../testdata"
	subs, _ := filepath.Glob(filepath.Join(root, "submissions", "*.json"))
	if len(subs) == 0 {
		t.Fatal("no corpus submissions")
	}
	verified, unsupported := 0, 0
	for _, p := range subs {
		id := strings.TrimSuffix(filepath.Base(p), ".json")
		var sub struct {
			Signatures []struct {
				Format       string `json:"format"`
				SignatureB64 string `json:"signature_b64"`
			} `json:"signatures"`
		}
		var gold struct {
			DSS struct {
				Signatures []struct {
					CounterSignature bool `json:"counter_signature"`
					SignatureIntact  bool `json:"signature_intact"`
				} `json:"signatures"`
			} `json:"dss"`
		}
		read(t, p, &sub)
		read(t, filepath.Join(root, "expected", id+".json"), &gold)
		var top []bool
		for _, s := range gold.DSS.Signatures {
			if !s.CounterSignature {
				top = append(top, s.SignatureIntact)
			}
		}
		for i, s := range sub.Signatures {
			if s.Format != "CAdES" {
				continue
			}
			b, _ := base64.StdEncoding.DecodeString(s.SignatureB64)
			sd, err := Parse(b)
			if err != nil {
				t.Fatalf("%s/%d: %v", id, i, err)
			}
			_, err = sd.VerifySigner(0)
			switch {
			case err == nil:
				verified++
			case errors.Is(err, ErrUnsupported):
				unsupported++
				t.Logf("%s/%d: not checked: %v", id, i, err)
			default:
				if i < len(top) && top[i] {
					t.Errorf("%s/%d: DSS says intact, verifier says %v", id, i, err)
				}
			}
		}
	}
	if verified < 10 {
		t.Fatalf("only %d CMS signatures verified (%d unsupported)", verified, unsupported)
	}
	t.Logf("%d verified, %d not checkable here", verified, unsupported)
}

func TestVerifySignerRejectsAChangedSignature(t *testing.T) {
	var sub struct {
		Signatures []struct {
			SignatureB64 string `json:"signature_b64"`
		} `json:"signatures"`
	}
	read(t, "../../testdata/submissions/cades-detached-qes.json", &sub)
	b, _ := base64.StdEncoding.DecodeString(sub.Signatures[0].SignatureB64)
	sd, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sd.VerifySigner(0); err != nil {
		t.Fatalf("original: %v", err)
	}
	// Flip one bit inside the signed attributes.
	attrs := sd.signedData.Children[len(sd.signedData.Children)-1].Child(0).Child(3).Raw
	i := strings.Index(string(b), string(attrs))
	c := append([]byte{}, b...)
	c[i+len(attrs)-1] ^= 1
	sd2, err := Parse(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sd2.VerifySigner(0); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("changed attributes: %v", err)
	}
}

func read(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}
