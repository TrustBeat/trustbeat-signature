package ers

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TrustBeat/trustbeat-signature/internal/ber"
	"github.com/TrustBeat/trustbeat-signature/internal/cms"
)

// Real production records (SK TIMESTAMPING UNIT 2026E), one per leaf, named by the leaf — the
// same files the server's EvidenceRecordCheckSpec verifies.
const goldenDir = "../../testdata/eps-sample-batch/records"

func golden(t *testing.T) map[string][]byte {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(goldenDir, "*.ers"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no golden records in %s", goldenDir)
	}
	out := map[string][]byte{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		out[strings.TrimSuffix(filepath.Base(f), ".ers")] = b
	}
	return out
}

func unhex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestProductionRecords(t *testing.T) {
	g := golden(t)
	if len(g) != 21 {
		t.Fatalf("%d golden records, want 21", len(g))
	}
	var imprint []byte
	for leaf, ers := range g {
		stamps, err := Verify(ers, unhex(t, leaf))
		if err != nil {
			t.Fatalf("%s: %v", leaf, err)
		}
		if len(stamps) != 1 || !stamps[0].SignatureValid || !strings.Contains(stamps[0].TSA, "SK TIMESTAMPING UNIT 2026E") {
			t.Fatalf("%s: %+v", leaf, stamps)
		}
		if stamps[0].GenTime.UTC().Format("2006-01-02T15:04:05Z") != "2026-09-14T08:10:40Z" {
			t.Fatalf("genTime %v", stamps[0].GenTime)
		}
		_ = imprint
	}
}

func TestWrongLeaf(t *testing.T) {
	g := golden(t)
	var leaves []string
	for l := range g {
		leaves = append(leaves, l)
	}
	if _, err := Verify(g[leaves[0]], unhex(t, leaves[1])); err == nil || !strings.Contains(err.Error(), "not in the first list") {
		t.Fatalf("want not-in-first-list, got %v", err)
	}
}

// Written by the server's EvidenceRecordCheckSpec (SP_ERS_FIXTURES_WRITE=1): renewed twice by the
// test TSA, three stamps in one chain.
func TestRenewedTwice(t *testing.T) {
	ers, err := os.ReadFile("../../testdata/evidence/renewed-twice.ers")
	if err != nil {
		t.Fatal(err)
	}
	h, _ := os.ReadFile("../../testdata/evidence/renewed-twice.sha256")
	stamps, err := Verify(ers, unhex(t, string(h)))
	if err != nil {
		t.Fatal(err)
	}
	if len(stamps) != 3 {
		t.Fatalf("%d stamps", len(stamps))
	}
	for i, s := range stamps {
		if !s.SignatureValid || !strings.Contains(s.TSA, "TrustBeat Test TSA") {
			t.Fatalf("stamp %d: %+v", i, s)
		}
		if i > 0 && s.Covers == stamps[i-1].Covers {
			t.Fatalf("stamp %d covers the same value as the one before", i)
		}
	}
}

func TestChangedTreeHashIsRefused(t *testing.T) {
	g := golden(t)
	for leaf, ers := range g {
		for other := range g {
			if other == leaf {
				continue
			}
			o := unhex(t, other)
			if i := bytes.Index(ers, o); i >= 0 {
				b := append([]byte{}, ers...)
				b[i+5] ^= 1
				if _, err := Verify(b, unhex(t, leaf)); err == nil || !strings.Contains(err.Error(), "the hash tree leads to") {
					t.Fatalf("want tree mismatch, got %v", err)
				}
				return
			}
		}
	}
	t.Fatal("no record holds a sibling leaf")
}

func TestChangedSignedContentDoesNotVerify(t *testing.T) {
	for leaf, ers := range golden(t) {
		er, _ := ber.ParseAll(ers)
		token := er.Children[len(er.Children)-1].Child(0).Child(0)
		token = token.Children[len(token.Children)-1]
		sd, err := cms.Parse(token.Raw)
		if err != nil {
			t.Fatal(err)
		}
		i := bytes.Index(ers, sd.EContent)
		if i < 0 {
			t.Fatal("TSTInfo not found")
		}
		// The last byte of the TSTInfo (inside its nonce / extensions), not the message imprint.
		b := append([]byte{}, ers...)
		b[i+len(sd.EContent)-1] ^= 1
		stamps, err := Verify(b, unhex(t, leaf))
		if err != nil {
			t.Fatal(err)
		}
		if stamps[0].SignatureValid || !strings.Contains(stamps[0].SignatureNote, "messageDigest") {
			t.Fatalf("a changed TSTInfo verified as signed: %+v", stamps[0])
		}
		return
	}
}

func TestFold(t *testing.T) {
	a := sha256.Sum256([]byte("a"))
	b := sha256.Sum256([]byte("b"))
	pair := [][]byte{a[:], b[:]}
	if bytes.Compare(a[:], b[:]) > 0 {
		pair = [][]byte{b[:], a[:]}
	}
	want := sha256.Sum256(bytes.Join(pair, nil))
	if got, _ := Fold(a[:], [][][]byte{{b[:], a[:]}}); !bytes.Equal(got, want[:]) {
		t.Fatal("pair fold")
	}
	if got, _ := Fold(a[:], [][][]byte{{a[:]}}); !bytes.Equal(got, a[:]) {
		t.Fatal("single leaf")
	}
	if got, _ := Fold(a[:], nil); !bytes.Equal(got, a[:]) {
		t.Fatal("no tree")
	}
	if _, err := Fold(a[:], [][][]byte{{b[:]}}); err == nil {
		t.Fatal("missing data hash accepted")
	}
}

func TestGarbage(t *testing.T) {
	for _, b := range [][]byte{nil, {1, 2, 3}, {0x30, 0x00}} {
		if _, err := Verify(b, make([]byte, 32)); err == nil {
			t.Fatalf("%x accepted", b)
		}
	}
}
