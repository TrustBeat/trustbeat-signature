package verify

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TrustBeat/trustbeat-signature/internal/extract"
)

// Packages written by the server's SignatureVerificationSpec (SP_PACKAGES_WRITE=1) from the corpus
// submissions, with an evidence record by the test TSA; pades-lt-pending.zip has none yet.
const root = "../../testdata"

var tool = extract.Tool{Name: "trustbeat-signature", Version: "test"}

type fixture struct {
	ID   string   `json:"id"`
	File string   `json:"file"`
	Data []string `json:"data"`
}

func fixtures(t *testing.T) map[string]fixture {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "fixtures", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct{ Fixtures []fixture }
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	out := map[string]fixture{}
	for _, f := range m.Fixtures {
		out[f.ID] = f
	}
	return out
}

// presented extracts a corpus file the way `trustbeat-signature verify` does.
func presented(t *testing.T, id string) Presented {
	t.Helper()
	f := fixtures(t)[id]
	in := extract.Input{Name: filepath.Base(f.File), Data: map[string][]byte{}}
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
	sub, err := extract.Extract(in, tool)
	if err != nil {
		t.Fatalf("%s: %v", id, err)
	}
	return Presented{File: sub.Container, Submission: sub}
}

func pkgBytes(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "packages", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func results(r Report) map[int]string {
	out := map[int]string{}
	for _, s := range r.Steps {
		out[s.Step] = s.Result
	}
	return out
}

func TestSameFilePasses(t *testing.T) {
	for _, id := range []string{"pades-two-qes-sk", "xades-enveloped-exclusive", "asice-cades-multifile", "cades-detached-qes"} {
		r := Run(presented(t, id), pkgBytes(t, id+".zip"), tool)
		got := results(r)
		for _, n := range []int{0, 1, 2, 3, 7} {
			if got[n] != Passed {
				t.Errorf("%s: step %d %s: %v", id, n, got[n], r.Steps[n].Details)
			}
		}
		for _, n := range []int{4, 5, 6} {
			if got[n] != Recorded {
				t.Errorf("%s: step %d %s", id, n, got[n])
			}
		}
		if r.Result != Passed || !strings.Contains(r.Claim, "is the preserved file") || len(r.EvidenceStamp) != 1 {
			t.Errorf("%s: %s / %s", id, r.Result, r.Claim)
		}
		if len(r.Steps) != 8 || r.RecordID == "" || r.PeoSHA256 == "" {
			t.Errorf("%s: %+v", id, r)
		}
	}
}

func TestNoTrustAnchorExplained(t *testing.T) {
	// The package fixtures were made offline, without trusted lists: no chain reaches a trust anchor.
	r := Run(presented(t, "pades-two-qes-sk"), pkgBytes(t, "pades-two-qes-sk.zip"), tool)
	n := 0
	for _, x := range r.Steps[4].Details {
		if !strings.HasPrefix(x, "Signature ") {
			continue // the closing line about the package's validation data
		}
		n++
		if !strings.Contains(x, noTrustAnchor) || !strings.HasSuffix(x, ". "+notOnTrustedList) {
			t.Errorf("step 4 detail without the explanation: %s", x)
		}
	}
	if n != 2 {
		t.Errorf("step 4: %d signature details, want 2: %v", n, r.Steps[4].Details)
	}
	if r.Steps[4].Result != Recorded {
		t.Errorf("step 4: %s", r.Steps[4].Result)
	}
}

func TestAnotherFileFails(t *testing.T) {
	r := Run(presented(t, "pades-one-signature"), pkgBytes(t, "pades-two-qes-sk.zip"), tool)
	got := results(r)
	if got[1] != Failed || got[2] != Failed || got[7] != Passed || r.Result != Failed {
		t.Fatalf("%v", got)
	}
}

func TestDetachedDataMissing(t *testing.T) {
	// Presented without the data file: the extractor refuses, verification still reports every step.
	f := fixtures(t)["cades-detached-qes"]
	b, _ := os.ReadFile(filepath.Join(root, "fixtures", f.File))
	_, err := extract.Extract(extract.Input{Name: filepath.Base(f.File), Bytes: b}, tool)
	ref, ok := extract.AsRefusal(err)
	if !ok {
		t.Fatalf("want refusal, got %v", err)
	}
	r := Run(Presented{File: extract.FileInfo{Name: filepath.Base(f.File)}, Refusal: ref.Error()},
		pkgBytes(t, "cades-detached-qes.zip"), tool)
	got := results(r)
	if got[1] != Failed || got[2] != Failed || got[3] != Passed || got[7] != Passed || len(r.Steps) != 8 {
		t.Fatalf("%v", got)
	}
	if !strings.Contains(r.Steps[2].Details[0], "refuses") {
		t.Fatalf("%v", r.Steps[2].Details)
	}
}

func TestPendingEvidenceRecord(t *testing.T) {
	r := Run(presented(t, "pades-lt"), pkgBytes(t, "pades-lt-pending.zip"), tool)
	got := results(r)
	if got[1] != Passed || got[2] != Passed || got[7] != Indeterminate || r.Result != Indeterminate {
		t.Fatalf("%v %s", got, r.Result)
	}
}

// rezip rewrites a package, changing one file.
func rezip(t *testing.T, b []byte, name string, f func([]byte) []byte) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for _, e := range zr.File {
		rc, _ := e.Open()
		data, _ := io.ReadAll(rc)
		rc.Close()
		if e.Name == name {
			data = f(data)
		}
		w, _ := zw.Create(e.Name)
		w.Write(data)
	}
	zw.Close()
	return out.Bytes()
}

func TestChangedPackageIsRefused(t *testing.T) {
	b := pkgBytes(t, "pades-two-qes-sk.zip")
	changed := rezip(t, b, "peo.json", func(d []byte) []byte {
		return bytes.Replace(d, []byte(`"peo_version":1`), []byte(`"peo_version":2`), 1)
	})
	r := Run(presented(t, "pades-two-qes-sk"), changed, tool)
	if r.Steps[0].Result != Failed || r.Result != Failed || len(r.Steps) != 1 || !strings.Contains(r.Steps[0].Details[0], "peo.json") {
		t.Fatalf("%+v", r.Steps)
	}
	if r := Run(presented(t, "pades-two-qes-sk"), []byte("not a zip"), tool); r.Steps[0].Result != Failed {
		t.Fatal("garbage accepted")
	}
}

func TestEvidenceRecordOverAnotherPeo(t *testing.T) {
	foreign := entry(t, pkgBytes(t, "xades-enveloped-exclusive.zip"), "evidence-record.ers")
	swapped := rezip(t, pkgBytes(t, "pades-two-qes-sk.zip"), "evidence-record.ers", func([]byte) []byte { return foreign })
	// Without updating the manifest, step 0 catches the swap.
	if r := Run(presented(t, "pades-two-qes-sk"), swapped, tool); r.Steps[0].Result != Failed {
		t.Fatalf("a swapped file passed the manifest check: %+v", r.Steps[0])
	}
	// With the manifest updated to match, step 7 catches it: the record does not cover this PEO.
	consistent := rezip(t, swapped, "manifest.json", func(m []byte) []byte {
		var doc map[string]any
		json.Unmarshal(m, &doc)
		for _, f := range doc["files"].([]any) {
			if f.(map[string]any)["path"] == "evidence-record.ers" {
				f.(map[string]any)["sha256"] = sha(foreign)
			}
		}
		out, _ := json.Marshal(doc)
		return out
	})
	r := Run(presented(t, "pades-two-qes-sk"), consistent, tool)
	if got := results(r); got[0] != Passed || got[7] != Failed || r.Result != Failed {
		t.Fatalf("%v %v", got, r.Steps[len(r.Steps)-1].Details)
	}
}

func entry(t *testing.T, b []byte, name string) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range zr.File {
		if e.Name == name {
			rc, _ := e.Open()
			defer rc.Close()
			d, _ := io.ReadAll(rc)
			return d
		}
	}
	t.Fatalf("%s not in package", name)
	return nil
}

func TestPrintExample(t *testing.T) {
	if os.Getenv("SP_PRINT") == "" {
		t.Skip()
	}
	t.Log("\n" + Run(presented(t, "pades-two-qes-sk"), pkgBytes(t, "pades-two-qes-sk.zip"), tool).Text())
}

func TestReportJSONAndText(t *testing.T) {
	r := Run(presented(t, "pades-two-qes-sk"), pkgBytes(t, "pades-two-qes-sk.zip"), tool)
	j, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"report_version":1`, `"result":"passed"`, `"checked_by":["EU DSS at preservation"]`, `"evidence_record":[`} {
		if !bytes.Contains(j, []byte(want)) {
			t.Errorf("JSON lacks %s", want)
		}
	}
	txt := r.Text()
	for _, want := range []string{"Result: PASSED", "7  evidence-record", "RECORDED"} {
		if !strings.Contains(txt, want) {
			t.Errorf("text lacks %q:\n%s", want, txt)
		}
	}
}

func TestCN(t *testing.T) {
	for dn, want := range map[string]string{
		`2.5.4.5=#13,CN=SINIVEE\,VEIKO\,36706020210,OU=digital signature,O=ESTEID,C=EE`: "SINIVEE,VEIKO,36706020210",
		"CN=TrustBeat Test TSA,O=TrustBeat Tests,C=CZ":                                  "TrustBeat Test TSA",
		"O=No Common Name,C=CZ": "O=No Common Name,C=CZ",
	} {
		if got := cn(dn); got != want {
			t.Errorf("cn(%q) = %q, want %q", dn, got, want)
		}
	}
}

// A file signed again after preservation: the record was made from the first revision of
// pades-two-signatures-incremental (one signature, cut at its byte range); the full file has a second
// signature in an incremental update. The record covers only what it was made with (decided
// 2026-10-13): step 1 fails, the preserved signature still passes step 2, and the report says to preserve
// again. The revision's submission is written for the server's spec with SP_REVISION_WRITE=1; the
// package comes back from it (SP_PACKAGES_WRITE=1).
func TestSignedAgainAfterPreservation(t *testing.T) {
	full := presented(t, "pades-two-signatures-incremental")
	if os.Getenv("SP_REVISION_WRITE") == "1" {
		f := fixtures(t)["pades-two-signatures-incremental"]
		b, _ := os.ReadFile(filepath.Join(root, "fixtures", f.File))
		br := full.Submission.Signatures[0].Binding[0].ByteRange
		rev1, err := extract.Extract(extract.Input{Name: filepath.Base(f.File), Bytes: b[:br[2]+br[3]]}, tool)
		if err != nil || len(rev1.Signatures) != 1 {
			t.Fatalf("first revision: %v", err)
		}
		j, _ := json.MarshalIndent(rev1, "", "  ")
		os.MkdirAll(filepath.Join(root, "revisions"), 0o755)
		if err := os.WriteFile(filepath.Join(root, "revisions", "pades-two-signatures-incremental-rev1.json"), append(j, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r := Run(full, pkgBytes(t, "pades-two-signatures-incremental-rev1.zip"), tool)
	got := results(r)
	if got[1] != Failed || got[2] != Passed || got[3] != Passed || got[7] != Passed || r.Result != Failed {
		t.Fatalf("%v", got)
	}
	if d := strings.Join(r.Steps[2].Details, " "); !strings.Contains(d, "1 signature(s) in the presented file are not part of this record") ||
		!strings.Contains(d, "preserve the file again after its last signature") {
		t.Fatalf("%s", d)
	}
}
