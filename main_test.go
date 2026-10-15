package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixtures = "testdata/fixtures/"

func cli(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestExtractWritesSubmissionJSON(t *testing.T) {
	code, out, stderr := cli("extract", fixtures+"cades/screenshot.png.signed_qes_detached.p7s", "--data", fixtures+"cades/screenshot.png")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var sub map[string]any
	if err := json.Unmarshal([]byte(out), &sub); err != nil {
		t.Fatal(err)
	}
	if sub["submission_version"].(float64) != 1 || len(sub["signatures"].([]any)) != 1 {
		t.Errorf("unexpected submission %v", sub)
	}
	if strings.Contains(out, "iVBORw0KGgo") { // base64 of a PNG header: the data file must not be in the output
		t.Error("the signed file's content is in the submission")
	}
}

func TestExtractToFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub.json")
	if code, _, stderr := cli("extract", fixtures+"asic-xades/onefile-ok.asics", "--out", p); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if b, err := os.ReadFile(p); err != nil || !json.Valid(b) {
		t.Errorf("no valid JSON in --out (%v)", err)
	}
}

func TestRefusalExitsThreeAndWritesNothing(t *testing.T) {
	code, out, stderr := cli("extract", fixtures+"unsigned/doc.pdf")
	if code != exitRefused || out != "" || !strings.Contains(stderr, "refused (unsigned)") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, stderr)
	}
	code, _, stderr = cli("extract", fixtures+"cades/screenshot.png.signed_qes_detached.p7s")
	if code != exitRefused || !strings.Contains(stderr, "missing-data") {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
}

func TestUsageAndErrors(t *testing.T) {
	for _, args := range [][]string{{}, {"nope"}, {"extract"}, {"extract", "a", "b"}, {"extract", "a", "--data"}, {"extract", "--bogus"}} {
		if code, _, _ := cli(args...); code != exitUsage {
			t.Errorf("%v: exit %d, want %d", args, code, exitUsage)
		}
	}
	if code, _, _ := cli("extract", "/does/not/exist.pdf"); code != exitError {
		t.Errorf("missing file: exit %d", code)
	}
	if code, out, _ := cli("version"); code != exitOK || !strings.HasPrefix(out, "trustbeat-signature ") {
		t.Errorf("version: %d %q", code, out)
	}
}

func TestHideNamesReplacesOnlyTheContainerName(t *testing.T) {
	// A copy under a name with personal data in it; the content, and so the hidden name, is the fixture's.
	dir := t.TempDir()
	b, err := os.ReadFile(fixtures + "pades/Signature-P-SK-6.pdf")
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "Smlouva_Jan_Novak_850101.pdf")
	if err := os.WriteFile(f, b, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := cli("extract", f, "--hide-names")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if strings.Contains(out, "Novak") {
		t.Error("the file name is in the submission")
	}
	var sub struct {
		Container struct {
			Name    string            `json:"name"`
			Digests map[string]string `json:"digests"`
		} `json:"container"`
	}
	if err := json.Unmarshal([]byte(out), &sub); err != nil {
		t.Fatal(err)
	}
	if want := sub.Container.Digests["sha256"][:16] + ".pdf"; sub.Container.Name != want {
		t.Errorf("container name %q, want %q", sub.Container.Name, want)
	}
	// Without the flag the name is kept.
	if _, out, _ := cli("extract", f); !strings.Contains(out, "Smlouva_Jan_Novak_850101.pdf") {
		t.Error("the name is hidden without --hide-names")
	}
}

func TestHideNamesP7mKeepsTheInnerExtension(t *testing.T) {
	dir := t.TempDir()
	b, err := os.ReadFile(fixtures + "cades/cades-bes-signeddata-enveloping.p7m")
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "Faktura_Novak.xml.p7m")
	if err := os.WriteFile(f, b, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := cli("extract", f, "--hide-names")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if strings.Contains(out, "Novak") {
		t.Error("the file name is in the submission (container, data object or signature source)")
	}
	if !strings.Contains(out, `.xml.p7m"`) || !strings.Contains(out, `.xml"`) {
		t.Errorf("container and data object should keep .xml.p7m / .xml:\n%s", out)
	}
}

func TestHiddenName(t *testing.T) {
	const prefix = "e3b0c44298fc1c14" // SHA-256 of nothing
	for name, want := range map[string]string{
		"contract.pdf":          prefix + ".pdf",
		"Contract.PDF":          prefix + ".pdf",
		"a.asice":               prefix + ".asice",
		"doc.xml.p7s":           prefix + ".xml.p7s",
		"Jan.Novak.pdf.p7m":     prefix + ".pdf.p7m",
		"no-extension":          prefix,
		"x.Jan_Novak_850101":    prefix, // an "extension" that is really a name
		"x.novakova":            prefix, // too long to be an extension
		"x.p7m":                 prefix + ".p7m",
		"Smlouva.Novak_Jan.p7m": prefix + ".p7m",
	} {
		if got := hiddenName(name, nil); got != want {
			t.Errorf("hiddenName(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestHideNamesIsNotForVerify(t *testing.T) {
	if code, _, stderr := cli("verify", "a.pdf", "--package", "p.zip", "--hide-names"); code != exitUsage || !strings.Contains(stderr, "--hide-names") {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
}

// ── preserve ─────────────────────────────────────────────────────────────────

func TestPreserveSendsTheSubmissionNeverTheFile(t *testing.T) {
	var got []byte
	var auth, path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, path = r.Header.Get("Authorization"), r.URL.String()
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"id":"01REC","status":"pending"}`))
	}))
	defer srv.Close()
	t.Setenv("TRUSTBEAT_API_URL", srv.URL)
	t.Setenv("TRUSTBEAT_API_KEY", "tb_test_key")

	code, out, stderr := cli("preserve", fixtures+"cades/screenshot.png.signed_qes_detached.p7s",
		"--data", fixtures+"cades/screenshot.png", "--client-ref", "contract 17")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if auth != "Bearer tb_test_key" || path != "/v1/signature-preservation?client_ref=contract+17" {
		t.Errorf("auth %q path %q", auth, path)
	}
	var sub map[string]any
	if err := json.Unmarshal(got, &sub); err != nil || sub["submission_version"].(float64) != 1 {
		t.Fatalf("body is not a submission: %v", err)
	}
	png, _ := os.ReadFile(fixtures + "cades/screenshot.png")
	if bytes.Contains(got, png[:64]) || strings.Contains(string(got), base64.StdEncoding.EncodeToString(png[:48])) {
		t.Error("the signed file's content was sent")
	}
	if !strings.Contains(out, `"id":"01REC"`) {
		t.Errorf("record not printed: %q", out)
	}
}

func TestPreserveRejectedByTheAPIExitsFour(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPaymentRequired)
		_, _ = w.Write([]byte(`{"error":{"code":"QUOTA_EXCEEDED","message":"Free plan monthly quota reached"}}`))
	}))
	defer srv.Close()
	t.Setenv("TRUSTBEAT_API_URL", srv.URL)
	t.Setenv("TRUSTBEAT_API_KEY", "k")
	code, out, stderr := cli("preserve", fixtures+"asic-xades/onefile-ok.asics")
	if code != exitRejected || out != "" || !strings.Contains(stderr, "QUOTA_EXCEEDED") {
		t.Errorf("exit %d stdout %q stderr %q", code, out, stderr)
	}
}

func TestPreserveRefusedFileIsNeverSent(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer srv.Close()
	t.Setenv("TRUSTBEAT_API_URL", srv.URL)
	t.Setenv("TRUSTBEAT_API_KEY", "k")
	if code, _, _ := cli("preserve", fixtures+"unsigned/doc.pdf"); code != exitRefused || called {
		t.Errorf("exit %d, called %v", code, called)
	}
}

func TestPreserveNeedsAKeyAndClientRefIsForPreserveOnly(t *testing.T) {
	t.Setenv("TRUSTBEAT_API_KEY", "")
	if code, _, stderr := cli("preserve", fixtures+"asic-xades/onefile-ok.asics"); code != exitUsage || !strings.Contains(stderr, "TRUSTBEAT_API_KEY") {
		t.Errorf("exit %d %q", code, stderr)
	}
	if code, _, _ := cli("extract", fixtures+"asic-xades/onefile-ok.asics", "--client-ref", "x"); code != exitUsage {
		t.Errorf("extract --client-ref: exit %d", code)
	}
}

func TestPreserveServerErrorExitsOne(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	t.Setenv("TRUSTBEAT_API_URL", srv.URL)
	t.Setenv("TRUSTBEAT_API_KEY", "k")
	if code, _, _ := cli("preserve", fixtures+"asic-xades/onefile-ok.asics"); code != exitError {
		t.Errorf("exit %d", code)
	}
}

// ── verify ───────────────────────────────────────────────────────────────────

const packages = "testdata/packages/"

func TestVerifyPassesExitsZero(t *testing.T) {
	code, out, stderr := cli("verify", fixtures+"cades/screenshot.png.signed_qes_detached.p7s", "--data", fixtures+"cades/screenshot.png",
		"--package", packages+"cades-detached-qes.zip")
	if code != exitOK || !strings.Contains(out, "Result: PASSED") {
		t.Fatalf("exit %d: %s%s", code, out, stderr)
	}
}

func TestVerifyFailedAndUndecidedExitCodes(t *testing.T) {
	// The extractor refuses the file without its detached data: verification fails, still reported.
	code, out, _ := cli("verify", fixtures+"cades/screenshot.png.signed_qes_detached.p7s", "--package", packages+"cades-detached-qes.zip")
	if code != exitVerifyFailed || !strings.Contains(out, "Result: FAILED") {
		t.Errorf("refused file: exit %d\n%s", code, out)
	}
	// Another file.
	if code, _, _ := cli("verify", fixtures+"pades/Signature-P-BG_BOR-1.pdf", "--package", packages+"pades-two-qes-sk.zip"); code != exitVerifyFailed {
		t.Errorf("another file: exit %d", code)
	}
	// No evidence record yet.
	if code, _, _ := cli("verify", fixtures+"pades/doc-firmado-LT.pdf", "--package", packages+"pades-lt-pending.zip"); code != exitVerifyIndeterminate {
		t.Errorf("pending: exit %d", code)
	}
}

func TestVerifyJSONToFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "report.json")
	code, out, stderr := cli("verify", fixtures+"xades/Signature-X-RO_TRA-15.xml", "--package", packages+"xades-enveloped-exclusive.zip", "--json", "--out", p)
	if code != exitOK || out != "" {
		t.Fatalf("exit %d, stdout %q: %s", code, out, stderr)
	}
	var rep struct {
		Result string `json:"result"`
		Steps  []struct {
			Step   int    `json:"step"`
			Result string `json:"result"`
		} `json:"steps"`
	}
	b, _ := os.ReadFile(p)
	if err := json.Unmarshal(b, &rep); err != nil || rep.Result != "passed" || len(rep.Steps) != 8 {
		t.Fatalf("%v %s", err, b)
	}
}

func TestVerifyUsage(t *testing.T) {
	for _, args := range [][]string{
		{"verify", fixtures + "pades/doc-firmado-LT.pdf"},                        // no --package
		{"verify", fixtures + "pades/doc-firmado-LT.pdf", "--package"},           // no value
		{"extract", fixtures + "pades/doc-firmado-LT.pdf", "--json"},             // verify only
		{"extract", fixtures + "pades/doc-firmado-LT.pdf", "--package", "x.zip"}, // verify only
	} {
		if code, _, _ := cli(args...); code != exitUsage {
			t.Errorf("%v: exit %d, want %d", args, code, exitUsage)
		}
	}
	if code, _, _ := cli("verify", fixtures+"pades/doc-firmado-LT.pdf", "--package", "/does/not/exist.zip"); code != exitError {
		t.Errorf("missing package: exit %d", code)
	}
}
