// trustbeat-signature extracts the signatures from a signed file for TrustBeat Signature
// Preservation. The file itself never leaves the machine: the output holds the signatures, the
// digests that bind them to the signed data (each checked here), and the file's digests.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TrustBeat/trustbeat-signature/internal/extract"
	"github.com/TrustBeat/trustbeat-signature/internal/verify"
)

// version is set at build time (-ldflags "-X main.version=…").
var version = "dev"

// Exit codes.
const (
	exitOK       = 0
	exitError    = 1
	exitUsage    = 2
	exitRefused  = 3
	exitRejected = 4
	// verify
	exitVerifyFailed        = 5
	exitVerifyIndeterminate = 6
)

const defaultAPIURL = "https://api.trustbeat.eu"

const usage = `Usage:
  trustbeat-signature extract  <signed-file> [--data <file>]... [--hide-names] [--out <submission.json>]
  trustbeat-signature preserve <signed-file> [--data <file>]... [--hide-names] [--client-ref <ref>] [--out <record.json>]
  trustbeat-signature verify   <signed-file> --package <package.zip> [--data <file>]... [--json] [--out <report>]
  trustbeat-signature version

extract   Reads a signed PDF (PAdES), XML (XAdES), CMS (.p7m/.p7s, CAdES) or ASiC-E/ASiC-S
          container, checks that every signature still matches the signed data, and writes
          the submission JSON (to stdout, or to --out). Works offline.
preserve  Extracts as above and sends the submission to TrustBeat Signature Preservation. Only
          the submission is sent, never the file. Prints the preservation record, and what
          EU DSS found for each signature to stderr (a warning when DSS found one invalid).
          API key: TRUSTBEAT_API_KEY. API: TRUSTBEAT_API_URL (default ` + defaultAPIURL + `).

verify    Checks the file against its Signature Preservation package (GET
          /v1/signature-preservation/{id}/package), offline: the package is intact, the file is
          the preserved file, every preserved signature is in it and verifies, and the RFC 4998
          evidence record covers the preserved evidence. Chain, timestamps and qualification are
          shown as EU DSS recorded them at preservation (re-validated by POST
          /v1/signature-preservation/{id}/verify). Prints the report (--json for JSON).

          --data        the signed file of a detached signature (repeat for several files)
          --client-ref  your reference for the record (preserve only)
          --hide-names  send a neutral name (SHA-256 prefix + extension) instead of the signed
                        file's name (extract, preserve). Names inside an ASiC container or an
                        XML reference are signed and stay; so do --data file names.

Exit codes: 0 done (verify: passed), 1 error, 2 usage, 3 refused by the extractor (not signed,
data missing or changed, or a feature this version does not support; nothing is written or
sent), 4 rejected by the API, 5 verify: a step failed, 6 verify: a step could not be decided.
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "version", "--version":
		fmt.Fprintf(stdout, "trustbeat-signature %s\n", version)
		return exitOK
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return exitOK
	case "extract", "preserve":
		o, code := parseArgs(args[0], args[1:], stderr)
		if code != exitOK {
			return code
		}
		sub, code := doExtract(o, stderr)
		if code != exitOK {
			return code
		}
		if args[0] == "extract" {
			j, err := json.MarshalIndent(sub, "", "  ")
			if err != nil {
				fmt.Fprintln(stderr, err)
				return exitError
			}
			return write(o.out, append(j, '\n'), stdout, stderr)
		}
		return doPreserve(o, sub, stdout, stderr)
	case "verify":
		o, code := parseArgs(args[0], args[1:], stderr)
		if code != exitOK {
			return code
		}
		return doVerify(o, stdout, stderr)
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
	return exitUsage
}

type options struct {
	file, out, clientRef, pkg string
	data                      []string
	json, hideNames           bool
}

func parseArgs(cmd string, args []string, stderr io.Writer) (options, int) {
	var o options
	for i := 0; i < len(args); i++ {
		switch a := args[i]; a {
		case "--json":
			if cmd != "verify" {
				fmt.Fprintln(stderr, "--json is for verify only")
				return o, exitUsage
			}
			o.json = true
		case "--hide-names":
			if cmd == "verify" {
				fmt.Fprintln(stderr, "--hide-names is for extract and preserve only")
				return o, exitUsage
			}
			o.hideNames = true
		case "--data", "--out", "--client-ref", "--package":
			if i+1 >= len(args) || (a == "--client-ref" && cmd != "preserve") || (a == "--package" && cmd != "verify") {
				fmt.Fprintf(stderr, "%s needs a value (--client-ref is for preserve only, --package for verify only)\n", a)
				return o, exitUsage
			}
			i++
			switch a {
			case "--data":
				o.data = append(o.data, args[i])
			case "--out":
				o.out = args[i]
			case "--package":
				o.pkg = args[i]
			default:
				o.clientRef = args[i]
			}
		default:
			if o.file != "" || (len(a) > 1 && a[0] == '-') {
				fmt.Fprintf(stderr, "unexpected argument %q\n\n%s", a, usage)
				return o, exitUsage
			}
			o.file = a
		}
	}
	if o.file == "" || (cmd == "verify" && o.pkg == "") {
		fmt.Fprint(stderr, usage)
		return o, exitUsage
	}
	return o, exitOK
}

func readInput(o options, stderr io.Writer) (extract.Input, int) {
	in := extract.Input{Name: filepath.Base(o.file), Data: map[string][]byte{}}
	var err error
	if in.Bytes, err = os.ReadFile(o.file); err != nil {
		fmt.Fprintln(stderr, err)
		return in, exitError
	}
	if o.hideNames {
		in.Name = hiddenName(in.Name, in.Bytes)
	}
	for _, d := range o.data {
		b, err := os.ReadFile(d)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return in, exitError
		}
		if _, dup := in.Data[filepath.Base(d)]; dup {
			fmt.Fprintf(stderr, "two --data files are named %s\n", filepath.Base(d))
			return in, exitUsage
		}
		in.Data[filepath.Base(d)] = b
	}
	return in, exitOK
}

// hiddenName replaces a file name, which may hold personal data ("Contract_Jan_Novak.pdf"), with
// the first 16 hex digits of the file's SHA-256 and its extension. The extension stays so the
// record still says what kind of file it was; for .p7m / .p7s the inner one stays too, because the
// encapsulated content of a .p7m is named after the container ("<hash>.pdf.p7m" → "<hash>.pdf").
func hiddenName(name string, content []byte) string {
	sum := sha256.Sum256(content)
	ext := strings.ToLower(filepath.Ext(name))
	if !shortExt(ext) {
		ext = ""
	}
	if ext == ".p7m" || ext == ".p7s" {
		if inner := strings.ToLower(filepath.Ext(strings.TrimSuffix(name, filepath.Ext(name)))); shortExt(inner) {
			ext = inner + ext
		}
	}
	return hex.EncodeToString(sum[:8]) + ext
}

// shortExt accepts ".pdf", ".asice", ".xml": a dot and one to five letters or digits. Anything
// longer could itself carry a name.
func shortExt(ext string) bool {
	if len(ext) < 2 || len(ext) > 6 || ext[0] != '.' {
		return false
	}
	for _, c := range ext[1:] {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func tool() extract.Tool { return extract.Tool{Name: "trustbeat-signature", Version: version} }

func doExtract(o options, stderr io.Writer) (*extract.Submission, int) {
	in, code := readInput(o, stderr)
	if code != exitOK {
		return nil, code
	}
	sub, err := extract.Extract(in, tool())
	if err != nil {
		if r, ok := extract.AsRefusal(err); ok {
			fmt.Fprintf(stderr, "%s: refused (%s): %s\n", in.Name, r.Reason, r.Detail)
			return nil, exitRefused
		}
		fmt.Fprintf(stderr, "%s: %v\n", in.Name, err)
		return nil, exitError
	}
	for _, n := range sub.Notes {
		fmt.Fprintf(stderr, "note: %s\n", n)
	}
	return sub, exitOK
}

// doPreserve sends the submission (never the file) and prints the record the API returns.
func doPreserve(o options, sub *extract.Submission, stdout, stderr io.Writer) int {
	key := strings.TrimSpace(os.Getenv("TRUSTBEAT_API_KEY"))
	if key == "" {
		fmt.Fprintln(stderr, "set TRUSTBEAT_API_KEY to your TrustBeat API key")
		return exitUsage
	}
	base := strings.TrimRight(os.Getenv("TRUSTBEAT_API_URL"), "/")
	if base == "" {
		base = defaultAPIURL
	}
	endpoint := base + "/v1/signature-preservation"
	if o.clientRef != "" {
		endpoint += "?client_ref=" + url.QueryEscape(o.clientRef)
	}
	body, err := json.Marshal(sub)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "trustbeat-signature/"+version)
	// Validation with EU DSS (trusted lists, OCSP, CRL) can take a while for a file with many signatures.
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		fmt.Fprintf(stderr, "could not reach %s: %v\n", base, err)
		return exitError
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	if resp.StatusCode != http.StatusAccepted {
		var e struct {
			Error struct{ Code, Message string } `json:"error"`
		}
		if json.Unmarshal(out, &e) == nil && e.Error.Code != "" {
			fmt.Fprintf(stderr, "%s: %s (%s)\n", resp.Status, e.Error.Message, e.Error.Code)
		} else {
			fmt.Fprintln(stderr, resp.Status)
		}
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return exitRejected
		}
		return exitError
	}
	// The record goes to stdout (or --out) unchanged; what EU DSS found goes to stderr, so a signature that
	// does not validate is never kept without the subscriber being told.
	for _, l := range verify.RecordSummary(out) {
		fmt.Fprintln(stderr, l)
	}
	return write(o.out, out, stdout, stderr)
}

// doVerify checks the file against its package, offline. A file the extractor refuses is still
// verified: steps 1–2 fail with the reason, the package's own steps are reported.
func doVerify(o options, stdout, stderr io.Writer) int {
	in, code := readInput(o, stderr)
	if code != exitOK {
		return code
	}
	pkg, err := os.ReadFile(o.pkg)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	p := verify.Presented{File: extract.FileInfo{Name: in.Name, SizeBytes: int64(len(in.Bytes))}}
	sub, err := extract.Extract(in, tool())
	switch r, refused := extract.AsRefusal(err); {
	case err == nil:
		p.File, p.Submission = sub.Container, sub
	case refused:
		p.Refusal = r.Error()
		p.File.Digests = extract.FileDigests(in.Bytes)
	default:
		fmt.Fprintf(stderr, "%s: %v\n", in.Name, err)
		return exitError
	}
	rep := verify.Run(p, pkg, tool())
	var out []byte
	if o.json {
		if out, err = json.MarshalIndent(rep, "", "  "); err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
		out = append(out, '\n')
	} else {
		out = []byte(rep.Text())
	}
	if code := write(o.out, out, stdout, stderr); code != exitOK {
		return code
	}
	switch rep.Result {
	case verify.Passed:
		return exitOK
	case verify.Failed:
		return exitVerifyFailed
	}
	return exitVerifyIndeterminate
}

func write(path string, b []byte, stdout, stderr io.Writer) int {
	var err error
	if path == "" {
		_, err = stdout.Write(b)
	} else {
		err = os.WriteFile(path, b, 0o644)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	return exitOK
}
