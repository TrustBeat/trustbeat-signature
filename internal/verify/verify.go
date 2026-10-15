// Package verify checks a signed file against its Signature Preservation package, offline: the eight
// verification steps of Signature Preservation, as far as they can be done without
// EU DSS and without TrustBeat.
//
//	0 package    manifest.json lists every file with its SHA-256; peo.json is the one the record names
//	1 file       the file's digests equal the PEO's                      (checked here)
//	2 binding    every preserved signature is in the file, same digests  (checked here)
//	3 signature  CMS signers / XML SignatureValue verify                 (checked here)
//	4 chain      certificate chain and revocation at preservation time   (recorded by EU DSS)
//	5 timestamps signature timestamps                                    (recorded by EU DSS)
//	6 qualif.    qualification from the trusted lists of the day         (recorded; the lists are checked)
//	7 evidence   RFC 4998 evidence record over SHA-256(peo.json)          (checked here)
//
// Steps 4–6 need EU DSS: POST /v1/signature-preservation/{id}/verify runs it again offline at
// preservation time, or any DSS-based validator can use the package's files. A "recorded" step is
// what DSS found at preservation, as the PEO states it — not checked again here.
package verify

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/TrustBeat/trustbeat-signature/internal/cms"
	"github.com/TrustBeat/trustbeat-signature/internal/ers"
	"github.com/TrustBeat/trustbeat-signature/internal/extract"
)

// PackageFormat is the package format this verifier reads.
const PackageFormat = "trustbeat-signature-preservation-package-v1"

// ReportVersion is the version of the JSON report.
const ReportVersion = 1

// Results of a step.
const (
	Passed        = "passed"
	Failed        = "failed"
	Indeterminate = "indeterminate"
	NotApplicable = "not-applicable"
	// Recorded: what EU DSS found at preservation, as the PEO states it; not re-checked offline.
	Recorded = "recorded"
)

// Step is one step of the report.
type Step struct {
	Step      int      `json:"step"`
	Name      string   `json:"name"`
	Title     string   `json:"title"`
	Result    string   `json:"result"`
	CheckedBy []string `json:"checked_by"`
	Details   []string `json:"details"`
}

// Report is the outcome of Run.
type Report struct {
	ReportVersion int              `json:"report_version"`
	Verifier      extract.Tool     `json:"verifier"`
	RecordID      string           `json:"record_id,omitempty"`
	PreservedAt   string           `json:"preserved_at,omitempty"`
	PeoSHA256     string           `json:"peo_sha256,omitempty"`
	Presented     extract.FileInfo `json:"presented"`
	Result        string           `json:"result"`
	Claim         string           `json:"claim"`
	Steps         []Step           `json:"steps"`
	EvidenceStamp []ers.Stamp      `json:"evidence_record,omitempty"`
}

// Presented is the file being verified: its submission, or why the extractor refused it.
type Presented struct {
	File       extract.FileInfo
	Submission *extract.Submission
	Refusal    string
}

const (
	byVerifier = "trustbeat-signature"
	byDSS      = "EU DSS at preservation"
)

// Run verifies the presented file against the package (the ZIP's bytes).
func Run(p Presented, pkg []byte, tool extract.Tool) Report {
	rep := Report{ReportVersion: ReportVersion, Verifier: tool, Presented: p.File}
	pk, step0 := openPackage(pkg)
	rep.Steps = append(rep.Steps, step0)
	if pk == nil {
		rep.Result = Failed
		rep.Claim = "The package cannot be used: see step 0."
		return rep
	}
	rep.RecordID, rep.PreservedAt, rep.PeoSHA256 = pk.manifest.RecordID, pk.peo.CreatedAt, pk.manifest.PeoSHA256
	found := presentedSignatures(pk, p)
	rep.Steps = append(rep.Steps,
		fileStep(pk, p),
		bindingStep(pk, p, found),
		signatureStep(pk),
		chainStep(pk),
		timestampsStep(pk),
		qualificationStep(pk),
	)
	ev, stamps := evidenceStep(pk)
	rep.Steps = append(rep.Steps, ev)
	rep.EvidenceStamp = stamps
	rep.Result = combine(rep.Steps)
	switch rep.Result {
	case Passed:
		rep.Claim = fmt.Sprintf("The file is the preserved file, its signature values are intact, and the PEO — signatures, bindings and "+
			"validation data — existed unchanged no later than %s. Chain, signature timestamps and qualification (steps 4–6) are as "+
			"EU DSS recorded them at preservation: re-validate them with EU DSS on the package's files or "+
			"POST /v1/signature-preservation/%s/verify.", stamps[0].GenTime.UTC().Format(time.RFC3339), rep.RecordID)
	case Failed:
		rep.Claim = "At least one step failed: see the steps for which claim does not hold."
	default:
		rep.Claim = "No step failed, but at least one could not be decided here: see the steps for what is open."
	}
	return rep
}

func combine(steps []Step) string {
	var r []string
	for _, s := range steps {
		r = append(r, s.Result)
	}
	switch {
	case has(r, Failed):
		return Failed
	case has(r, Indeterminate):
		return Indeterminate
	}
	return Passed
}

func has(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// ── Package ────────────────────────────────────────────────────────────────

type manifest struct {
	Format         string `json:"format"`
	RecordID       string `json:"record_id"`
	PeoSHA256      string `json:"peo_sha256"`
	EvidenceRecord string `json:"evidence_record"`
	Files          []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"files"`
}

type peoFile struct {
	Name    string          `json:"name"`
	Format  string          `json:"format"`
	Digests extract.Digests `json:"digests"`
}

type peoSignature struct {
	Index        int               `json:"index"`
	Format       string            `json:"format"`
	SignatureB64 string            `json:"signature_b64"`
	Binding      []extract.Binding `json:"binding"`
	DSS          struct {
		Found             bool    `json:"found"`
		Level             *string `json:"level"`
		Indication        *string `json:"indication"`
		SubIndication     *string `json:"sub_indication"`
		Qualification     *string `json:"qualification"`
		VerdictApplicable bool    `json:"verdict_applicable"`
		SignatureIntact   bool    `json:"signature_intact"`
		Signer            *struct {
			Subject   string `json:"subject"`
			NotBefore string `json:"not_before"`
			NotAfter  string `json:"not_after"`
		} `json:"signer"`
		SignerQualification struct {
			AtSigningTime *string `json:"at_signing_time"`
		} `json:"signer_qualification"`
		Timestamps []struct {
			Type           string `json:"type"`
			ProductionTime string `json:"production_time"`
			TSA            string `json:"tsa"`
			Intact         bool   `json:"intact"`
		} `json:"timestamps"`
		Missing []string `json:"missing_validation_data"`
	} `json:"dss"`
}

type peoDoc struct {
	CreatedAt   string         `json:"created_at"`
	Container   peoFile        `json:"container"`
	DataObjects []peoFile      `json:"data_objects"`
	Signatures  []peoSignature `json:"signatures"`
	Timestamps  []struct {
		TokenB64 string            `json:"token_b64"`
		Binding  []extract.Binding `json:"binding"`
	} `json:"timestamps"`
	TrustContext struct {
		TrustedLists []struct {
			Territory      string `json:"territory"`
			SequenceNumber int    `json:"sequence_number"`
			SHA256         string `json:"sha256"`
		} `json:"trusted_lists"`
	} `json:"trust_context"`
	Validation struct {
		Validator      string `json:"validator"`
		ValidationTime string `json:"validation_time"`
	} `json:"validation"`
}

type pkg struct {
	manifest manifest
	files    map[string][]byte
	peo      peoDoc
	peoRaw   []byte
}

func openPackage(b []byte) (*pkg, Step) {
	st := Step{Step: 0, Name: "package", Title: "The package is complete and unchanged", CheckedBy: []string{byVerifier}}
	fail := func(f string, a ...any) (*pkg, Step) {
		st.Result, st.Details = Failed, []string{fmt.Sprintf(f, a...)}
		return nil, st
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return fail("not a ZIP file: %v", err)
	}
	p := &pkg{files: map[string][]byte{}}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return fail("%s: %v", f.Name, err)
		}
		data, err := io.ReadAll(io.LimitReader(rc, 256<<20))
		rc.Close()
		if err != nil {
			return fail("%s: %v", f.Name, err)
		}
		p.files[f.Name] = data
	}
	m, ok := p.files["manifest.json"]
	if !ok {
		return fail("manifest.json is missing")
	}
	if err := json.Unmarshal(m, &p.manifest); err != nil {
		return fail("manifest.json does not parse: %v", err)
	}
	if p.manifest.Format != PackageFormat {
		return fail("package format %q, this verifier reads %s", p.manifest.Format, PackageFormat)
	}
	listed := map[string]bool{"manifest.json": true}
	var bad []string
	for _, f := range p.manifest.Files {
		listed[f.Path] = true
		data, ok := p.files[f.Path]
		if !ok {
			bad = append(bad, f.Path+" is missing")
		} else if sha(data) != f.SHA256 {
			bad = append(bad, f.Path+" has another SHA-256 than the manifest lists")
		}
	}
	var extra []string
	for name := range p.files {
		if !listed[name] {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	p.peoRaw = p.files["peo.json"]
	switch {
	case len(bad) > 0:
		sort.Strings(bad)
		return fail("%s.", strings.Join(bad, "; "))
	case p.peoRaw == nil:
		return fail("peo.json is missing")
	case sha(p.peoRaw) != p.manifest.PeoSHA256:
		return fail("peo.json's SHA-256 is %s, the manifest names %s", sha(p.peoRaw), p.manifest.PeoSHA256)
	}
	if err := json.Unmarshal(p.peoRaw, &p.peo); err != nil {
		return fail("peo.json does not parse: %v", err)
	}
	st.Result = Passed
	st.Details = []string{fmt.Sprintf("manifest.json lists %d files, each present with its SHA-256; peo.json is the PEO of record %s.",
		len(p.manifest.Files), p.manifest.RecordID)}
	if len(extra) > 0 {
		st.Details = append(st.Details, fmt.Sprintf("Not listed in the manifest, ignored: %s.", strings.Join(extra, ", ")))
	}
	return p, st
}

// ── Steps 1–2 ──────────────────────────────────────────────────────────────

func sameDigests(a, b extract.Digests) bool { return a == b }

func fileStep(p *pkg, pr Presented) Step {
	st := Step{Step: 1, Name: "file", Title: "The presented file is the preserved file", CheckedBy: []string{byVerifier}}
	same := sameDigests(p.peo.Container.Digests, pr.File.Digests)
	if same {
		st.Details = append(st.Details, fmt.Sprintf("SHA-256, SHA-512 and SHA3-512 of %s equal the preserved file's (%s).", pr.File.Name, p.peo.Container.Name))
	} else {
		st.Details = append(st.Details, fmt.Sprintf("The digests of %s differ from the preserved file's (%s).", pr.File.Name, p.peo.Container.Name))
	}
	var missing []string
	if pr.Submission != nil {
		for _, d := range p.peo.DataObjects {
			hit := false
			for _, x := range pr.Submission.DataObjects {
				if sameDigests(d.Digests, x.Digests) {
					hit = true
				}
			}
			if !hit {
				missing = append(missing, d.Name)
			}
		}
	} else {
		for _, d := range p.peo.DataObjects {
			missing = append(missing, d.Name)
		}
	}
	if len(p.peo.DataObjects) > 0 {
		if len(missing) == 0 {
			st.Details = append(st.Details, fmt.Sprintf("All %d signed data object(s) are present with the same digests.", len(p.peo.DataObjects)))
		} else {
			st.Details = append(st.Details, fmt.Sprintf("Signed data object(s) missing or changed: %s (give detached data with --data).", strings.Join(missing, ", ")))
		}
	}
	switch {
	case same && len(missing) == 0:
		st.Result = Passed
	case !same && len(missing) == 0 && p.peo.Container.Format == extract.FormatXAdES:
		st.Result = Indeterminate
		st.Details = append(st.Details, "An XML file may be re-serialised without changing what is signed: step 2 decides.")
	default:
		st.Result = Failed
	}
	return st
}

type bindingKey struct {
	kind, byteRange, alg, digest string
	signer                       int
}

func keys(bs []extract.Binding) map[bindingKey]bool {
	out := map[bindingKey]bool{}
	for _, b := range bs {
		s := -1
		if b.Signer != nil {
			s = *b.Signer
		}
		out[bindingKey{b.Kind, fmt.Sprint(b.ByteRange), b.Alg, b.Digest, s}] = true
	}
	return out
}

func sameKeys(a, b map[bindingKey]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// presentedSignatures: PEO signature index → found in the presented file byte for byte, same bindings.
func presentedSignatures(p *pkg, pr Presented) map[int]bool {
	found := map[int]bool{}
	if pr.Submission == nil {
		return found
	}
	for _, ps := range p.peo.Signatures {
		for _, s := range pr.Submission.Signatures {
			if s.SignatureB64 == ps.SignatureB64 && sameKeys(keys(s.Binding), keys(ps.Binding)) {
				found[ps.Index] = true
			}
		}
	}
	return found
}

func bindingStep(p *pkg, pr Presented, found map[int]bool) Step {
	st := Step{Step: 2, Name: "binding", Title: "Every preserved signature is in the presented file, bound to it by the same digests",
		CheckedBy: []string{byVerifier}}
	if pr.Submission == nil {
		st.Result = Failed
		st.Details = []string{"The extractor refuses the presented file: " + pr.Refusal}
		return st
	}
	var absent []string
	for _, s := range p.peo.Signatures {
		if !found[s.Index] {
			absent = append(absent, fmt.Sprint(s.Index))
		}
	}
	var noStamp []string
	for i, t := range p.peo.Timestamps {
		hit := false
		for _, x := range pr.Submission.Timestamps {
			if x.TokenB64 == t.TokenB64 && sameKeys(keys(x.Binding), keys(t.Binding)) {
				hit = true
			}
		}
		if !hit {
			noStamp = append(noStamp, fmt.Sprint(i))
		}
	}
	if len(absent) == 0 {
		st.Details = append(st.Details, fmt.Sprintf("All %d preserved signature(s) found, byte for byte, with the same signed digests "+
			"(byte range, data objects, references), each checked against the file.", len(p.peo.Signatures)))
	} else {
		st.Details = append(st.Details, fmt.Sprintf("Preserved signature(s) %s not in the presented file with the same bindings.", strings.Join(absent, ", ")))
	}
	if len(p.peo.Timestamps) > 0 && len(noStamp) == 0 {
		st.Details = append(st.Details, fmt.Sprintf("All %d document / container timestamp(s) found.", len(p.peo.Timestamps)))
	}
	if len(noStamp) > 0 {
		st.Details = append(st.Details, fmt.Sprintf("Preserved timestamp(s) %s not in the presented file.", strings.Join(noStamp, ", ")))
	}
	if extra := len(pr.Submission.Signatures) - (len(p.peo.Signatures) - len(absent)); extra > 0 {
		st.Details = append(st.Details, fmt.Sprintf("%d signature(s) in the presented file are not part of this record — signed after preservation? A record covers the signatures it was made with: preserve the file again after its last signature.", extra))
	}
	st.Result = Passed
	if len(absent) > 0 || len(noStamp) > 0 {
		st.Result = Failed
	}
	return st
}

// ── Steps 3–6 ──────────────────────────────────────────────────────────────

func signatureStep(p *pkg) Step {
	st := Step{Step: 3, Name: "signature", Title: "The signature value is intact over what it signs", CheckedBy: []string{byVerifier}}
	var results []string
	for _, s := range p.peo.Signatures {
		r, msg := signatureValue(s)
		results = append(results, r)
		st.Details = append(st.Details, fmt.Sprintf("Signature %d%s: %s — %s", s.Index, signerName(s), r, msg))
	}
	st.Result = combineResults(results)
	return st
}

func signatureValue(s peoSignature) (string, string) {
	b, err := base64.StdEncoding.DecodeString(s.SignatureB64)
	if err != nil {
		return Failed, "the stored signature is not base64"
	}
	if s.Format == extract.FormatXAdES {
		c, err := extract.VerifyXMLSignatureValue(b)
		switch {
		case err == nil:
			return Passed, "SignatureValue verifies over the canonical SignedInfo with the KeyInfo certificate " + cn(c.Subject.String()) + "."
		case errors.Is(err, extract.ErrXMLUnsupported):
			return Indeterminate, "not checkable offline here: " + err.Error() + "; EU DSS recorded it as " + intact(s) + "."
		default:
			return Failed, err.Error() + "."
		}
	}
	sd, err := cms.Parse(b)
	if err != nil {
		return Failed, "the stored CMS does not parse: " + err.Error()
	}
	var unsupported []string
	for i := range sd.Signers {
		_, err := sd.VerifySigner(i)
		switch {
		case err == nil:
		case errors.Is(err, cms.ErrUnsupported):
			unsupported = append(unsupported, fmt.Sprintf("signer %d: %v", i, err))
		default:
			return Failed, fmt.Sprintf("signer %d: %v.", i, err)
		}
	}
	if len(unsupported) > 0 {
		return Indeterminate, "not checkable offline here (" + strings.Join(unsupported, "; ") + "); EU DSS recorded it as " + intact(s) + "."
	}
	return Passed, fmt.Sprintf("the CMS signature over the signed attributes verifies with the signer's certificate (%d signer(s)).", len(sd.Signers))
}

func intact(s peoSignature) string {
	if s.DSS.SignatureIntact {
		return "intact"
	}
	return "not intact"
}

func chainStep(p *pkg) Step {
	st := Step{Step: 4, Name: "chain", Title: "The signer's certificate chains to a trust anchor, with revocation data from preservation time",
		CheckedBy: []string{byDSS}, Result: Recorded}
	for _, s := range p.peo.Signatures {
		msg := "chain to a trust anchor of the EU trusted lists, revocation data for every certificate."
		if len(s.DSS.Missing) > 0 {
			var m []string
			for _, x := range s.DSS.Missing {
				if dn, ok := strings.CutPrefix(x, "no revocation data for "); ok {
					x = "no revocation data for " + cn(dn)
				}
				m = append(m, x)
			}
			msg = strings.Join(m, "; ") + "."
		}
		if s.DSS.SubIndication != nil && strings.HasPrefix(*s.DSS.SubIndication, "REVOKED") {
			msg = "revoked (" + *s.DSS.SubIndication + ")."
		}
		st.Details = append(st.Details, fmt.Sprintf("Signature %d%s: %s", s.Index, signerName(s), msg))
	}
	n := 0
	for name := range p.files {
		if strings.HasPrefix(name, "validation-data/") {
			n++
		}
	}
	st.Details = append(st.Details, fmt.Sprintf("The package holds %d certificate / OCSP / CRL file(s) from preservation time (validation-data/) "+
		"for re-validation with EU DSS.", n))
	return st
}

var signatureTimestampTypes = map[string]bool{"SIGNATURE_TIMESTAMP": true, "CONTENT_TIMESTAMP": true,
	"ALL_DATA_OBJECTS_TIMESTAMP": true, "INDIVIDUAL_DATA_OBJECTS_TIMESTAMP": true}

func timestampsStep(p *pkg) Step {
	st := Step{Step: 5, Name: "timestamps", Title: "Signature timestamps are intact and inside the signer certificate's validity",
		CheckedBy: []string{byDSS}, Result: Recorded}
	for _, s := range p.peo.Signatures {
		var ts []string
		for _, t := range s.DSS.Timestamps {
			if signatureTimestampTypes[t.Type] {
				state := "intact"
				if !t.Intact {
					state = "NOT intact"
				}
				ts = append(ts, fmt.Sprintf("%s %s (%s)", t.ProductionTime, state, cn(t.TSA)))
			}
		}
		msg := "no signature timestamp; the earliest proven time is the evidence record's first time-stamp (step 7)."
		if len(ts) > 0 {
			msg = "signature timestamp(s) " + strings.Join(ts, ", ") + "."
		}
		st.Details = append(st.Details, fmt.Sprintf("Signature %d%s: %s", s.Index, signerName(s), msg))
	}
	return st
}

func qualificationStep(p *pkg) Step {
	st := Step{Step: 6, Name: "qualification", Title: "Qualification according to the EU trusted lists in force at preservation time",
		CheckedBy: []string{byDSS, byVerifier}, Result: Recorded}
	for _, s := range p.peo.Signatures {
		q := s.DSS.Qualification
		if !s.DSS.VerdictApplicable {
			q = s.DSS.SignerQualification.AtSigningTime
		}
		st.Details = append(st.Details, fmt.Sprintf("Signature %d%s: %s.", s.Index, signerName(s), deref(q, "no qualification recorded")))
	}
	var bad []string
	for _, tl := range p.peo.TrustContext.TrustedLists {
		name := fmt.Sprintf("trusted-lists/%s-%d.xml", tl.Territory, tl.SequenceNumber)
		if b, ok := p.files[name]; !ok || sha(b) != tl.SHA256 {
			bad = append(bad, name)
		}
	}
	switch {
	case len(p.peo.TrustContext.TrustedLists) == 0:
		st.Details = append(st.Details, "The PEO names no trusted list.")
	case len(bad) == 0:
		st.Details = append(st.Details, fmt.Sprintf("The %d signed trusted list(s) the PEO names are in the package, byte for byte (trusted-lists/).",
			len(p.peo.TrustContext.TrustedLists)))
	default:
		st.Result = Failed
		st.Details = append(st.Details, "Trusted list(s) the PEO names are missing or differ: "+strings.Join(bad, ", ")+".")
	}
	return st
}

// ── Step 7 ─────────────────────────────────────────────────────────────────

func evidenceStep(p *pkg) (Step, []ers.Stamp) {
	st := Step{Step: 7, Name: "evidence-record", Title: "The evidence record proves the PEO existed unchanged since preservation",
		CheckedBy: []string{byVerifier}}
	rec, ok := p.files["evidence-record.ers"]
	if !ok {
		st.Result = Indeterminate
		st.Details = []string{"The package has no evidence record yet (manifest: " + p.manifest.EvidenceRecord + "): download the package again after the next anchoring cycle."}
		return st, nil
	}
	h := sha256.Sum256(p.peoRaw)
	stamps, err := ers.Verify(rec, h[:])
	if err != nil {
		st.Result = Failed
		st.Details = []string{err.Error() + "."}
		return st, nil
	}
	first := stamps[0]
	st.Details = append(st.Details, fmt.Sprintf("RFC 4998 hash tree from SHA-256(peo.json) %s… to the time-stamp of %s by %s.",
		hex.EncodeToString(h[:8]), first.GenTime.UTC().Format(time.RFC3339), cn(first.TSA)))
	if len(stamps) > 1 {
		st.Details = append(st.Details, fmt.Sprintf("%d time-stamp renewal(s), the last at %s; each covers the previous time-stamp.",
			len(stamps)-1, stamps[len(stamps)-1].GenTime.UTC().Format(time.RFC3339)))
	}
	st.Result = Passed
	for _, s := range stamps {
		if !s.SignatureValid {
			st.Result = Failed
			st.Details = append(st.Details, fmt.Sprintf("Time-stamp %d: its signature does not verify (%s).", s.Index, s.SignatureNote))
		}
	}
	if st.Result == Passed {
		st.Details = append(st.Details, "Every time-stamp's signature verifies with its TSA certificate.")
	}
	if created, err := time.Parse(time.RFC3339Nano, p.peo.CreatedAt); err == nil && first.GenTime.Before(created.Add(-time.Minute)) {
		st.Result = Failed
		st.Details = append(st.Details, fmt.Sprintf("The first time-stamp (%s) is older than the record (%s).", first.GenTime.UTC().Format(time.RFC3339), p.peo.CreatedAt))
	}
	st.Details = append(st.Details, "The TSA certificates' chains and qualification: EU DSS or the BSI ERVerifyTool on evidence-record.ers.")
	return st, stamps
}

// ── Helpers ────────────────────────────────────────────────────────────────

func combineResults(rs []string) string {
	switch {
	case has(rs, Failed):
		return Failed
	case has(rs, Indeterminate):
		return Indeterminate
	case has(rs, Passed):
		return Passed
	}
	return NotApplicable
}

func signerName(s peoSignature) string {
	if s.DSS.Signer == nil {
		return ""
	}
	return " (" + cn(s.DSS.Signer.Subject) + ")"
}

// cn is the CN of an RFC 2253 / Go-style DN, or the DN itself. Escaped commas
// (CN=SINIVEE\,VEIKO\,…) stay part of the value and are unescaped.
func cn(dn string) string {
	var parts []string
	var cur strings.Builder
	for i := 0; i < len(dn); i++ {
		switch {
		case dn[i] == '\\' && i+1 < len(dn):
			cur.WriteByte(dn[i+1])
			i++
		case dn[i] == ',':
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(dn[i])
		}
	}
	parts = append(parts, cur.String())
	for _, p := range parts {
		if v, ok := strings.CutPrefix(strings.TrimSpace(p), "CN="); ok {
			return v
		}
	}
	return dn
}

func deref(s *string, def string) string {
	if s == nil || *s == "" {
		return def
	}
	return *s
}

func sha(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Text is the report for a terminal.
func (r Report) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s against Signature Preservation record %s (preserved %s)\n", r.Presented.Name, orDash(r.RecordID), orDash(r.PreservedAt))
	scope := ""
	if r.Result == Passed {
		scope = " (steps 0–3 and 7 checked here; 4–6 as recorded at preservation)"
	}
	fmt.Fprintf(&b, "Result: %s%s\n%s\n\n", strings.ToUpper(r.Result), scope, r.Claim)
	for _, s := range r.Steps {
		fmt.Fprintf(&b, "%d  %-15s %-14s %s\n", s.Step, s.Name, strings.ToUpper(s.Result), s.Title)
		for _, d := range s.Details {
			fmt.Fprintf(&b, "                                     %s\n", d)
		}
	}
	fmt.Fprintf(&b, "\nRECORDED = what EU DSS found at preservation, as the PEO states it, not checked again offline.\n")
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
