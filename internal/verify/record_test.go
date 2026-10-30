package verify

import (
	"encoding/json"
	"strings"
	"testing"
)

// peoWith is a package whose PEO holds one signature with the given DSS facts.
func peoWith(t *testing.T, dss string) *pkg {
	t.Helper()
	var p pkg
	if !strings.Contains(dss, "verdict_applicable") {
		dss = `{"verdict_applicable":true,` + strings.TrimPrefix(dss, "{")
		dss = strings.Replace(dss, "true,}", "true}", 1)
	}
	doc := `{"signatures":[{"index":0,"format":"PAdES","dss":` + dss + `}]}`
	if err := json.Unmarshal([]byte(doc), &p.peo); err != nil {
		t.Fatal(err)
	}
	return &p
}

func TestChainStepFollowsDSSResult(t *testing.T) {
	signer := `"signer":{"subject":"CN=Jan Novák,C=CZ"}`
	cases := []struct {
		name, dss, want, notWant string
	}{
		{"passed", `{"indication":"TOTAL_PASSED",` + signer + `}`,
			"Signature 0 (Jan Novák): chain to a trust anchor of the EU trusted lists, revocation data for every certificate.", ""},
		// The prod record of 2026-10-30: nothing missing, yet DSS did not pass the chain.
		{"chain failure, nothing missing", `{"indication":"INDETERMINATE","sub_indication":"CERTIFICATE_CHAIN_GENERAL_FAILURE",` + signer + `}`,
			"EU DSS did not confirm a chain to a trust anchor with revocation data: its result is INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE.",
			"chain to a trust anchor of the EU trusted lists"},
		{"failed", `{"indication":"TOTAL_FAILED","sub_indication":"HASH_FAILURE"}`,
			"its result is TOTAL_FAILED / HASH_FAILURE.", "revocation data for every certificate"},
		{"no result", `{}`, "its result is no result recorded.", "revocation data for every certificate"},
		{"missing data wins", `{"indication":"INDETERMINATE","sub_indication":"NO_CERTIFICATE_CHAIN_FOUND","missing_validation_data":["` +
			noTrustAnchor + `"]}`, noTrustAnchor + ". " + notOnTrustedList, "did not confirm"},
		{"revoked", `{"indication":"TOTAL_FAILED","sub_indication":"REVOKED"}`, "revoked (REVOKED).", "did not confirm"},
		// XAdES without its content: DSS's result is about the missing data, not the chain.
		{"verdict not applicable", `{"verdict_applicable":false,"indication":"INDETERMINATE","sub_indication":"SIGNED_DATA_NOT_FOUND"}`,
			"chain to a trust anchor of the EU trusted lists", "did not confirm"},
	}
	for _, c := range cases {
		st := chainStep(peoWith(t, c.dss))
		got := st.Details[0]
		if !strings.Contains(got, c.want) || (c.notWant != "" && strings.Contains(got, c.notWant)) {
			t.Errorf("%s: %s", c.name, got)
		}
		if st.Result != Recorded {
			t.Errorf("%s: result %s", c.name, st.Result)
		}
	}
}

func TestRecordSummary(t *testing.T) {
	rec := `{"id":"01REC","status":"pending","signatures":[
		{"index":0,"signer_subject":"CN=Jan Novák,C=CZ","indication":"TOTAL_PASSED"},
		{"index":1,"signer_subject":"CN=DocuSign\\, Inc.,C=US","indication":"INDETERMINATE","sub_indication":"NO_CERTIFICATE_CHAIN_FOUND"},
		{"index":2,"indication":"TOTAL_FAILED","sub_indication":"SIG_CRYPTO_FAILURE","verdict_applicable":true},
		{"index":3,"indication":"TOTAL_FAILED","sub_indication":"HASH_FAILURE","verdict_applicable":false}]}`
	l := RecordSummary([]byte(rec))
	if len(l) != 5 {
		t.Fatalf("%d lines: %q", len(l), l)
	}
	if !strings.HasPrefix(l[0], "record 01REC: pending") {
		t.Errorf("header: %s", l[0])
	}
	if l[1] != "signature 0 (Jan Novák): EU DSS TOTAL_PASSED." {
		t.Errorf("passed: %s", l[1])
	}
	if !strings.HasPrefix(l[2], "signature 1 (DocuSign, Inc.): EU DSS INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND — preserved") ||
		!strings.Contains(l[2], "does not mean it is invalid") || strings.HasPrefix(l[2], "warning") {
		t.Errorf("indeterminate: %s", l[2])
	}
	if !strings.HasPrefix(l[3], "warning: signature 2: EU DSS found it invalid (TOTAL_FAILED / SIG_CRYPTO_FAILURE)") ||
		!strings.Contains(l[3], "DELETE /v1/signature-preservation/01REC?confirm=01REC") {
		t.Errorf("failed: %s", l[3])
	}
	if !strings.HasPrefix(l[4], "signature 3: preserved; EU DSS's overall result (TOTAL_FAILED / HASH_FAILURE) does not apply") {
		t.Errorf("verdict not applicable must not warn: %s", l[4])
	}
}

func TestRecordSummaryUnreadable(t *testing.T) {
	for _, rec := range []string{``, `not json`, `{"status":"pending"}`} {
		if l := RecordSummary([]byte(rec)); l != nil {
			t.Errorf("%q: %q", rec, l)
		}
	}
	// A record without signatures (an older API) still gets the header line.
	if l := RecordSummary([]byte(`{"id":"01REC","status":"pending"}`)); len(l) != 1 {
		t.Errorf("no signatures: %q", l)
	}
}
