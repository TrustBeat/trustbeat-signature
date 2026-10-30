package verify

import (
	"encoding/json"
	"fmt"
)

// DSSPassed reports whether EU DSS's indication for a signature is a pass.
func DSSPassed(indication *string) bool {
	return indication != nil && (*indication == "TOTAL_PASSED" || *indication == "PASSED")
}

// DSSResult is EU DSS's indication with its sub-indication, as DSS names them.
func DSSResult(indication, subIndication *string) string {
	r := deref(indication, "no result recorded")
	if subIndication != nil && *subIndication != "" {
		r += " / " + *subIndication
	}
	return r
}

// RecordSummary is what `preserve` tells the subscriber about the record the API returned: one line
// per signature with EU DSS's result, and a warning for a signature DSS found invalid. The record is
// kept either way — the result is recorded, not judged (practice statement §3) — so the summary only
// makes sure the subscriber knows what was preserved. Nil when the record cannot be read.
func RecordSummary(record []byte) []string {
	var r struct {
		ID         string `json:"id"`
		Status     string `json:"status"`
		Signatures []struct {
			Index             int     `json:"index"`
			SignerSubject     *string `json:"signer_subject"`
			Indication        *string `json:"indication"`
			SubIndication     *string `json:"sub_indication"`
			VerdictApplicable *bool   `json:"verdict_applicable"`
		} `json:"signatures"`
	}
	if json.Unmarshal(record, &r) != nil || r.ID == "" {
		return nil
	}
	lines := []string{fmt.Sprintf("record %s: %s — the RFC 4998 evidence record follows after the next 10-minute anchoring cycle.", r.ID, r.Status)}
	for _, s := range r.Signatures {
		name := ""
		if s.SignerSubject != nil {
			name = " (" + cn(*s.SignerSubject) + ")"
		}
		res := DSSResult(s.Indication, s.SubIndication)
		switch {
		case s.VerdictApplicable != nil && !*s.VerdictApplicable:
			// DSS's overall result reflects signed content TrustBeat never receives, not the signature.
			lines = append(lines, fmt.Sprintf("signature %d%s: preserved; EU DSS's overall result (%s) does not apply, as it "+
				"depends on signed data that is not sent — `verify` steps 3–6 show what was checked.", s.Index, name, res))
		case DSSPassed(s.Indication):
			lines = append(lines, fmt.Sprintf("signature %d%s: EU DSS %s.", s.Index, name, res))
		case s.Indication != nil && *s.Indication == "TOTAL_FAILED":
			lines = append(lines, fmt.Sprintf("warning: signature %d%s: EU DSS found it invalid (%s). It is preserved as it is, "+
				"but the record does not show that a valid signature was made. If you did not mean to keep it, delete the "+
				"record: DELETE /v1/signature-preservation/%s?confirm=%s (the file still counts as preserved this month).",
				s.Index, name, res, r.ID, r.ID))
		default:
			lines = append(lines, fmt.Sprintf("signature %d%s: EU DSS %s — preserved; its validity is not established under "+
				"the EU trusted lists. This does not mean it is invalid: `verify` steps 3–6 show what was checked.",
				s.Index, name, res))
		}
	}
	return lines
}
