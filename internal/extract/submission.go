package extract

import (
	"errors"
	"fmt"
)

// SubmissionVersion is the version of the JSON the extractor sends to the API. Fields are only
// ever added within a version.
const SubmissionVersion = 1

// Submission is everything the API receives about one signed file. The file itself never leaves
// the customer's machine (P2): only its digests, the signatures and the binding digests.
type Submission struct {
	SubmissionVersion int         `json:"submission_version"`
	Extractor         Tool        `json:"extractor"`
	Container         FileInfo    `json:"container"`
	DataObjects       []FileInfo  `json:"data_objects"`
	Signatures        []Signature `json:"signatures"`
	Timestamps        []Timestamp `json:"timestamps"`
	Notes             []string    `json:"notes,omitempty"`
}

// Tool names the extractor build that produced the submission.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// FileInfo describes a file by name, size and digests.
type FileInfo struct {
	Format    string  `json:"format,omitempty"`
	Name      string  `json:"name"`
	SizeBytes int64   `json:"size_bytes"`
	Digests   Digests `json:"digests"`
}

// Digests of a whole file (hex).
type Digests struct {
	SHA256   string `json:"sha256"`
	SHA512   string `json:"sha512"`
	SHA3_512 string `json:"sha3-512"`
}

// Signature is one top-level signature. Counter-signatures stay inside it.
type Signature struct {
	// Format of the signature object: "CAdES" (PAdES /Contents is a detached CAdES SignedData)
	// or "XAdES".
	Format string `json:"format"`
	// Source says where in the file the signature was found: "pdf", a ZIP entry name, or the file.
	Source string `json:"source"`
	// ID is the XML signature's Id attribute, if any.
	ID string `json:"id,omitempty"`
	// SignatureB64 is the signature object: verbatim, or the derived copy described by Derived.
	SignatureB64 string `json:"signature_b64"`
	// Derived lists how SignatureB64 differs from the bytes in the file: "content-detached"
	// (enveloped content removed), "namespace-context" (inherited namespace / xml:* declarations
	// added to a cut-out XML signature), "re-encoded-utf8" (XML converted from another encoding).
	Derived []string `json:"derived,omitempty"`
	// SignedInfoC14NSHA256 is the SHA-256 of the canonical SignedInfo (XAdES); the server
	// recomputes it from SignatureB64 and it must match.
	SignedInfoC14NSHA256 string `json:"signed_info_c14n_sha256,omitempty"`
	// ManifestB64 is the ASiCManifest an ASiC-E CAdES signature signs (names and digests only).
	ManifestB64 string    `json:"manifest_b64,omitempty"`
	Binding     []Binding `json:"binding"`
}

// Binding is one digest inside a signature that ties it to signed data, and the extractor's
// finding that the data in hand reproduces it ("checked_by": "extractor").
type Binding struct {
	// Kind: "byte-range" (PDF), "content" (CMS messageDigest over a data object or the
	// encapsulated content), "manifest" (CMS messageDigest over an ASiCManifest),
	// "manifest-entry" (a data object listed in that manifest), "reference" (XML-DSig Reference).
	Kind string `json:"kind"`
	// Signer is the index of the CMS SignerInfo (CMS kinds only).
	Signer *int `json:"signer,omitempty"`
	// Target names the data: a data-object name, a same-document URI, or a manifest entry.
	Target    string  `json:"target,omitempty"`
	ByteRange []int64 `json:"byte_range,omitempty"`
	// CoversWholeFile: the byte range reaches the end of the file (PDF only).
	CoversWholeFile *bool    `json:"covers_whole_file,omitempty"`
	URI             *string  `json:"uri,omitempty"`
	Type            string   `json:"type,omitempty"`
	Transforms      []string `json:"transforms,omitempty"`
	// Alg is an OID (CMS) or URI (XML-DSig).
	Alg    string `json:"alg"`
	Digest string `json:"digest"`
	// Checked is always true in a submission: a binding that does not match is a refusal.
	Checked bool `json:"checked"`
}

// Timestamp is a timestamp over the file itself rather than over a signature: a PDF document
// timestamp or an ASiC container timestamp.
type Timestamp struct {
	Kind     string `json:"kind"`
	Source   string `json:"source"`
	TokenB64 string `json:"token_b64"`
	// ManifestB64 is the ASiCArchiveManifest an ASiC-E timestamp covers.
	ManifestB64 string    `json:"manifest_b64,omitempty"`
	Binding     []Binding `json:"binding"`
}

// Refusal reasons. The extractor exits non-zero and sends nothing.
const (
	ReasonUnsigned       = "unsigned"
	ReasonMissingData    = "missing-data"
	ReasonDigestMismatch = "digest-mismatch"
	ReasonUnsupported    = "unsupported"
	ReasonMalformed      = "malformed"
)

// Refusal explains why a file is not accepted.
type Refusal struct {
	Reason string
	Detail string
}

func (r *Refusal) Error() string { return fmt.Sprintf("refused (%s): %s", r.Reason, r.Detail) }

func refuse(reason, format string, a ...any) *Refusal {
	return &Refusal{Reason: reason, Detail: fmt.Sprintf(format, a...)}
}

// AsRefusal returns the refusal inside err, if any.
func AsRefusal(err error) (*Refusal, bool) {
	var r *Refusal
	ok := errors.As(err, &r)
	return r, ok
}

func malformed(err error, what string) error {
	if _, ok := AsRefusal(err); ok {
		return err
	}
	return refuse(ReasonMalformed, "%s: %v", what, err)
}
