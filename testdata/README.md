# Signature Preservation — fixture corpus and DSS oracle

The test corpus of [trustbeat-signature](../README.md). There is
one source of truth for two implementations: EU DSS (on the server) and the Go extractor
(on the customer's machine). Both are tested against the golden files here.

```
fixtures/manifest.json      one entry per fixture: file, detached data files, what the extractor must do
fixtures/<format>/…         the signed files (PAdES, XAdES, CAdES, ASiC-E/S with XAdES or CAdES, unsigned)
expected/<id>.json          golden file per fixture, written by the DSS oracle
submissions/<id>.json       what the Go extractor sends for each accepted fixture (input for the server's tests)
packages/<id>.zip           record packages the server built from those submissions (input for `verify`)
revisions/                  a fixture signed again after preservation (`verify` must fail step 1)
evidence/                   an RFC 4998 evidence record renewed twice
eps-sample-batch/           real production evidence records, one per leaf (see its README)
```

Everything here except `fixtures/` and `expected/` is TrustBeat's own output: `submissions/` comes from
this extractor (`SP_SUBMISSIONS_WRITE=1 go test ./...`), the rest from the server's tests (the
`SP_*_WRITE=1` switches named in the Go tests).

## Manifest

| Field | Meaning |
|---|---|
| `id` | Fixture name; the golden file is `expected/<id>.json`. One file can be several fixtures (e.g. a detached signature with and without its data). |
| `file` | The file the customer hands to the extractor. |
| `data` | Detached data files (`--data`), optional. |
| `extractor` | `accept`, or `refuse:<reason>` with reason `unsigned`, `missing-data` (a signed data object is not available) or `digest-mismatch` (a data object no longer gives the digest inside the signature). |
| `covers` | What the fixture exercises. |
| `source` | Where the file comes from (see *Licence*). |

## Golden files

`SignatureOracle` (in TrustBeat's server repository, which is not public) writes two views of each
fixture into one JSON document:

- **`parsed`** — what an extractor computes from the file, worked out with PDFBox, Bouncy Castle and
  Santuario independently of DSS: file and data-object digests (SHA-256, SHA-512, SHA3-512); for PDFs
  every signature dictionary with its `/ByteRange`, whether it covers the whole file, the digest of the
  signed range and the CMS cut from `/Contents` (encoding, SHA-256, size); for XML every top-level
  `ds:Signature` with the SHA-256 of its canonical `SignedInfo`, its references (URI, transforms,
  digest) and the namespace declarations it inherits; for CMS the encapsulated content's digests; for
  ASiC the mimetype, data objects and `META-INF` entries.
- **`dss`** — what EU DSS 6.2 reports for the **full** file plus its data files: per signature the
  format, signing certificate, indication and every digest matcher (type, URI/name, algorithm, the
  digest stored in the signature, found, intact); document and container timestamps.

Validation is offline (no OCSP, CRL, AIA or trusted list) at the fixed time 2026-10-12T00:00:00Z, so
the files do not change with the network or as certificates expire. Indications are therefore mostly
`INDETERMINATE/NO_CERTIFICATE_CHAIN_FOUND`; what matters for the extractor is the digest matchers.

`SignatureOracleSpec` (part of `sbt test`) fails when a golden file differs from what DSS reports, when
a fixture file is not in the manifest, and when the two views disagree: the PAdES signed range must
give DSS's `messageDigest`, every digest DSS reads from an XAdES signature must be a reference digest
Santuario reads, data files must give the digests DSS matched, and each `extractor` expectation must
follow from DSS's matchers (`accept` = every matcher of every top-level signature found and intact).

**Regenerate** after adding a fixture or upgrading DSS, then review the diff:

```bash
SP_ORACLE_WRITE=1 sbt "shared/testOnly trustbeat.signaturepreservation.SignatureOracleSpec"
```

The Go extractor ([trustbeat-signature](../README.md)) is tested against the
same files by `TestOracleCorpus`, which also keeps `submissions/` current
(`SP_SUBMISSIONS_WRITE=1 go test ./...` in `signature-extractor/` regenerates them).

## What the corpus taught us (for the extractor)

- **Counter-signatures** are nested inside the signature they counter-sign. The extractor cuts and
  checks top-level signatures only; DSS judges counter-signatures on the server
  (`xades-enveloped-xpath` has a broken counter-signature over an intact signature).
- **PDF document timestamps are not always `/Type /DocTimeStamp`.** In `pades-two-qes-sk` a
  timestamp dictionary has `/Type /Sig` with `/SubFilter /ETSI.RFC3161` — classify by `SubFilter`.
- **BER indefinite length** in `/Contents`: `pades-lt`, `pades-modified-after-signature` and
  `pades-two-signatures-incremental`. Cut the CMS with a BER parser, never by DER length, and never
  re-encode it.
- **ASiC `mimetype` is not always the first entry** (`asice-xades-multifile`): find it by name.
- **DSS test-file names are not verdicts.** `valid-xades.xml` has a `SignedProperties` hash failure;
  `multifiles-wrong-file.asice` holds a different file than its signatures reference (missing data,
  not a digest mismatch).
- `xades-enveloped-xpath` (XPath 1.0) and `xades-enveloped-xpath-filter2` (XPath Filter 2.0) use
  transforms `goxmldsig` lacks; the extractor implements the patterns that
  remove signatures and refuses other expressions.
- Found while building the extractor: an ASiC-E CAdES signature can **encapsulate its
  ASiCManifest** (`asice-cades-lta`); an enveloped signature can hold a non-content `ds:Object`
  (`xades-enveloped-inclusive-inherited-ns`), so content is removed only from enveloping
  signatures; Id values may repeat across `Id`/`ID`/`id` attributes and are refused only when a
  reference points at one; `digitorus/pdf` cannot read the cross-reference table of
  `pades-five-signatures-document-timestamp` (a `/ByteRange` scan takes over).

## Licence

Every fixture whose `source` is a `dss-…` path is a test resource of
[EU DSS](https://github.com/esig/dss) at tag 6.2, © European Commission, licensed under the
**GNU Lesser General Public License 2.1** — kept unmodified, used as test data only, not linked into
or shipped with any TrustBeat product. Two files are derived from DSS files by TrustBeat (as stated
in their `source`) and two (`unsigned/invoice.xml`, `unsigned/no-signature.asice`) were written for this
corpus.
