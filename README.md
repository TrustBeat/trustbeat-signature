# trustbeat-signature

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

The signature extractor for **TrustBeat Signature Preservation**: long-term preservation of
electronic signatures (PAdES, XAdES, CAdES, ASiC-E/S) under ETSI TS 119 511, with RFC 4998 evidence
records over eIDAS-qualified timestamps.

Part of **[TrustBeat](https://trustbeat.eu/en)** — digital trust infrastructure for the EU.

One static executable per OS (Go, `CGO_ENABLED=0`, ~6.5 MB). It reads a signed file on your machine
and writes a **submission**: the signatures, the digests that bind them to the signed data — each
checked here against the data in hand — and the file's own digests. **The signed file never leaves
your machine**; TrustBeat receives signatures and digests only. The source is open so that you can
check exactly what is sent.

> **Status:** Signature Preservation is not launched yet. `extract` and `verify` work offline today;
> `preserve` gets `404` from the API until launch.

## Install

```bash
brew install trustbeat/tap/trustbeat-signature           # macOS, Linux
```

```powershell
scoop bucket add trustbeat https://github.com/TrustBeat/scoop-bucket   # Windows
scoop install trustbeat-signature
```

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" \
  ghcr.io/trustbeat/trustbeat-signature extract contract.pdf --out sub.json
```

Homebrew and Scoop install the release archives below and check their SHA-256. The container image
(linux/amd64 + arm64, distroless, ~3.5 MB) packs the same release binaries; it runs as a non-root
user, so pass `--user` as above when it writes into the mounted directory. Its signature (needs
cosign v3 or later — v2 does not read the Sigstore bundle format and reports "no signatures found"):

```bash
cosign verify ghcr.io/trustbeat/trustbeat-signature:0.1.1 \
  --certificate-identity-regexp '^https://github.com/TrustBeat/trustbeat-signature/\.github/workflows/docker\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Or download the archive for your OS from [Releases](https://github.com/TrustBeat/trustbeat-signature/releases)
(Linux, macOS and Windows; amd64 and arm64) and put `trustbeat-signature` on your `PATH`. Or build it
yourself: `GOTOOLCHAIN=local CGO_ENABLED=0 go build -trimpath .` (Go version pinned in `go.mod`).

### Checking a download

Every release carries `SHA256SUMS`, signed in CI with [Sigstore cosign](https://docs.sigstore.dev/)
(keyless — the signature is bound to this repository's release workflow, there is no TrustBeat key to
lose). Check the signature, then the archive:

```bash
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/TrustBeat/trustbeat-signature/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --check --ignore-missing SHA256SUMS
```

Binaries are built by CI from the tagged source only, never on a workstation. Each archive holds
`LICENSE` and `THIRD_PARTY_LICENSES.txt` (the licences of every Go module linked into the binary).

The build is reproducible: rebuild a release from its tag and compare with the published checksums
(needs Go 1.23.4, the version pinned in `go.mod`, and `git`, `tar`, `gzip`, `zip`):

```bash
git clone --branch v0.1.1 https://github.com/TrustBeat/trustbeat-signature.git && cd trustbeat-signature
./build.sh v0.1.1 && diff dist/SHA256SUMS <(curl -sL https://github.com/TrustBeat/trustbeat-signature/releases/download/v0.1.1/SHA256SUMS)
```

Build from a git clone: the binary records the commit it was built from.

## Usage

```bash
trustbeat-signature extract contract.pdf                       # PAdES
trustbeat-signature extract invoice.xml --out sub.json         # XAdES (enveloped / enveloping)
trustbeat-signature extract doc.xml.p7s --data doc.xml         # detached CAdES / XAdES
trustbeat-signature extract contract.asice                     # ASiC-E / ASiC-S (data is inside)
```

Exit codes: `0` done (`verify`: passed), `1` I/O or network error, `2` usage, `3` refused by the
extractor, `4` rejected by the API, `5` `verify`: a step failed, `6` `verify`: a step could not be decided. A refusal prints `refused (<reason>): <detail>` and writes or sends nothing.
`extract` works offline.

```bash
export TRUSTBEAT_API_KEY=tb_live_…            # TRUSTBEAT_API_URL overrides https://api.trustbeat.eu
trustbeat-signature preserve contract.pdf --client-ref contract-17
```

`preserve` extracts as above and posts the submission — never the file — to
`POST /v1/signature-preservation`, then prints the record the API returns (status `pending` →
`anchored` → `preserved`). The endpoint answers `404` until the product is launched.

**File names.** The submission carries the signed file's name, which often names a person
(`Smlouva_Jan_Novak.pdf`). `--hide-names` (on `extract` and `preserve`) sends the first 16 hex digits
of the file's SHA-256 plus its extension instead (`3f9a…c2.pdf`; a `.pdf.p7m` keeps both
extensions). Names that are part of what was signed — data files inside an ASiC container, URIs of
XML references — cannot be changed and stay, as do the names of `--data` files.

## Verifying later

```bash
trustbeat-signature verify contract.pdf --package trustbeat-signature-preservation-<id>.zip   # --json for JSON
```

Checks the file against the record's package (`GET /v1/signature-preservation/{id}/package`) **offline,
without TrustBeat**: (0) the package is complete — every file has the SHA-256 `manifest.json` lists and
`peo.json` is the record's PEO; (1) the file's digests equal the preserved file's; (2) every preserved
signature is in the file, byte for byte, with the same binding digests (re-extracted from the file); (3)
each signature verifies — CMS signers over their signed attributes, XML `SignatureValue` over the canonical
`SignedInfo` (brainpool keys are reported as not checkable here); (7) the RFC 4998 evidence record folds
from SHA-256(`peo.json`) to each time-stamp, every time-stamp's signature verifies, renewals in order.
Steps 4–6 (chain and revocation, signature timestamps, qualification) need EU DSS: the report shows what
DSS recorded at preservation and checks that the trusted lists the PEO names are in the package byte for
byte; `POST /v1/signature-preservation/{id}/verify` (same submission as `extract` writes) runs DSS again
offline at preservation time, with a PDF report. A file the extractor refuses is still reported: steps 1–2
fail with the reason. **A record covers the signatures it was made with:** a file signed again after
preservation is a different file (step 1 fails; the new signatures are listed as not part of the record) —
preserve it again after its last signature. Step by step for auditors: the `README.txt` inside every
record package.

## What it does per format

| Format | Signature object in the submission | Bindings checked |
|---|---|---|
| PAdES | the CMS cut from `/Contents` (zero padding removed, BER kept — never re-encoded) | each signer's `messageDigest` = digest of the `/ByteRange`; the range must leave out exactly the `/Contents` string. Document timestamps: message imprint = digest of their range. `covers_whole_file` and a note when the file changed after the last signature |
| CAdES `.p7s` | verbatim | `messageDigest` = digest of the `--data` file |
| CAdES `.p7m` | **content-detached copy** (`derived: content-detached`): eContent removed, signerInfos / certificates / CRLs byte-identical | `messageDigest` = digest of the encapsulated content |
| XAdES | each top-level `ds:Signature` cut out byte-exact, with the namespace declarations it inherits added to its start tag (`namespace-context`), content `ds:Object`s of an enveloping signature removed (`content-detached`), XML declaration kept; Latin-1 / Windows-1252 converted to UTF-8 (`re-encoded-utf8`) | every `ds:Reference`, after its transforms; then a **self-check**: the cut-out copy must give the same canonical `SignedInfo` and the same digests for the references it still contains |
| ASiC-E / ASiC-S | XAdES as above per signature file; CAdES verbatim with the `ASiCManifest` it signs | references / manifest entries against the container's data objects; container and archive timestamps (`ASiCArchiveManifest`) |

Every file and data object gets SHA-256, SHA-512 and SHA3-512 (P7). Counter-signatures stay inside
the signature they counter-sign; DSS judges them on the server.

**XML transforms:** enveloped-signature, C14N 1.0 / 1.1 / exclusive (with or without comments),
base64, XPath `not(ancestor-or-self::ds:Signature)`, and XPath Filter 2.0 *subtract* of signatures
(`/descendant::*[name()='ds:Signature']`, `//ds:Signature`, `here()/ancestor::ds:Signature[1]`).
Anything else is refused as `unsupported`.

## Refusals

| Reason | When |
|---|---|
| `unsigned` | no signature in the file |
| `missing-data` | a detached signature without its `--data`, or a reference / manifest entry whose data is not there |
| `digest-mismatch` | the data no longer gives the digest inside the signature (changed after signing) |
| `unsupported` | DOCTYPE, an XML encoding other than UTF-8 / Latin-1 / Windows-1252, an unknown transform or digest algorithm, inclusive C14N with inherited `xml:*` attributes, an encrypted PDF, a signer without signed attributes, a signature that cannot be cut out without changing its `SignedInfo` |
| `malformed` | the file does not parse, an invalid `/ByteRange`, a reference to an Id used by two elements (signature wrapping) |

## The submission (version 1)

Go types with field documentation: [`internal/extract/submission.go`](internal/extract/submission.go).
Real examples for every accepted fixture: [`testdata/submissions/`](testdata/submissions/).
The server re-checks what it can: the signature cryptographically, and that the declared
binding digests are the ones inside the signature. That the data produces them is checked only
here (`checked_by: extractor` in the PEO) — customers re-check it with their own file at
verification time.

## Tests

```bash
GOTOOLCHAIN=local go test ./...          # DSS oracle corpus, refusals, CLI, BER reader
GOTOOLCHAIN=local go test ./internal/extract -run '^$' -fuzz FuzzExtract -fuzztime 60s
./build.sh 0.1.0                          # release archives for 6 OS/arch pairs + SHA256SUMS into dist/
```

`TestOracleCorpus` runs all fixtures of [`testdata/`](testdata/README.md):
each must be accepted or refused as the manifest says, and an accepted one must reproduce EU DSS's
golden file — file digests, data objects, one signature per DSS signature, the cut CMS byte for
byte, Santuario's canonical `SignedInfo`, and every digest DSS reads from a signature as a checked
binding. It also keeps `submissions/<id>.json` current (`SP_SUBMISSIONS_WRITE=1` regenerates).

## Dependencies

Pinned in `go.mod`, built with `GOTOOLCHAIN=local` (no silent toolchain download):
`beevik/etree` (XML tree), `russellhaering/goxmldsig` (canonicalisation only — byte-identical to
Santuario on the corpus), `digitorus/pdf` (AcroForm walk; a `/ByteRange` scan takes over when its
cross-reference parser fails, cross-checked against it on every corpus PDF), `golang.org/x/crypto`
(SHA-3) and `golang.org/x/text` (Latin-1). CMS is read with our own BER reader
([`internal/ber`](internal/ber)): `digitorus/pkcs7` silently drops signers of SignedData v5 with
OCSP.

## Licence

MIT — see [LICENSE](LICENSE). The licences of the Go modules linked into the binary ship in every
release archive as `THIRD_PARTY_LICENSES.txt` (`./build.sh` writes it from the modules in the build).
Most files in `testdata/fixtures/` are test resources of [EU DSS](https://github.com/esig/dss)
(© European Commission, LGPL 2.1), used as test data only and not part of the binary — see
[testdata/README.md](testdata/README.md#licence).
