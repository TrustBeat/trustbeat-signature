# Golden evidence records — production batch of 14 Sep 2026 08:10 UTC

> A copy of the server's golden files, used here by `internal/ers` to check the extractor's own
> RFC 4998 verifier against real records. The files are frozen: never edit or regenerate the copy.

Real evidence records that TrustBeat issued in production, used by `EvidenceRecordsSpec` to prove that
`EvidenceRecords.build` still produces **exactly the same bytes** for records already in customers' hands.

- `leaves.txt` — the batch's 21 leaf hashes in `leaf_index` order, as stored in `anchor_leaves`. They are
  SHA-256 values of fictitious sample parking events (no customer data).
- `token.der` — the batch's RFC 4998 timestamp token from `batch_evidence_records.token_der`
  (SK TIMESTAMPING UNIT 2026E, genTime 2026-09-14T08:10:40Z, RFC 4998 root `87bfed7a…`).
- `records/<hash>.ers` — the evidence record for each leaf, byte for byte as served by
  `GET /v1/public/proof/{id}/evidence-record.ers`. Each validated PASSED / QTSA on the European
  Commission's DSS Demonstration WebApp.

**Never regenerate these files to make a failing test pass.** A mismatch means a code or library change
(e.g. a Bouncy Castle upgrade) alters records that customers have already downloaded and whose SHA-256 is
printed in their evidence record reports. Fix the change, or version the record format deliberately.
