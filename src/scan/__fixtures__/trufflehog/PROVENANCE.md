# `trufflehog-3.96.0-git-unverified.json` — provenance

CAPTURED, not hand-written (conservation invariant 3, #1130/#1146). This is real TruffleHog output,
kept because the pre-existing `src/scan/secrets.test.ts` literals were HAND-WRITTEN
(FIXTURE-INVENTORY.md rows 8 & 10): a literal encoding a field TruffleHog never emits, or missing one
it does, leaves `parseTruffleHogFindings` silently dead against every real target (the #1063 class).

**Do not hand-edit this file.** If it needs to change, re-capture it.

## How it was captured

```
trufflehog 3.96.0
trufflehog git --no-verification --results=unverified --json file://<throwaway-repo>
```

Captured 2026-07-26. `<throwaway-repo>` is a temp git repo built exactly as
`buildGitHistoryFixture()` builds it (`src/scan/git-history-secret-gate.ts`): a fake, valid-shape-only
GitHub PAT committed in one commit and `git rm`'d in the next, so the only way TruffleHog can report it
is by walking history. `--no-verification` makes no network call — a fake token could never verify
anyway, which is exactly the limitation the REASON block below records.

## What was dropped, and what was not

TruffleHog emits JSONL (one JSON object per result line); the records were collected into a JSON array
(envelope change only — the parser consumes `TruffleHogResult[]`). Records were **dropped, never
edited** — every field present is byte-for-byte as TruffleHog emitted it (modulo re-indentation).
Dropped fields:

- `Raw`, `RawV2`, `SecretParts` — carry the matched token value verbatim; not read by
  `parseTruffleHogFindings`, and a committed token-shaped string trips push protection.
- `SourceMetadata.Data.Git.repository` and `.repository_local_path` — the capturing machine's absolute
  temp paths; not read by the parser.

Everything the parser reads survives verbatim: `DetectorName`, `DecoderName`, `Verified`, `Redacted`
(the empty-string the #1099 fallback keys on), `ExtraData.rotation_guide` (#1078), and
`SourceMetadata.Data.Git` (`commit`/`file`/`email`/`timestamp`/`line`).

## The verified-secret path is live-only

`parseTruffleHogFindings` DROPS unverified hits — only a live-verified secret (`Verified: true`) reaches
the grading path. This capture is `Verified: false` because `--no-verification` was used against a fake
token; the field cannot be flipped in a committed fixture without EDITING captured output, which
invariant 3 forbids. So the grading-path tests apply `{ ...record, Verified: true }` at the test site
(the ONLY field not from the tool, disclosed there), and the impossibility of an offline verified
capture is recorded here:

REASON: A TruffleHog `Verified: true` record cannot be captured offline — verification is a live network call to the credential's provider (e.g. GitHub) against a real, revocable secret; a fake fixture token can never verify.
KIND: empirical
PROVENANCE: MEASURED 2026-07-26
FALSIFIER: test -f src/scan/__fixtures__/trufflehog/trufflehog-3.96.0-git-verified.json
TOUCHES: src/scan/secrets.ts src/scan/__fixtures__/trufflehog

The falsifier exits 0 once a real live-verified capture is committed at that path (captured against a
revocable provider token with network up), which is the concrete point at which the offline-impossibility
blocker no longer holds and the `{ ...record, Verified: true }` overrides in `secrets.test.ts` can be
replaced by loading the verified fixture directly.
