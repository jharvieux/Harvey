# `gitleaks-8.30.1-corpus.json` — provenance

CAPTURED, not hand-written (conservation invariant 3, #1130/#1146/#1156, closes #1150 row 9). This is
real `gitleaks` output against Harvey's OWN custom ruleset. The pre-existing
`src/scan/secrets.test.ts` literals fed to `parseGitleaksFindings` were hand-built — the #1063 class:
a literal encoding a field gitleaks never emits, or a correlation arrangement (demo-marker
co-location, test-IdP down-rank) that a real run does not actually produce, leaves the parser's
suppression/down-rank logic silently dead against every real target.

Capturing this VERIFIED the literals were faithful (MEASURED 2026-07-26, gitleaks 8.30.1): every
tested RuleID is a real id, the real `Match` values match (`"role":"service_role"`,
`"iss":"supabase-demo"`, `ENTITY_ID`), and — the load-bearing one — the #210 demo co-location really
does report `supabase-service-role-jwt` and `supabase-demo-key-marker` on the SAME `File:StartLine`
(a single decoded JWT body carries both claims). No invented field was found; the value of the
capture is pinning the parser to real output so a future gitleaks shape change is caught.

**Do not hand-edit this file.** If it needs to change, re-capture it with the builder below.

## How it was captured

```
gitleaks 8.30.1
node src/scan/__fixtures__/gitleaks/build-corpus.mjs > gitleaks-8.30.1-corpus.json   # then File-relativized, see below
```

`build-corpus.mjs` writes a planted-secret corpus to a throwaway temp dir — one scenario per
`parseGitleaksFindings` branch (service-role high, generic review, private-key impact, demo
co-location clear, test-IdP CI-workflow down-rank, test-IdP non-workflow stays high, stripe/db-URI
redaction, correlation-markers-not-surfaced) — and runs the EXACT pinned invocation `runGitleaks`
builds (`src/scan/secrets.ts`): `gitleaks detect --no-git --config src/scan/rules/gitleaks-supabase.toml
--max-decode-depth 2`. The `--max-decode-depth 2` is what base64-decodes the JWT bodies so the
service-role/demo-iss claims match and co-locate. Captured 2026-07-26.

The demo/service-role JWTs are structural fakes (`header.payload.sig`, `sig` = `c2ln`) whose DECODED
payloads carry the claims the rules key on — non-functional, so no live credential is committed. The
`.github/workflows/` file lives ONLY in the temp corpus, never in the repo tree, so it is not a
Harvey CI definition and GitHub never executes it.

## What was transformed, and what was not

Every field VALUE is byte-for-byte as gitleaks emitted it, with ONE disclosed exception:

- `File` was relativized — the mkdtemp scan-scope prefix (`/var/folders/.../harvey-gitleaks-corpus-*/`,
  which carries the capturing machine's user-folder hash) was stripped to the corpus-relative path.
  This is the IDENTICAL transform production's `relativizeScanScope` applies to gitleaks' absolute
  `-s` paths at runtime (#1104); committing the raw absolute path would leak the operator's temp
  layout and be unreproducible on any other machine. No other value is touched.

Fields dropped per record (not read by `parseGitleaksFindings`): `Author`, `Email`, `Date`,
`Message`, `Tags`, `Entropy`, `Fingerprint`, `StartColumn`/`EndColumn`/`EndLine`, `SymlinkFile`.
Kept: `RuleID`, `Description`, `File`, `StartLine`, `Commit`, `Match`, `Secret` — the fields the
parser reads. Records are sorted by `(File, StartLine, RuleID)` for a deterministic diff.

## Deliberately synthetic literals that remain (secrets.test.ts, #1078 allowlist block)

The `allowlist suppressions are scoped to the value and counted (#1078)` describe keeps hand-built
literals ON PURPOSE. Its whole subject is a value-scoped allowlist, and a live-shaped `sk_live_…`
Stripe key run through a real capture trips GitHub push protection — the reason those literals were
defanged in the first place (noted at the block). They exercise `parseGitleaksFindings`/
`gitleaksSuppression` logic on defanged values, not the gitleaks regex, so a capture would add no
fidelity there:

REASON: The #1078 allowlist tests must use DEFANGED (non-live-shaped) secret literals — a real `sk_live_`/`pk_live_` value run through gitleaks and committed as a fixture trips GitHub push protection, and the tests exercise parseGitleaksFindings/gitleaksSuppression on the VALUE, not the gitleaks regex, so a real capture adds no fidelity.
KIND: decisional
PROVENANCE: MEASURED 2026-07-26
OWNER: operator
DECISION: keep the #1078 allowlist literals defanged and synthetic; do not capture them.
