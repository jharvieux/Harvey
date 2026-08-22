# `semgrep-1.173.0-corpus.json` — provenance

CAPTURED, not hand-written (conservation invariant 3, #1130/#1146/#1156; migrated to the current
1.173.0 authority by #1954; closes #1150 row 7). This is real `semgrep` output. It exists because
pre-existing `src/scan/semgrep.test.ts` literals fed to `parseSemgrepFindings` were HAND-WRITTEN —
the #1063 fiction class, in Harvey's most-relied-on detector: a literal that encodes a field the real
binary never emits, or omits one it does, leaves the parser silently dead against every real target.
The original 1.164.0 capture found and corrected two invented shapes; this 1.173.0 re-capture retains
those corrections and adds exact canonical diagnostic, scope, executed-rule, and timeout evidence.

**Do not hand-edit this file.** If it needs to change, re-capture it with the builder below.

## How it was captured

```
semgrep 1.173.0
node src/scan/__fixtures__/semgrep/build-corpus.mjs > semgrep-1.173.0-corpus.json
```

`build-corpus.mjs` writes a purpose-built corpus to a throwaway temp dir — one source file per
`parseSemgrepFindings` test scenario, plus an inert `.github/workflows/release.yml` for the CI-routing
case — and runs the pinned binary with the same rule/config and output/scope surface used by
`runSemgrep` (`src/scan/semgrep.ts`): the six registry packs
`p/typescript,p/react,p/nextjs,p/owasp-top-ten,p/secrets,p/security-audit` + the custom
`src/scan/rules/semgrep/` rules, `--disable-nosem --x-ignore-semgrepignore-files --timeout 0 --time
--json --verbose`. This deliberately small parser corpus does not reproduce the production Carbon
paired-cold local-injection measurement; that whole-family evidence is recorded at the production
seam and in `docs/design/semgrep-determinism.md`. Registry packs are fetched from the Semgrep registry
over the network on first run (cached after).

The `.github/workflows/` file lives ONLY in the temp corpus — it is never written into the repo tree,
so it is not a Harvey CI definition and GitHub never executes it. Captured 2026-08-21.

### Why the corpus, not one drop-in file

Each `parseSemgrepFindings` branch needs a DIFFERENT real rule to fire (service-role-in-client for
ERROR+HIGH, an `.audit.` rule for the audit-routing case, a `harveyTaxonomy` rule for the override, a
registry rule with bare-STRING cwe/owasp for the #976 normalization, a rule carrying references for
#1077, a workflow-path rule for CI routing). That is per-rule target reconstruction — exactly why
#1150 split row 7 out. The builder is the reproducible recipe (mirrors trufflehog's throwaway-repo
provenance).

### Stable check_id namespace

A semgrep rule's `check_id` namespace prefix is derived from the `--config` PATH, so a raw run against
a temp dir would bake the capturing machine's absolute path into every `harvey-*` id. The builder
copies the rules to their repo-relative location inside the temp root and runs with
`--config src/scan/rules/semgrep/`, so `harvey-*` ids come out identical to a production run from the
repo root (`src.scan.rules.semgrep.harvey-*`). In a live engagement this prefix is machine-dependent;
the parser keys only on the id SUFFIX and the `.audit.` marker (`ruleIdMatches`/`isAuditRule`), so the
prefix is not load-bearing.

## What canonicalization drops, and what it preserves

Finding and diagnostic records are never hand-edited or dropped. The tracked
`canonicalizeSemgrepFixtureOutput` function is shared by the builder and the live drift comparator;
it normalizes only the known throwaway root and sorts result, error, scanned-path and skipped-path
populations for a deterministic comparison.

- At the envelope level it drops only `profiling_results`. It keeps `version`, `results`, `errors`,
  `paths.scanned`, `paths.skipped`, `skipped_rules`, `engine_requested`, and canonical semantic
  `time` evidence.
- Within `time`, it drops only the enumerated profiling children (`rules_parse_time`,
  `profiling_times`, `parsing_time`, `scanning_time`, `matching_time`, `tainting_time`,
  `prefiltering`, `targets`, `total_bytes`, `max_memory_bytes`). It retains the complete sorted
  `rules` and `fixpoint_timeouts` populations. A new unclassified `time` child throws instead of
  being silently discarded.
- Every per-result field is retained, including `extra.lines`, `extra.fingerprint`,
  `extra.validation_state`, `extra.engine_kind`, `extra.message`, `extra.severity`, and the complete
  `extra.metadata` block. Every per-path error and skip remains client-facing drift evidence.

The committed 1.173.0 fixture canonically contains 309 executed rule IDs and 0 fixpoint timeouts.
No secret-shaped strings are present — the `.npmrc` uses `${NPM_TOKEN}`, not a literal token.

## Fiction the historical 1.164.0 capture corrected (revalidated at 1.173.0)

- The old `#455 "never invents cwe"` literal put NO cwe on `harvey-service-role-in-client`. MEASURED
  2026-07-26 with 1.164.0 and revalidated by the 1.173.0 fixture: every captured `harvey-*` match
  carries `cwe` (and the captured registry matches do too). The negative control (a result with no cwe
  → the parser adds neither field) is therefore synthetic and kept as a labelled literal, not a capture.
- The old `#976 "bare-STRING cwe/owasp"` literal used a fabricated `tainted-sql-string` record. The
  real bare-string carrier is `problem-based-packs...bypass-tls-verification`, which ships BOTH `cwe`
  and `owasp` as bare strings — now captured here and asserted directly.
- The old `#1077 references` literal claimed `severity: "ERROR"` for
  `npm-missing-minimum-release-age`; the rule really emits `severity: "MEDIUM"` (a value
  `SEVERITY_FROM_SEMGREP` does not map — it falls through to the "Medium" default, which is correct
  here but means a registry rule emitting `HIGH`/`CRITICAL` would under-map; tracked as an
  observation, not fixed in this PR).

## Genuinely synthetic literals that remain (no real rule emits them)

`bare-string references` (#1077) and `no-cwe` (#455) are kept as small labelled literals in
`semgrep.test.ts`, because no rule across the six packs Harvey loads emits either shape:

REASON: No semgrep rule across the six registry packs Harvey loads emits a match with a bare-STRING `references` value, nor a match carrying no `cwe` at all — both are shapes the JSON type admits and `parseSemgrepFindings` must handle defensively, but neither is reproducible from a real run, so they stay as labelled synthetic negative-control literals rather than fabricated captures.
KIND: empirical
PROVENANCE: MEASURED 2026-07-26 with semgrep 1.164.0 and revalidated 2026-08-21 with semgrep 1.173.0 (`build-corpus.mjs` against all six packs; bare-string `cwe`/`owasp` DO occur — bypass-tls-verification — bare-string `references` and no-`cwe` do not)
FALSIFIER: test -f src/scan/__fixtures__/semgrep/build-corpus.mjs || exit 127; node src/scan/__fixtures__/semgrep/build-corpus.mjs > /tmp/harvey-semgrep-corpus.json 2>/dev/null || exit 127; node -e "let r;try{r=JSON.parse(require('fs').readFileSync('/tmp/harvey-semgrep-corpus.json','utf8')).results}catch{process.exit(127)}process.exit(r.some(x=>typeof x.extra?.metadata?.references==='string'||!x.extra?.metadata?.cwe)?0:1)"

The falsifier exits 0 once any pack ships a bare-string `references` or a no-`cwe` match, at which point
those two literals can be replaced by a captured record.
