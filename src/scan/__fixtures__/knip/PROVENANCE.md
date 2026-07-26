# `knip-5.88.1-report.json` — provenance

CAPTURED, not hand-written. Real `knip --reporter json` output, consumed by the base
`knipToFindings` unit tests in `src/quality-scan.test.ts`. Before #1150 the `knipReport` literal was
hand-built.

**Do not hand-edit this file.** If it needs to change, re-capture it.

## How it was captured

```
knip --version: 5.88.1
knip --reporter json --no-exit-code
```

Captured 2026-07-26 against a purpose-built mini TypeScript project:

- `src/index.ts` — the sole entry (`knip.json` `entry: ["src/index.ts"]`), importing `usedHelper`
  from `clean.ts` and `usedByMixed` from `mixed.ts`.
- `src/clean.ts` — its one export is imported, so knip reports NO issue for it (a fully-used file
  never appears in knip's output — see the note under the "skipping clean files" test).
- `src/mixed.ts` — reachable via `usedByMixed`, but its `neverImported` value export (line 4) and
  `UnusedType` type export (line 9) are unreferenced → the one `issues` record.
- `src/dead.ts` — imported by nothing → listed whole in `files`.

## What was elided, and what was not

**Nothing was elided.** The report is byte-faithful (re-indented by `jq`). Every field knip's json
reporter emitted is present, including the empty issue-category arrays (`dependencies`, `unlisted`,
`binaries`, …) and the `col`/`pos` offsets on each export record that `KnipExportIssue` does not
read. Keeping them proves the parser tolerates the real, wider record shape.
