# M6 two-reviewer agreement baselines (#813)

Recorded reviewer-pass verdicts in the packet's "Verdict format" schema, compared by
`pnpm exec tsx src/cli/m6-agreement.ts <a.json> <b.json>` (protocol:
`docs/design/m6-simplification-eval.md` §3.5).

The **current baseline is the 2026-07-23 run5/run6 pair** — the first genuinely-paired
two-reviewer run over the full twelve-file corpus (#830, logged in `m6-simplification-eval.md`
§3.6). Two independent fresh-context Claude Fable 5 reviewers each emitted their own verdict at
pass time; the pair agrees 12/12 with no splits (7/7 positives + 5/5 negatives per pass against
the §4 key). It supersedes the seven-file 2026-07-16 pair below as the recorded baseline.

The 2026-07-16 pair is a **transcription** of the historical runs 3 and 4 — the two independent
fresh-context passes logged in `m6-simplification-eval.md` §3.3/§3.4 — into the #813 format,
made 2026-07-23; the `.agreement.txt` beside them is the tool's verbatim output over that pair.
They were real independent passes, but the JSON files postdate them. It speaks only for the
seven-file corpus and is retained for provenance.

An agreement figure here is a rubric-agreement number for one pair of passes — never M6 precision.
