# M6 two-reviewer agreement baselines (#813)

Recorded reviewer-pass verdicts in the packet's "Verdict format" schema, compared by
`pnpm exec tsx src/cli/m6-agreement.ts <a.json> <b.json>` (protocol:
`docs/design/m6-simplification-eval.md` §3.5).

The 2026-07-16 pair is a **transcription** of the historical runs 3 and 4 — the two independent
fresh-context passes logged in `m6-simplification-eval.md` §3.3/§3.4 — into the #813 format,
made 2026-07-23; the `.agreement.txt` beside them is the tool's verbatim output over that pair.
They were real independent passes, but the JSON files postdate them. Future pairs should be
emitted by the reviewers themselves at pass time.

An agreement figure here is a rubric-agreement number for one pair of passes — never M6 precision.
