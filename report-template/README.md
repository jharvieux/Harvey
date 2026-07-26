# Audit report renderer

Turns structured findings into a professional, hybrid **PDF** (dashboard cover page +
formal findings body) — driven entirely by data, so every engagement gets an identical
polished artifact.

## Pipeline
`findings.json` (data)  →  `render.mjs` (HTML+CSS+inline-SVG charts)  →  `report.pdf` (+ `report.html`, `page1.png`)

Uses the repo's existing Playwright (`page.pdf()`) — no new dependency.

## Run
```bash
node report-template/render.mjs <findings.json> [outDir]
# example (ATC self-audit):
node report-template/render.mjs report-template/findings.atc.json
```
Outputs land in `out/` (git-ignored): `report.pdf`, `report.html`, `page1.png` (QA screenshot).

## Per engagement
Copy `findings.atc.json` → `findings.<client>.json`, replace `meta` + `findings`. Each finding's
**BFTB** is computed from `value × ease × safety` (1–5 each). The **Action Plan** auto-includes everything
BFTB > 75 plus any Critical/High security finding (excluding already-completed items). Format never changes.

## Schema (per finding)
`id, title, category, severity (Critical|High|Medium|Low|Perf|Info|Watch),
confidence (Confirmed|Likely|Review|N/A), value, ease, safety, taxonomy, location,
evidence, impact, fix, status, note`

- **confidence** drives FP control. `Confirmed` = repro'd; `Likely` = needs one check; `Review` =
  heuristic/candidate; `N/A` = ruled out by the **applicability gate** (irrelevant to this app's auth model /
  architecture). N/A findings are excluded from the severity counts, Top-BFTB, and Action Plan, and rendered in a
  separate **"Checked & ruled out"** section (with `note` explaining why) — so context-blind false positives never
  reach the action plan but are still shown for transparency.
- **reviewFlagOnly / reviewFlagColumns** (#459, M10-specific): a finding whose only PII signal is an
  `OPAQUE_JSON_BLOB` review flag (#377 — a JSON/JSONB container column named like a denormalization
  bucket) sets `reviewFlagOnly: true` and is excluded from the asserted findings list, severity
  counts, Top-BFTB, and Action Plan — it renders instead in a dedicated **"Review for nested PII"**
  section, never as an asserted PII holding. `reviewFlagColumns` lists the flagged column name(s);
  a finding that also has asserted columns keeps `reviewFlagOnly: false` but still lists its
  flagged columns there, so no review-flag content is dropped from the report.

## Document-level sections (beyond `findings[]`)

- **`coverage[]`** (#349) — the derived per-module ledger. Drives the completeness banner, the
  **Module coverage** table, and the **Confidence & limitations** table. Absent ⇒ the report falls
  back to `meta.outOfScope`.
- **`testQuality`** (#1045) — M8's §3b measurement, set by `run-audit --findings-out` from
  `pnpm mutation-scan`'s `--out` artifact. Renders **Test quality & intent (M8)**: the overall
  mutation score with its covered scope (#319 — a scoped score is never printed as a whole-repo
  claim), the documented per-module table (Module/file · Line cov · Mutation score · Surviving
  mutants (critical) · Action), and the surviving-mutant list. A row's `action` is optional — the
  renderer derives one from the row's numbers when the operator has not written it. Absent
  `testQuality` with an M8 coverage row ⇒ the section states that no mutation measurement was
  produced, rather than disappearing.
- **`legalTerms`** (#1048) — `{ text, approvedBy? }`. The **Limitations & liability** section is
  ALWAYS rendered; without `legalTerms.text` it emits the tooling's DRAFT wording under a
  "not reviewed by counsel — do not deliver as-is" banner (plus a cover-page badge). Supply
  counsel-approved text here before a report ships. See `report-template/sections.mjs`.
- **`baseline`** (#457) — the re-audit progress diff, when a `--baseline` was supplied.
