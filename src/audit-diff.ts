// Engagement baseline diff (#457) — resolved-vs-persistent-vs-new across two audits of the SAME
// client. A repeat client re-audited next quarter gets a fresh findings.json; this classifies each
// finding against a prior engagement's findings.json so the deliverable can lead with "you fixed 6
// of last time's 9, and here are 3 new ones."
//
// ── The finding-identity model (the crux) ────────────────────────────────────────────────────────
// "The same finding" across two audits is NOT the positional `id` (F-01, F-02…) — those are assigned
// per-run in severity/BFTB order and reshuffle every audit, so they carry no cross-audit meaning.
// Identity is instead a STABLE KEY derived from two fields that describe WHAT and WHERE, not HOW the
// run happened to render it:
//
//   identity = normalize(taxonomy || category) :: normalizeLocation(location)
//
//   • taxonomy is the detector/rule class ("auth_rls_initplan", "Missing index", "Dead code") — the
//     closest thing Harvey has to a rule id, and stable across runs. category is the fallback when a
//     hand-authored finding left taxonomy blank.
//   • normalizeLocation tolerates the churn that does NOT change identity: raw line/column numbers
//     (":42", ":42:10", "(line 42)", GitHub "#L42"), case, and whitespace. A finding that simply
//     MOVED because unrelated code shifted above it keeps the same key → classified `persistent`,
//     which is the acceptance-test invariant.
//
// Deliberately NOT in the key: raw line numbers, the title (counts like "124 unindexed FKs" drift
// run-to-run), evidence/snippet whitespace, severity, BFTB — all volatile. Keying on them would
// churn identity on cosmetic edits and inflate the resolved/new counts, defeating the feature.
//
// Trade-off / known limits (documented, not hidden):
//   • Coarse locations ("main DB (multiple tables)", "repo-wide") collapse to one key per taxonomy.
//     Two distinct repo-wide findings of the same taxonomy would collide; acceptable because Harvey
//     emits at most one such rollup per taxonomy per run today.
//   • A file RENAME, or a taxonomy re-label of the same underlying issue, breaks the exact key. Such
//     a finding is NOT silently merged. It surfaces as `new` with a low-confidence-match pointer to
//     the plausible baseline finding (same taxonomy + same location basename), AND the baseline
//     finding still shows as `resolved` — so the pair points at each other for a human to confirm.
//     That is the required fail-loud behaviour: an uncertain match is never quietly treated as the
//     same finding.
//
// ── How a re-audit consumes a baseline ────────────────────────────────────────────────────────────
// `run-audit <t> --findings-out cur.json --baseline prior.json` reads the prior engagement's
// findings.json, runs diffAgainstBaseline over (prior.findings, current.findings), tags every current
// finding with `baselineStatus` (+ `lowConfidenceMatch` where applicable), and attaches a `baseline`
// summary (resolved list + counts) to the deliverable. No --baseline ⇒ nothing added, current
// behaviour unchanged.

import type { BaselineSummary, Finding, FindingsDocument } from "./findings.js";

// Strip the churn that does not change identity: line/column suffixes, "(line N)"/"lines N–M"
// descriptors, GitHub "#L42" anchors, case, and whitespace runs.
export function normalizeLocation(location: string): string {
  return location
    .toLowerCase()
    .replace(/#l\d+(?:-l?\d+)?/g, "") // GitHub blob anchors: #L42, #L42-L48
    .replace(/:\d+(?::\d+)?/g, "") // path:line or path:line:col
    .replace(/\(?\blines?\s+\d+(?:\s*[-–]\s*\d+)?\)?/g, "") // "(line 42)", "lines 10-20"
    .replace(/\s+/g, " ")
    .trim();
}

function normalizeTaxonomy(f: Finding): string {
  const t = (f.taxonomy || f.category || "").toLowerCase().trim();
  return t.replace(/\s+/g, " ");
}

// The cross-audit identity key. Same key ⇒ "the same finding". See the header for the model and its
// trade-offs.
export function findingIdentity(f: Finding): string {
  return `${normalizeTaxonomy(f)}::${normalizeLocation(f.location)}`;
}

// The location "stem" used ONLY for low-confidence matching: taxonomy is equal but the exact key is
// not, and we ask "is this plausibly the same place?" — drop any "(...)" descriptor and reduce a path
// to its basename, so a param rename or a moved file still points a human at the likely prior finding
// without ever auto-merging it.
function locationStem(location: string): string {
  const base = normalizeLocation(location).replace(/\s*\(.*$/, "").trim();
  const firstToken = base.split(/\s+/)[0] ?? base;
  const slug = firstToken.split("/").pop() ?? firstToken;
  return slug;
}

interface BaselineDiff {
  // Current findings, each tagged with baselineStatus ("persistent" | "new") and, where a plausible
  // but unconfirmed prior match exists, lowConfidenceMatch = that baseline finding's id.
  findings: Finding[];
  // Baseline findings absent from the current run, tagged baselineStatus "resolved".
  resolved: Finding[];
  counts: { resolved: number; persistent: number; new: number };
}

export function diffAgainstBaseline(baseline: Finding[], current: Finding[]): BaselineDiff {
  const baselineByKey = new Map<string, Finding[]>();
  for (const b of baseline) {
    const key = findingIdentity(b);
    const bucket = baselineByKey.get(key);
    if (bucket) bucket.push(b);
    else baselineByKey.set(key, [b]);
  }

  const matched = new Set<Finding>();
  const tagged: Finding[] = [];
  let persistent = 0;

  for (const c of current) {
    const key = findingIdentity(c);
    const exact = baselineByKey.get(key)?.find((b) => !matched.has(b));
    if (exact) {
      matched.add(exact);
      tagged.push({ ...c, baselineStatus: "persistent" });
      persistent++;
      continue;
    }
    // No confident (exact-key) match. Look for a plausible-but-uncertain prior: same taxonomy, same
    // location basename. We do NOT consume it — it still surfaces as `resolved` — so the uncertain
    // pair points at each other for a human to reconcile (fail loud, never silently merged).
    const cTaxonomy = normalizeTaxonomy(c);
    const cStem = locationStem(c.location);
    const candidate = baseline.find(
      (b) => !matched.has(b) && normalizeTaxonomy(b) === cTaxonomy && locationStem(b.location) === cStem,
    );
    tagged.push(candidate ? { ...c, baselineStatus: "new", lowConfidenceMatch: candidate.id } : { ...c, baselineStatus: "new" });
  }

  const resolved = baseline.filter((b) => !matched.has(b)).map((b): Finding => ({ ...b, baselineStatus: "resolved" }));

  return {
    findings: tagged,
    resolved,
    counts: { resolved: resolved.length, persistent, new: tagged.length - persistent },
  };
}

// Fold a baseline diff into a summary for the deliverable. priorLabel is a human-facing tag for the
// prior audit (its date/commit) shown in the report header.
function baselineSummary(diff: BaselineDiff, priorLabel?: string): BaselineSummary {
  return {
    ...(priorLabel ? { priorLabel } : {}),
    resolved: diff.resolved,
    counts: diff.counts,
  };
}

// Apply a prior engagement's findings as a baseline to an assembled deliverable: tag every current
// finding with its baselineStatus and attach the summary. run-audit calls this when --baseline is
// given; no baseline ⇒ the document is returned unchanged.
export function applyBaseline(doc: FindingsDocument, baselineFindings: Finding[], priorLabel?: string): FindingsDocument {
  const diff = diffAgainstBaseline(baselineFindings, doc.findings);
  return { ...doc, findings: diff.findings, baseline: baselineSummary(diff, priorLabel) };
}
