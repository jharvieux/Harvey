// App-layer SOURCE-DETECTOR recall gate (#945). The free tier's source-detector recall — how many
// application-code vulnerabilities with a genuine untrusted-input → dangerous-sink data flow the
// mechanical tier catches — had no scored number. The SecBench.js gate (#879) measured it at 0/600,
// but that is a CORPUS MISMATCH, not a capability: SecBench's vulnerability lives inside a library
// (the sink is in node_modules) and its exploit is a jest test with no HTTP request source, so
// Harvey's request→sink taint rules have nothing to latch onto (re-verified 2026-07-24, see
// docs/design/secbench-recall-measurement.md). This gate scores the SAME source detectors against an
// APP-LAYER answer key — the request→sink taint fixtures in targets/calibration — where they DO have
// a request source. It reports a number DISTINCT from:
//   - the SecBench/SCA number (0 by construction there — a library-CVE corpus, scored via osv-scanner);
//   - the M1 MIXED-corpus number (validate-calibration.ts, ~198/201) whose answer key blends the
//     source detectors with the SCA/secret/header/crypto/next.config/RLS-config/schema tiers.
// No blended figure may masquerade as the source-detector number — that blend is the exact caveat
// #868 (the free-tier positioning doc) must avoid.
//
// THE ANSWER KEY (SOURCE_TIER_IDS below) — what "source detector" means here, and why each class is in
// or out. IN: a detector that traces an untrusted INPUT VALUE to a dangerous SINK (a taint/data-flow
// detector). OUT: a detector that flags the ABSENCE of a control, or a static config/dependency/
// secret/crypto fact. Concretely:
//   IN  — injection & code-execution (SQLi, command/code injection, PostgREST-filter, prototype
//         pollution, deserialization, XXE, path-traversal, zip-slip, SSTI, ReDoS, log-forging);
//         XSS & client-side sinks (DOM innerHTML/document.write, stored/prop/reflected
//         dangerouslySetInnerHTML, javascript:-URL href/setAttribute, open-URL sink); SSRF; open
//         redirect; and the request→sink ACCESS-CONTROL taint rules (IDOR/BOLA by request id,
//         mass-assignment of the request body, reflected-Origin CORS-with-credentials,
//         client-trusted privilege flag, client-supplied payment amount, Host-header URL poisoning).
//   OUT — absence-of-control heuristics (route-noauth, missing role check, no rate limiter, hardcoded
//         bypass, missing `server-only`, public bucket, unsigned webhook, missing upload limit,
//         unguarded draftMode, middleware-matcher gaps, client-render-only authz); the SCA/dependency
//         tier; secrets-in-files; TLS/security-header hardening; crypto-primitive choice; next.config
//         flags; and the DB-layer RLS/Supabase-config/schema classes. Two adjacent SOURCE-code
//         detectors are deliberately OUT of THIS taint-only answer key because they are not
//         request→sink injection/access-control flows: server-client-leak (excessive data exposure —
//         a DB row spread into a Client Component) and client-side-authz (an authz decision made in
//         the wrong tier). They are NOT unscored, though — #1011 folds both into their own
//         M9_SOURCE_TIER_IDS tier below, reported distinctly rather than blended into this number.
//
// MAINTENANCE: the answer key is an explicit ID list, kept next to this rationale so the in/out call
// on each class is reviewable in one place. When you add a request→sink taint fixture to any
// *.entries.ts, add its id here too. assertSourceTierResolvable() fails loud if a listed id is renamed,
// removed, or acquires a `module` tag (which would drop it out of the mechanical scan) — so drift is a
// gate failure, never a silent smaller denominator.

import { CORPUS, buildCoverageMatrix, mechanicalCorpus, type CorpusEntry } from "./calibration.js";
import type { CoverageMatrix } from "./calibration.js";
import type { Finding } from "../findings.js";

// The documented answer key: every M1-mechanical corpus entry whose detector is a request→sink
// (untrusted-input → dangerous-sink) taint flow. Grouped by family for review; membership, not order,
// is what matters.
export const SOURCE_TIER_IDS: readonly string[] = [
  // Injection & code-execution (semgrep taint rules, injection.yml + base SQLi)
  "P-SQLI-CONCAT", "N-PARAM-QUERY",
  "P-SQLI-RPC", "N-RPC-PARAM",
  "P-CMD-INJECTION", "N-CMD-SAFE",
  "P-EVAL-CODE-INJ", "N-EVAL-JSON",
  "P-POSTGREST-FILTER-INJ",
  "P-PROTO-POLLUTION", "N-PROTO-SAFE",
  "P-INSECURE-DESERIALIZE",
  "P-XXE", "N-XXE-SAFE",
  "P-PATH-TRAVERSAL", "N-PATH-BASENAME",
  "P-ZIP-SLIP",
  "P-SSTI", "P-SSTI-APPROUTER", "N-SSTI-APPROUTER-FIXED",
  "P-REDOS",
  "P-LOG-INJECTION",

  // XSS & client-side sinks (xss.yml + base DSIH)
  "P-XSS-DSIH", "N-DSIH-SANITIZED",
  "P-DOM-XSS-INNERHTML", "N-INNERHTML-STATIC",
  "P-DOM-XSS-DOCWRITE",
  "P-XSS-STORED-DSIH",
  "P-DSIH-PROP", "N-DSIH-PROP-ESCAPED",
  "P-XSS-HREF-JS", "N-HREF-INTERNAL",
  "P-XSS-DANGEROUS-URL",
  "P-XSS-SETATTR",
  "N-SEARCHPARAMS-TEXT",

  // SSRF & open redirect (base)
  "P-SSRF-FETCH", "P-SSRF-APPROUTER", "N-SSRF-APPROUTER-FIXED",
  "P-OPEN-REDIRECT",

  // Access-control taint: IDOR/BOLA, mass-assignment, CORS, client-trust
  "P-IDOR-PARAM", "N-IDOR-SCOPED",
  "P-IDOR-APPROUTER", "N-IDOR-APPROUTER-SCOPED",
  "P-IDOR-AWAIT-PARAMS", "N-IDOR-AWAIT-PARAMS-SCOPED",
  "P-PG-IDOR", "N-PG-IDOR-COMPARED", "N-PG-IDOR-UNAUTH", "N-PG-IDOR-BENIGN-NAME",
  "P-MASS-ASSIGNMENT", "N-MASS-ASSIGN-PICK",
  "P-MASS-ASSIGN-APPROUTER", "N-MASS-ASSIGN-APPROUTER-PICK",
  "P-MASS-ASSIGN-BARE", "N-MASS-ASSIGN-BARE-RECONSTRUCTED",
  "P-PG-MASS-ASSIGN", "N-PG-MASS-ASSIGN-ALLOWLIST", "N-PG-MASS-ASSIGN-BENIGN-NAME",
  "P-CORS-REFLECTED-OBJLIT", "N-CORS-OBJLIT-REFLECTED-SAFE",
  "P-CLIENT-TRUSTED-ROLE", "N-BENIGN-BODY-FIELD",
  "P-CLIENT-PRIV-HEADER", "N-PRIV-FROM-SESSION",
  "P-CLIENT-PAYMENT-AMOUNT", "N-PAYMENT-DB-PRICE",
  "P-BOLA-BODY-OWNER", "N-BOLA-SESSION-OWNER",
  "P-HOST-HEADER-URL", "N-HOST-HEADER-FIXED-ORIGIN",
];

// Fail loud: every listed id must resolve to exactly one entry in the M1 MECHANICAL corpus (the slice
// runMechanicalScan actually scores). A renamed/removed id, or one that gained a `module` tag and thus
// left the mechanical scan, would otherwise silently shrink the denominator — the inflation trap the
// SecBench gate (#879) and the coverage guard both warn about.
export function assertSourceTierResolvable(corpus: CorpusEntry[] = CORPUS): void {
  const byId = new Map<string, CorpusEntry>();
  for (const e of mechanicalCorpus(corpus)) byId.set(e.id, e);
  const missing = SOURCE_TIER_IDS.filter((id) => !byId.has(id));
  if (missing.length) {
    throw new Error(
      `source-recall answer key references ${missing.length} id(s) not in the M1 mechanical corpus: ` +
        `${missing.join(", ")}. An id was renamed, removed, or gained a \`module\` tag (dropping it out ` +
        `of runMechanicalScan). Fix SOURCE_TIER_IDS in src/scan/source-recall.ts — a stale id silently ` +
        `shrinks the source-recall denominator.`,
    );
  }
  const dupes = SOURCE_TIER_IDS.filter((id, i) => SOURCE_TIER_IDS.indexOf(id) !== i);
  if (dupes.length) throw new Error(`source-recall answer key has duplicate id(s): ${[...new Set(dupes)].join(", ")}`);
}

// The app-layer source-detector subset of the mechanical corpus, in the corpus's own entry order.
export function sourceTierCorpus(corpus: CorpusEntry[] = CORPUS): CorpusEntry[] {
  assertSourceTierResolvable(corpus);
  const ids = new Set(SOURCE_TIER_IDS);
  return mechanicalCorpus(corpus).filter((e) => ids.has(e.id));
}

// Scores a mechanical Finding[] against the source-tier answer key. Reuses buildCoverageMatrix so the
// positive-caught / negative-cleared rules are identical to validate-calibration's — this is the SAME
// scoring model over a NARROWER answer key, not a second implementation.
export function scoreSourceRecall(findings: Finding[], corpus: CorpusEntry[] = CORPUS): CoverageMatrix {
  return buildCoverageMatrix(findings, sourceTierCorpus(corpus));
}

// #1011 — the M9 SOURCE-CODE (non-taint) tier: server-client-leak and client-side-authz. Both read
// the app's own code (not a config/dependency/secret fact) so they are genuinely "source detectors",
// but neither is a request→sink TAINT flow — server-client-leak flags an over-broad DATA SHAPE handed
// to a Client Component, client-side-authz flags an authz DECISION made in the wrong tier — so they
// stay out of SOURCE_TIER_IDS's taint-only definition above and get their OWN tier instead, reported
// distinctly (never blended into the 38/39 headline number).
//
// VERIFIED (not assumed, #1011 corrects a stale claim in docs/design/source-detector-recall.md): the
// two detectors do NOT share one scoring pipeline. client-side-authz is a leftover-auth.ts mechanical
// grep — its corpus entries (P-CLIENT-AUTHZ-STORAGE/-USER, N-CLIENT-AUTHZ-SERVER-CHECK in
// b14-applogic.entries.ts) carry NO `module` tag, so they are already inside mechanicalCorpus() and
// already caught by runMechanicalScan(targets/calibration) — the SAME findings scoreSourceRecall's
// caller already has. server-client-leak is the M9 AST pass (detectAppRouterFindings) and IS
// module-tagged M9 in m9-checks.entries.ts, scored only against its own committed
// src/detectors/__fixtures__/server-client-leak/ fixtures, never against targets/calibration — the
// caller must run that pass separately and pass its findings in alongside the mechanical ones.
export const M9_SOURCE_TIER_IDS: readonly string[] = [
  "M9C-LEAK-POS", "M9C-LEAK-NEG", // server-client-leak (M9 AST pass, __fixtures__-scored)
  "P-CLIENT-AUTHZ-STORAGE", "P-CLIENT-AUTHZ-USER", "N-CLIENT-AUTHZ-SERVER-CHECK", // client-side-authz (mechanical)
];

// Fail loud, same discipline as assertSourceTierResolvable — but this tier deliberately spans BOTH a
// module-tagged (M9) and a module-less (mechanical) entry, so it resolves against the WHOLE corpus,
// not mechanicalCorpus().
export function assertM9SourceTierResolvable(corpus: CorpusEntry[] = CORPUS): void {
  const byId = new Map<string, CorpusEntry>();
  for (const e of corpus) byId.set(e.id, e);
  const missing = M9_SOURCE_TIER_IDS.filter((id) => !byId.has(id));
  if (missing.length) {
    throw new Error(
      `M9 source-tier answer key references ${missing.length} id(s) not in the corpus: ${missing.join(", ")}. ` +
        `Fix M9_SOURCE_TIER_IDS in src/scan/source-recall.ts.`,
    );
  }
}

export function m9SourceTierCorpus(corpus: CorpusEntry[] = CORPUS): CorpusEntry[] {
  assertM9SourceTierResolvable(corpus);
  const ids = new Set(M9_SOURCE_TIER_IDS);
  return corpus.filter((e) => ids.has(e.id));
}

// Scores the M9 non-taint source tier. The caller supplies findings from BOTH pipelines (mechanical +
// the M9 AST pass over its own fixtures) — relevantFindings() only matches a finding to the entry
// whose location it carries, so combining the two sets can't cross-contaminate scoring.
export function scoreM9SourceRecall(findings: Finding[], corpus: CorpusEntry[] = CORPUS): CoverageMatrix {
  return buildCoverageMatrix(findings, m9SourceTierCorpus(corpus));
}
