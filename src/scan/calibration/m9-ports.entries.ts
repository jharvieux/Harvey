// #917/#918 — M9 per-framework port calibration corpus (Remix / React Router 7, TanStack Start).
//
// The boundary-model ports (#916) added new per-framework detection code — the Remix loader-return
// leak and `action` mutation collector, the TanStack `createServerFn` chain — so under this repo's
// doctrine each must be GRADED, not merely shipped: an ungraded port cannot claim recall and would
// recreate the problem #872 fixed. Each entry binds ONE positive + ONE negative per ported check to
// the SAME committed fixtures the port's routing test uses (src/detectors/__fixtures__/{remix,
// tanstack}/<check>/{positive,negative}), path-prefixed to a globally-unique
// `m9-<fw>-corpus/<check>/<kind>` location so the answer key can't drift from what the scanner emits
// and no file lands in the scanned calibration target. The live scoring lives in calibration.test.ts
// ("#917/#918 M9 port corpus"), which loads each fixture, runs detectAppRouterFindings with the
// framework flag, and scores with the SAME scoreEntry as the rest of the corpus.
//
// Ported checks graded here: server→client leak, server-mutation missing authorization (M1),
// server-mutation missing input validation. SSR-misuse and data-waterfall reuse the unchanged
// framework-agnostic detectors (already graded by m9-checks.entries.ts) and their routing is proven
// in app-router.test.ts; every check with no port implementation keeps its not-assessed row (also
// proven there). Every positive is `review` tier — the M9 AST heuristics are never free-count.

import type { CorpusEntry } from "./types.js";

interface PortCheck {
  check: string;
  match: string;
  posNote: string;
  negNote: string;
}

const CHECKS: PortCheck[] = [
  {
    check: "leak",
    match: "Server→client data leak",
    posNote: "leak/positive: a full query-result row is returned from the server boundary (Remix loader / TanStack createServerFn handler) and serialised whole to the client.",
    negNote: "leak/negative: the boundary returns a narrowed projection (row.name), not the whole row — the safe shape, nothing fires.",
  },
  {
    check: "action-authz",
    match: "missing authorization",
    posNote: "action-authz/positive: a mutating server entry point (Remix action / TanStack server function) with no session/authority check in its body — routed to the M1 authorization class.",
    negNote: "action-authz/negative: the same mutation once it authenticates the caller and scopes the write to the session — no missing-auth finding.",
  },
  {
    check: "action-validation",
    match: "missing input validation",
    posNote: "action-validation/positive: a mutating server entry point reads input straight into the DB with no schema validation (no Zod .parse / TanStack .validator()).",
    negNote: "action-validation/negative: the same mutation once its input is validated (Zod .parse / chain-level .validator()) — nothing fires.",
  },
];

function frameworkEntries(fw: "remix" | "tanstack", label: string): CorpusEntry[] {
  const out: CorpusEntry[] = [];
  for (const { check, match, posNote, negNote } of CHECKS) {
    const idFw = fw.toUpperCase();
    out.push({
      id: `M9P-${idFw}-${check.toUpperCase()}-POS`,
      kind: "positive",
      cls: `${label}: ${check}`,
      module: "M9",
      location: `m9-${fw}-corpus/${check}/positive`,
      match: [match],
      expectedTier: "review",
      note: `${label} ${posNote}`,
    });
    out.push({
      id: `M9P-${idFw}-${check.toUpperCase()}-NEG`,
      kind: "negative",
      cls: `${label}: ${check} (clean)`,
      module: "M9",
      location: `m9-${fw}-corpus/${check}/negative`,
      match: [match],
      note: `${label} ${negNote}`,
    });
  }
  return out;
}

export const m9PortEntries: CorpusEntry[] = [...frameworkEntries("remix", "Remix / RR7")];
