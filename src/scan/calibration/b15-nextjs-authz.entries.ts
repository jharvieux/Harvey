// Batch B15 (#123, issues #131-#136) — Next.js/Supabase authz-shape classes routed to the
// semantic/whole-program tier (roadmap `docs/design/corpus-roadmap-to-100.md` §4a: these six
// classes need request+identity context, matcher-vs-route-inventory reasoning, or control-flow
// reasoning that a grep/AST rule can't do reliably — they are LLM/paid-tier (M-series) detection,
// never promoted into the mechanical count). Every entry here is `review` tier and — unlike B14 —
// NONE has a matching mechanical rule: these fixtures seed the corpus/GROUND-TRUTH answer key so
// the paid-tier LLM pass has planted vulns + benign lookalikes to be measured against; the offline
// mechanical gate is expected to leave every positive uncaught (reviewMisses, non-fatal — see
// src/cli/validate-calibration.ts). The acceptance bar for THIS batch is precision, not recall:
// zero free-count (high-tier) false positives on the negatives from any EXISTING mechanical rule.
// Built incrementally, one issue at a time; see GROUND-TRUTH.md §B15.

import type { CorpusEntry } from "./types.js";

export const b15NextjsAuthzEntries: CorpusEntry[] = [
  // #131 — object/function-level authz gap (BOLA/BFLA)
  { id: "P-BOLA-BODY-OWNER", kind: "positive", cls: "object/function-level authz gap: route trusts body.tenantId for the query (BOLA/BFLA)", location: "pages/api/billing/invoice.js", match: ["bola-body-owner"], expectedTier: "review", note: "#131: pages/api/billing/invoice.js authenticates the caller but scopes the invoices query to req.body.tenantId — a client-supplied value — instead of the tenant id on the verified session. No mechanical rule targets this (needs request+identity reasoning); semantic/paid-tier per roadmap §4a (missing-object-property-level-authz). Expected to stay uncaught in the offline gate (non-fatal reviewMiss)." },
  { id: "N-BOLA-SESSION-OWNER", kind: "negative", cls: "invoice query scoped to the session's tenant id, not a client-supplied field", location: "pages/api/billing/invoice-safe.js", match: ["bola-body-owner"], note: "#131: pages/api/billing/invoice-safe.js scopes the query to session.user.tenantId — req.body.tenantId is never read. No mechanical rule targets this shape, so it's cleared trivially; recorded to complete the corpus pair." },
];
