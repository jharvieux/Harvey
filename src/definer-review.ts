// M1 connected [LLM] — deepen SECURITY DEFINER 'ambiguous'/'flag' verdicts with a caller-
// authorization body-read (#200). definer-classifier.ts returns ok/flag/ambiguous from structural
// signals; this pass reads the body of the non-ok verdicts for the specific escalation shape the
// classifier can't adjudicate mechanically: a privileged write/grant with no check on WHO is
// calling before it runs. Canonical miss: promote_to_admin(target_user_id) — SECURITY DEFINER,
// granted to authenticated, updates profiles.role with no caller check (P-SECDEF-PRIV-WRITE-NOAUTH,
// b16-storage-secdef.entries.ts). Reuses the existing detect-deeper definer pull.

import type { Finding } from "./findings.js";
import type { DefinerFunction } from "./definer-classifier.js";
import { reviewFinding } from "./review-tier.js";

const PRIVILEGED_WRITE = /\b(update|insert\s+into|delete\s+from|grant)\b/i;
const CALLER_AUTH = /auth\.(uid|jwt)\s*\(\)/i;

export function needsAuthzReview(fn: DefinerFunction): boolean {
  return PRIVILEGED_WRITE.test(fn.body) && !CALLER_AUTH.test(fn.body);
}

export function definerReviewFindings(fns: DefinerFunction[]): Finding[] {
  return fns
    .filter(needsAuthzReview)
    .map((fn, i) =>
      reviewFinding({
        id: `M1-DEF-AUTHZ-${String(i + 1).padStart(2, "0")}`,
        title: `SECURITY DEFINER ${fn.schema}.${fn.name} — caller-authorization review`,
        severity: "High",
        category: "Multi-tenant security",
        taxonomy: "M1 — Multi-tenant security",
        location: `${fn.schema}.${fn.name}`,
        evidence: `Body performs a privileged write/grant with no auth.uid()/auth.jwt() check on the caller before it runs; granted to ${fn.exposedTo.join(", ")}. Function body: ${fn.body.trim()}`,
        question: "Does the function verify the CALLER is authorized (owns the row, holds the required role, or is in the tenant) before this privileged write or grant?",
        impact: "A SECURITY DEFINER function runs with the owner's privileges — without a caller check, any exposed role can invoke it to escalate (e.g. self-promote to admin) or write outside its own tenant.",
        fix: "Add an explicit caller-authorization guard (verify auth.uid() owns the row or holds the required role) before the privileged write, or REVOKE EXECUTE from anon/authenticated.",
        okWhen: "The body checks the caller's identity/role/tenant before the write, or the write isn't actually privileged.",
        notOkWhen: "Any exposed caller can trigger the privileged write without the function verifying who they are.",
      }),
    );
}
