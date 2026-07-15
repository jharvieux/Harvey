// Shared review-tier harness for the connected-tier semantic passes (RLS policy semantics,
// SECURITY DEFINER caller-authorization, M10 PII protection). These passes make a judgment the
// mechanical lints can't: each deterministically CLEARS the provably-safe subjects and packages
// the rest here as a `review`-tier Finding for downstream adjudication (the vuln-scan LLM pass /
// human triage). `question` states exactly what the reviewer must decide; okWhen/notOkWhen are the
// adjudication criteria. The corpus entries for this class live in
// src/scan/calibration/b16-storage-secdef.entries.ts (P-STORAGE-AUTH-NOT-OWNER, P-SECDEF-PRIV-
// WRITE-NOAUTH). Both are now also reached statically — supabase-static.ts feeds these same
// reviewers from parsed migration SQL (#220/#256, #264), so each rule set has two feeds.

import type { Finding, Severity } from "./findings.js";
import { mechanicalFinding } from "./scan/common.js";

interface ReviewRequest {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  taxonomy: string;
  location: string;
  evidence: string;
  // The semantic question the reviewer must answer — what makes this a review request rather
  // than a mechanical finding.
  question: string;
  impact: string;
  fix: string;
  okWhen: string;
  notOkWhen: string;
}

export function reviewFinding(r: ReviewRequest): Finding {
  return {
    ...mechanicalFinding({
      id: r.id,
      title: r.title,
      severity: r.severity,
      category: r.category,
      taxonomy: r.taxonomy,
      location: r.location,
      evidence: `${r.evidence} Review question: ${r.question}`,
      impact: r.impact,
      fix: r.fix,
      precisionTier: "review",
    }),
    okWhen: r.okWhen,
    notOkWhen: r.notOkWhen,
  };
}
