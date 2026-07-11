import { describe, expect, it } from "vitest";
import { definerReviewFindings, needsAuthzReview } from "./definer-review.js";
import type { DefinerFunction } from "./definer-classifier.js";

// POSITIVE — P-SECDEF-PRIV-WRITE-NOAUTH: privileged write to profiles.role with no caller check.
const promoteToAdmin: DefinerFunction = {
  schema: "public",
  name: "promote_to_admin",
  argNames: ["target_user_id"],
  exposedTo: ["authenticated"],
  body: "UPDATE public.profiles SET role = 'admin' WHERE id = target_user_id;",
};

// NEGATIVE — the guarded variant: raises unless the CALLER is already an admin before the write.
const promoteToAdminChecked: DefinerFunction = {
  schema: "public",
  name: "promote_to_admin_checked",
  argNames: ["target_user_id"],
  exposedTo: ["authenticated"],
  body:
    "IF NOT EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin') THEN " +
    "RAISE EXCEPTION 'not authorized'; END IF; " +
    "UPDATE public.profiles SET role = 'admin' WHERE id = target_user_id;",
};

describe("needsAuthzReview", () => {
  it("flags a privileged write with no caller-auth check", () => {
    expect(needsAuthzReview(promoteToAdmin)).toBe(true);
  });

  it("clears a privileged write gated on the caller's own identity", () => {
    expect(needsAuthzReview(promoteToAdminChecked)).toBe(false);
  });
});

describe("definerReviewFindings", () => {
  it("emits a review-tier finding only for the unauthorized privileged write", () => {
    const findings = definerReviewFindings([promoteToAdmin, promoteToAdminChecked]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.location).toBe("public.promote_to_admin");
    expect(findings[0]?.precisionTier).toBe("review");
    expect(findings[0]?.confidence).toBe("Review");
  });

  it("carries the raw function body into the evidence for offline adjudication", () => {
    const findings = definerReviewFindings([promoteToAdmin]);
    expect(findings[0]?.evidence).toContain("UPDATE public.profiles SET role = 'admin'");
  });
});
