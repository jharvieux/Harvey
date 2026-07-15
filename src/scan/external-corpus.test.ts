// Layer 1 for the external-repo corpus (#222): runs in `pnpm verify` with no clone and no
// network. Two jobs:
//   - prove the drift scorer actually fails on movement (the point of the corpus);
//   - pin the M10 classifier against the REAL column names from the swept repos — the module has
//     no static-schema CLI path, so this is where its #233 behavior on real code is gated.
// Layer 2 (clone each pinned commit, re-run detect-static/quality-scan, score against the
// baselines) needs network + binaries; it is the deferred supervisor pass, same shape as the M7
// live-advisor split in m7.entries.ts.

import { describe, expect, it } from "vitest";
import { classifyColumn } from "../../tools/pii-classify.mjs";
import { EXTERNAL_CORPUS, isNotRun, scoreExternalBaseline, type ExternalTarget } from "./external-corpus.js";
import type { Finding, Severity } from "../findings.js";

function finding(taxonomy: string, severity: Severity = "Perf"): Finding {
  return {
    id: "X", title: "", severity, confidence: "Confirmed", category: "", taxonomy,
    location: "app/page.tsx:1", status: "Open", evidence: "", impact: "", fix: "",
    value: 3, ease: 3, safety: 3, mechanical: true,
  };
}

const target = (slug: string): ExternalTarget => {
  const t = EXTERNAL_CORPUS.find((x) => x.slug === slug);
  if (!t) throw new Error(`no corpus target ${slug}`);
  return t;
};

describe("external corpus manifest", () => {
  it("pins every target to a full 40-char commit — a baseline against a moving ref is meaningless", () => {
    for (const t of EXTERNAL_CORPUS) {
      expect(t.commit, t.slug).toMatch(/^[0-9a-f]{40}$/);
    }
  });

  it("records a reason for every module that did not run, never a bare zero", () => {
    // The coverage guard (CLAUDE.md): a module that cannot run is `partial`/`requires-live-run`
    // WITH THE REASON. A not-run module scored 0 would read as "clean" — the exact silent-skip
    // this repo treats as a defect.
    for (const t of EXTERNAL_CORPUS) {
      for (const [module, baseline] of Object.entries(t.modules)) {
        if (isNotRun(baseline)) expect(baseline.reason.length, `${t.slug}/${module}`).toBeGreaterThan(20);
        else expect(baseline.note.length, `${t.slug}/${module}`).toBeGreaterThan(20);
      }
    }
  });

  it("records M5 as unrun wherever the target's deps were not installed", () => {
    // knip without the target's `npm install` yields a knip-FAILED artifact, not a dead-code
    // measurement (#223) — so every target except the one small enough to install must be
    // not-run, never a zero that would read as "no dead code".
    for (const t of EXTERNAL_CORPUS.filter((x) => x.slug !== "multi-tenant-starter")) {
      expect(isNotRun(t.modules.M5!), t.slug).toBe(true);
    }
    expect(isNotRun(target("multi-tenant-starter").modules.M5!)).toBe(false);
  });
});

describe("scoreExternalBaseline", () => {
  it("passes when a scan reproduces the recorded counted total", () => {
    const rows = scoreExternalBaseline(target("multi-tenant-starter"), [
      finding("M9 — Accidental dynamic rendering"),
      finding("M9 — Accidental dynamic rendering"),
      finding("M9 — Data-fetching waterfall"),
    ]);
    expect(rows.find((r) => r.module === "M9")).toMatchObject({ pass: true, actual: 3, drift: 0 });
  });

  it("FAILS on a new over-match — the regression this corpus exists to catch", () => {
    // boxyhq is a Pages Router app: #231 requires the App-Router checks to stay silent. A single
    // M9 finding here is the pre-#231 misfire coming back.
    const rows = scoreExternalBaseline(target("boxyhq"), [finding("M9 — Accidental dynamic rendering")]);
    const m9 = rows.find((r) => r.module === "M9")!;
    expect(m9.pass).toBe(false);
    expect(m9.drift).toBe(1);
    expect(m9.detail).toContain("DRIFT +1");
  });

  it("FAILS when a real detection stops firing", () => {
    const rows = scoreExternalBaseline(target("multi-tenant-starter"), []);
    expect(rows.find((r) => r.module === "M9")).toMatchObject({ pass: false, drift: -3 });
  });

  it("ignores Info findings, so the demoted exhaustive-deps class can't re-enter the count", () => {
    // #230 demoted exhaustive-deps to Info rather than deleting it. If a future change promotes
    // it back to a graded severity, proposit's M7 jumps 49 -> 79 and this scorer must catch it.
    const rows = scoreExternalBaseline(target("mvp-boilerplate"), [
      finding("M7 — Unbounded select"),
      finding("M7 — Index used as list key"),
      finding("M7 — State sprawl"),
      finding("M7 — Missing hook dependencies", "Info"),
    ]);
    expect(rows.find((r) => r.module === "M7")).toMatchObject({ pass: true, actual: 3 });
  });

  it("skips not-run modules instead of scoring them 0 against a baseline", () => {
    expect(scoreExternalBaseline(target("proposit"), []).map((r) => r.module)).not.toContain("M5");
  });

  it("scores M5 on the one target whose deps were installed", () => {
    // The dead tenant-authz guard (#226's security cross-link on real code). If this detection
    // stops firing, a quality module lost a finding that corroborates a Critical.
    const rows = scoreExternalBaseline(target("multi-tenant-starter"), [finding("M5 — Slop / dead code", "Low")]);
    expect(rows.find((r) => r.module === "M5")).toMatchObject({ pass: true, actual: 1 });
  });
});

// M10's answer key on REAL swept columns. The sweep's #233 triage found the module both over- and
// under-matching; these lock in each verdict against the columns that produced it.
describe("M10 classifier on real external-corpus columns (#233)", () => {
  it("flags proposit's plaintext per-tenant secrets — the must-not-miss headline finding", () => {
    // organisations.ai_api_key / smtp_pass are stored plaintext and readable by ANY org member
    // via normal RLS `SELECT *`. Per #233 this must outrank the contact PII in the report.
    expect(classifyColumn("ai_api_key", "text", "organisations")).toMatchObject({ category: "SECRET", confidence: "high" });
    expect(classifyColumn("smtp_pass", "text", "organisations")).toMatchObject({ category: "SECRET", confidence: "high" });
  });

  it("catches boxyhq's opaquely-named encrypted secret store", () => {
    // jackson_store.value holds BoxyHQ SAML/SSO config including IdP secrets — a name-only
    // matcher skips a column called `value`, which is exactly what #233 fixed.
    expect(classifyColumn("value", "text", "jackson_store")).toMatchObject({ category: "SECRET" });
  });

  it("does not call an org's own name personal PII (the #233 over-match)", () => {
    expect(classifyColumn("name", "text", "organisations")).toBeNull();
  });

  it("does not call a capability token a stored credential (the #233 over-match)", () => {
    // Invite / share-link / reset tokens are capabilities, not secrets at rest.
    expect(classifyColumn("token", "text", "organisation_invitations")).toBeNull();
  });

  it("still classifies genuine contact PII on the same repos", () => {
    expect(classifyColumn("email", "text", "profiles")).toMatchObject({ infotype: "EMAIL", category: "PII" });
  });
});
