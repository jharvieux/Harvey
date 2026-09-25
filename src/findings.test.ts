import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { bftb, redactDependencyRange, validateFindings } from "./findings.js";
import { checkNonRegistryDependencies } from "./scan/supply-chain.js";

const example = JSON.parse(readFileSync(new URL("../report-template/findings.atc.json", import.meta.url), "utf8"));

describe("validateFindings", () => {
  it("validates complete producer-to-scope assignments and their version bindings", () => {
    const token = JSON.stringify(["scanner", "1"]);
    const auditContext = { engagementId: "test", kind: "client-audit", target: { id: "target", revision: "one" }, producerVersions: { [token]: "1" }, schemaVersion: "1", assessedScope: ["scope"], scopeComplete: true, producerAssignments: { scope: [token] } };
    expect(validateFindings({ ...example, auditContext }).errors).toEqual([]);
    for (const assignments of [{}, { other: [token] }, { scope: [] }, { scope: ["invalid"] }, { scope: [JSON.stringify(["scanner", "2"])] }]) {
      expect(validateFindings({ ...example, auditContext: { ...auditContext, producerAssignments: assignments } }).errors).toContainEqual(expect.stringContaining("producerAssignments"));
    }
  });

  it("requires measured identities and limitations for partial fresh audit context", () => {
    const auditContext = {
      engagementId: "fresh:test", kind: "client-audit", target: { id: "fixture", revision: "content:test" },
      producerVersions: { engine: "measured" }, schemaVersion: "finding-dispositions/1", assessedScope: ["M7 source"], scopeComplete: false,
      limitations: ["Only the M7 source tier was assessed."],
      provenance: {
        schema: 1, kind: "fresh-execution", target: { contentSha256: "a".repeat(64), complete: true, stable: true },
        engine: { contentSha256: "b".repeat(64), complete: true, stable: true }, configurationSha256: "c".repeat(64),
        inputBindings: [], moduleObservations: [{ module: "M7", instance: ".", status: "examined", unitsExamined: 1, scope: "source files" }],
        commandReceiptSha256: [], producerIdentityComplete: false,
      },
    };
    expect(validateFindings({ ...example, auditContext }).errors).toEqual([]);
    for (const context of [
      { ...auditContext, scopeComplete: true }, { ...auditContext, limitations: [] },
      { ...auditContext, provenance: { ...auditContext.provenance, target: { ...auditContext.provenance.target, contentSha256: "HEAD" } } },
      { ...auditContext, provenance: { ...auditContext.provenance, commandReceiptSha256: ["guessed"] } },
      { ...auditContext, provenance: { ...auditContext.provenance, moduleObservations: [{ ...auditContext.provenance.moduleObservations[0], unitsExamined: 0 }] } },
    ]) expect(validateFindings({ ...example, auditContext: context }).errors.some((error) => error.startsWith("auditContext."))).toBe(true);
  });

  it("accepts the shipped example report (the renderer's reference input)", () => {
    const result = validateFindings(example);
    expect(result.errors).toEqual([]);
    expect(result.ok).toBe(true);
  });

  it("rejects non-object documents", () => {
    expect(validateFindings(null).ok).toBe(false);
    expect(validateFindings([]).ok).toBe(false);
  });

  it("reports unknown severities and out-of-range BFTB inputs by path", () => {
    const doc = {
      ...example,
      findings: [{ ...example.findings[0], severity: "Catastrophic", value: 0 }],
    };
    const { ok, errors } = validateFindings(doc);
    expect(ok).toBe(false);
    expect(errors).toContainEqual(expect.stringContaining("findings[0].severity"));
    expect(errors).toContainEqual(expect.stringContaining("findings[0].value"));
  });

  it("rejects duplicate finding ids — ids anchor the report and client follow-ups", () => {
    const doc = { ...example, findings: [example.findings[0], example.findings[0]] };
    const { ok, errors } = validateFindings(doc);
    expect(ok).toBe(false);
    expect(errors).toContainEqual(expect.stringContaining("duplicate id"));
  });
});

describe("validateFindings — mechanical scan fields", () => {
  it("validates complete dependency metadata outcomes and rejects inconsistent receipts", () => {
    const dependencyMetadataEvidence = {
      schemaVersion: 1 as const, population: 1, processed: 1, cacheHits: 0, registryRequests: 0, complete: true,
      outcomes: [{ coordinate: "workspace-pkg", status: "local-manifest" as const, provenance: "packages/pkg/package.json#license/scripts", license: "MIT", hasInstallScript: false, installScriptAssessment: "absent" as const }],
    };
    expect(validateFindings({ ...example, findings: [{ ...example.findings[0], dependencyMetadataEvidence }] }).errors).toEqual([]);
    for (const broken of [
      { ...dependencyMetadataEvidence, schemaVersion: 2 },
      { ...dependencyMetadataEvidence, processed: 0 },
      { ...dependencyMetadataEvidence, population: 2, complete: true },
      { ...dependencyMetadataEvidence, outcomes: [{ ...dependencyMetadataEvidence.outcomes[0], status: "guessed" }] },
      { ...dependencyMetadataEvidence, outcomes: [{ ...dependencyMetadataEvidence.outcomes[0], installScriptAssessment: "maybe" }] },
      { ...dependencyMetadataEvidence, outcomes: [{ ...dependencyMetadataEvidence.outcomes[0], hasInstallScript: true, installScriptAssessment: "absent" }] },
    ]) expect(validateFindings({ ...example, findings: [{ ...example.findings[0], dependencyMetadataEvidence: broken }] }).errors.join("\n")).toContain("dependencyMetadataEvidence");
    const malformed = { ...dependencyMetadataEvidence, complete: false, outcomes: [{ coordinate: "registry-pkg@1.0.0", status: "malformed-metadata" as const, provenance: "https://registry.npmjs.org/registry-pkg/1.0.0", installScriptAssessment: "unsupported" as const, detail: "scripts.install must be a string" }] };
    expect(validateFindings({ ...example, findings: [{ ...example.findings[0], dependencyMetadataEvidence: malformed }] }).errors).toEqual([]);
    expect(validateFindings({ ...example, findings: [{ ...example.findings[0], dependencyMetadataEvidence: { ...malformed, complete: true } }] }).errors.join("\n")).toContain("incompatible with complete receipt");
  });

  it("preserves credential-free ranges and URL provenance while producing idempotent credential projections", () => {
    for (const range of ["1.2.3", " ^1.2.3 ", "~2.0.0", "*", "workspace:*", "npm:@scope/package@^1.0.0", "file:../local-pkg", "github:owner/repo#abcdef", "git+https://example.invalid/repo.git#abcdef", "//example.invalid/repo.tgz",
      "repository https://example.invalid", '"https://example.invalid"', "https://safe.invalid/path/https://example.invalid/repo", "https://safe.invalid/repo#https://example.invalid/repo",
      "https://example.invalid/one and https://other.invalid/two", "gitlab:owner/repo", "bitbucket:owner/repo",
      "npm:package@^1.0.0", "git+github:owner/repo", "GIT+gitlab:owner/repo", "git+git+bitbucket:owner/repo",
    ]) {
      expect(redactDependencyRange(range)).toBe(range);
    }
    for (const range of ["\u0000https://fixture-user:fixture-password@example.invalid/repo\u001f", "ht\ttps://fixture-user:fixture-password@example.invalid/repo", "https://example.invalid/repo#token=fixture-token with spaces"]) {
      const projected = redactDependencyRange(range);
      expect(projected).not.toMatch(/fixture-(?:user|password|token)|with spaces/);
      expect(projected).toContain("[redacted]");
      expect(redactDependencyRange(projected)).toBe(projected);
    }
  });

  it("retains and validates the real range artifact while rejecting count, identity, shape and credential regressions", () => {
    const [finding] = checkNonRegistryDependencies([{ manifest: "package.json", name: "fixture", range: "https://fixture-user:fixture-password@example.invalid/pkg.tgz?token=fixture-token" }]);
    const doc = { ...example, findings: [finding] };
    expect(validateFindings(doc).errors).toEqual([]);
    const json = JSON.stringify(doc);
    for (const secret of ["fixture-user", "fixture-password", "fixture-token"]) expect(json).not.toContain(secret);
    expect(JSON.parse(json).findings[0].dependencyRangeEvidence).toMatchObject({ schemaVersion: 1, examined: 1, matched: 1, edges: [{ range: "https://[redacted]@example.invalid/pkg.tgz?[redacted]", redacted: true }] });
    const brokenArtifacts = [
      { ...finding!.dependencyRangeEvidence, matched: 2 },
      { ...finding!.dependencyRangeEvidence, schemaVersion: 99 },
      { ...finding!.dependencyRangeEvidence, edges: [{ ...finding!.dependencyRangeEvidence!.edges[0], identity: "not-an-identity" }] },
      { ...finding!.dependencyRangeEvidence, edges: [{ ...finding!.dependencyRangeEvidence!.edges[0], range: { not: "a string" } }] },
      { ...finding!.dependencyRangeEvidence, edges: [{ ...finding!.dependencyRangeEvidence!.edges[0], range: "https://fixture-user:fixture-password@example.invalid/pkg.tgz" }] },
      { ...finding!.dependencyRangeEvidence, edges: [{ ...finding!.dependencyRangeEvidence!.edges[0], ownerVersion: "https://fixture-user:fixture-password@example.invalid/pkg.tgz" }] },
      { ...finding!.dependencyRangeEvidence, edges: [{ ...finding!.dependencyRangeEvidence!.edges[0], ownerName: "https://fixture-user:fixture-password@example.invalid/pkg.tgz" }] },
    ];
    for (const dependencyRangeEvidence of brokenArtifacts) {
      const result = validateFindings({ ...example, findings: [{ ...finding, dependencyRangeEvidence }] });
      expect(result.ok).toBe(false);
      expect(result.errors.join("\n")).toContain("dependencyRangeEvidence");
    }
  });

  it("accepts a finding with mechanical + precisionTier set", () => {
    const doc = {
      ...example,
      findings: [{ ...example.findings[0], mechanical: true, precisionTier: "high" }],
    };
    expect(validateFindings(doc).ok).toBe(true);
  });

  it("rejects an unknown precisionTier", () => {
    const doc = {
      ...example,
      findings: [{ ...example.findings[0], precisionTier: "certain" }],
    };
    const { ok, errors } = validateFindings(doc);
    expect(ok).toBe(false);
    expect(errors).toContainEqual(expect.stringContaining("findings[0].precisionTier"));
  });

  it("rejects a non-boolean mechanical flag", () => {
    const doc = {
      ...example,
      findings: [{ ...example.findings[0], mechanical: "yes" }],
    };
    const { ok, errors } = validateFindings(doc);
    expect(ok).toBe(false);
    expect(errors).toContainEqual(expect.stringContaining("findings[0].mechanical"));
  });
});

// #1083: report-template/render.mjs places a finding in the report ONLY if it's asserted
// (confidence !== "N/A" && !reviewFlagOnly), N/A (confidence === "N/A"), or review-flagged
// (reviewFlagColumns.length > 0). A reviewFlagOnly finding with no reviewFlagColumns and a
// non-"N/A" confidence matches none of the three and renders in no section — latent until #1083,
// since the sole current producer (tools/pii-classify.mjs) always sets both together.
describe("validateFindings — reviewFlagOnly requires reviewFlagColumns (#1083)", () => {
  it("rejects reviewFlagOnly: true with no reviewFlagColumns — it would render in no report section", () => {
    const doc = {
      ...example,
      findings: [{ ...example.findings[0], confidence: "Likely", reviewFlagOnly: true }],
    };
    const { ok, errors } = validateFindings(doc);
    expect(ok).toBe(false);
    expect(errors).toContainEqual(expect.stringContaining("findings[0].reviewFlagColumns"));
  });

  it("rejects reviewFlagOnly: true with an empty reviewFlagColumns array", () => {
    const doc = {
      ...example,
      findings: [{ ...example.findings[0], confidence: "Likely", reviewFlagOnly: true, reviewFlagColumns: [] }],
    };
    expect(validateFindings(doc).ok).toBe(false);
  });

  it("accepts reviewFlagOnly: true when reviewFlagColumns is non-empty", () => {
    const doc = {
      ...example,
      findings: [{ ...example.findings[0], confidence: "Likely", reviewFlagOnly: true, reviewFlagColumns: ["metadata"] }],
    };
    expect(validateFindings(doc).ok).toBe(true);
  });

  it("accepts reviewFlagOnly: true with no reviewFlagColumns when confidence is N/A (the na section still shows it)", () => {
    const doc = {
      ...example,
      findings: [{ ...example.findings[0], confidence: "N/A", reviewFlagOnly: true }],
    };
    expect(validateFindings(doc).ok).toBe(true);
  });
});

describe("validateFindings — cwe/owasp (#455)", () => {
  it("accepts a finding with cwe/owasp arrays set", () => {
    const doc = {
      ...example,
      findings: [{ ...example.findings[0], cwe: ["CWE-89"], owasp: ["A03:2021 - Injection"] }],
    };
    expect(validateFindings(doc).ok).toBe(true);
  });

  it("existing findings with no cwe/owasp still validate — the fields are optional", () => {
    const doc = { ...example, findings: [{ ...example.findings[0] }] };
    expect(validateFindings(doc).ok).toBe(true);
  });

  it("rejects a non-array cwe/owasp", () => {
    const doc = {
      ...example,
      findings: [{ ...example.findings[0], cwe: "CWE-89", owasp: 42 }],
    };
    const { ok, errors } = validateFindings(doc);
    expect(ok).toBe(false);
    expect(errors).toContainEqual(expect.stringContaining("findings[0].cwe"));
    expect(errors).toContainEqual(expect.stringContaining("findings[0].owasp"));
  });

  it("rejects a cwe array containing a non-string element", () => {
    const doc = {
      ...example,
      findings: [{ ...example.findings[0], cwe: ["CWE-89", 42] }],
    };
    const { ok, errors } = validateFindings(doc);
    expect(ok).toBe(false);
    expect(errors).toContainEqual(expect.stringContaining("findings[0].cwe"));
  });
});

// #1077: references is optional and validated the same way as cwe/owasp — a semgrep rule's own
// remediation links, populated only from the rule's declared metadata (src/scan/semgrep.ts).
describe("validateFindings — references (#1077)", () => {
  it("accepts a finding with a references array set", () => {
    const doc = { ...example, findings: [{ ...example.findings[0], references: ["https://example.com/advisory"] }] };
    expect(validateFindings(doc).ok).toBe(true);
  });

  it("existing findings with no references still validate — the field is optional", () => {
    expect(validateFindings({ ...example, findings: [{ ...example.findings[0] }] }).ok).toBe(true);
  });

  it("rejects a non-array references, and an array with a non-string element", () => {
    const nonArray = validateFindings({ ...example, findings: [{ ...example.findings[0], references: "https://example.com" }] });
    expect(nonArray.ok).toBe(false);
    expect(nonArray.errors).toContainEqual(expect.stringContaining("findings[0].references"));

    const badElement = validateFindings({ ...example, findings: [{ ...example.findings[0], references: ["https://example.com", 42] }] });
    expect(badElement.ok).toBe(false);
    expect(badElement.errors).toContainEqual(expect.stringContaining("findings[0].references"));
  });
});

describe("validateFindings — coverage ledger (#349)", () => {
  const ledger = [
    { module: "M4", name: "Duplication", status: "ran", detail: "pnpm quality-scan /t" },
    { module: "M2", name: "Local pen-test (dynamic)", status: "requires-live-run", reason: "no local supabase stack" },
    { module: "M7", name: "Performance", status: "partial", reason: "code tier only — no DB creds" },
  ];

  it("accepts a well-formed derived ledger alongside findings", () => {
    expect(validateFindings({ ...example, coverage: ledger }).ok).toBe(true);
  });

  it("still accepts a document with no coverage ledger — back-compat with hand-authored docs", () => {
    expect(validateFindings(example).ok).toBe(true);
    expect(Object.hasOwn(example, "coverage")).toBe(false);
  });

  it("rejects an unknown coverage status", () => {
    const { ok, errors } = validateFindings({ ...example, coverage: [{ module: "M1", name: "x", status: "skipped" }] });
    expect(ok).toBe(false);
    expect(errors).toContainEqual(expect.stringContaining("coverage[0].status"));
  });

  // The whole point of the ledger: a non-"ran" row without a reason is a silent skip wearing a
  // status, which reads in the report as "clean". It must not validate.
  it("rejects a partial / requires-live-run row with no reason", () => {
    const { ok, errors } = validateFindings({ ...example, coverage: [{ module: "M5", name: "Slop", status: "requires-live-run" }] });
    expect(ok).toBe(false);
    expect(errors).toContainEqual(expect.stringContaining("coverage[0].reason"));
  });

  it("does not require a reason on a clean ran row", () => {
    expect(validateFindings({ ...example, coverage: [{ module: "M4", name: "Duplication", status: "ran" }] }).ok).toBe(true);
  });
});

describe("validateFindings — headline must not claim completion over a partial ledger (#509)", () => {
  const partialLedger = [
    { module: "M2", name: "Local pen-test (dynamic)", status: "requires-live-run", reason: "no local supabase stack" },
  ];

  it("rejects a headline claiming the audit is done while the ledger has a gap", () => {
    const doc = {
      ...example,
      meta: { ...example.meta, headline: "The full audit is done and the deliverable is rendered." },
      coverage: partialLedger,
    };
    const { ok, errors } = validateFindings(doc);
    expect(ok).toBe(false);
    expect(errors).toContainEqual(expect.stringContaining("meta.headline"));
  });

  it("accepts an honest partial headline against the same gap", () => {
    const doc = {
      ...example,
      meta: { ...example.meta, headline: "Partial audit — M2 requires a live run." },
      coverage: partialLedger,
    };
    expect(validateFindings(doc).ok).toBe(true);
  });

  it("accepts a completion claim when the ledger is actually complete", () => {
    const doc = {
      ...example,
      meta: { ...example.meta, headline: "The audit is done — all modules assessed." },
      coverage: [{ module: "M2", name: "Local pen-test (dynamic)", status: "ran" }],
    };
    expect(validateFindings(doc).ok).toBe(true);
  });
});

describe("bftb", () => {
  it("matches the renderer's formula: round(value*ease*safety/125*100)", () => {
    expect(bftb({ value: 5, ease: 5, safety: 5 })).toBe(100);
    expect(bftb({ value: 1, ease: 1, safety: 1 })).toBe(1);
    expect(bftb({ value: 4, ease: 3, safety: 5 })).toBe(48);
  });
});
