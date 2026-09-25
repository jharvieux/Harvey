import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { assessmentFor, contentIdentity, populationSummary, prepareFindings } from "../report-template/dispositions.mjs";
import { buildHtml } from "../report-template/render.mjs";
import { applyBaseline, diffAgainstBaseline } from "./audit-diff.js";
import { assembleEngagementDocument } from "./audit-report.js";
import { baselineLedger, conservationLedger } from "./conservation-ledger.js";
import { type AuditContext, type Finding, type FindingsDocument, type ReportMeta, type TestQuality, validateFindings } from "./findings.js";
import { renderFidelityBreaches } from "./render-fidelity.js";

const fixture = JSON.parse(readFileSync(new URL("./__fixtures__/dispositions/scenarios.json", import.meta.url), "utf8")) as {
  meta: ReportMeta; templates: Record<string, Finding>; scenarios: Record<string, { template: string; count: number }[]>; testQuality: TestQuality;
};
function scenario(name: string): FindingsDocument {
  const findings = fixture.scenarios[name]!.flatMap((group) => Array.from({ length: group.count }, (_, index): Finding => ({
    ...fixture.templates[group.template]!, id: `${name}-${group.template}-${index}`, location: `src/${group.template}/${index}.ts`,
  })));
  return { meta: { ...fixture.meta, client: `${name} synthetic disposition acceptance` }, findings, testQuality: fixture.testQuality };
}
const context = (over: Partial<AuditContext> = {}): AuditContext => ({ engagementId: "current", kind: "client-audit", target: { id: "fixture", revision: "current" }, producerVersions: { scanner: "1" }, schemaVersion: "1", assessedScope: ["source", "schema"], scopeComplete: true, ...over });
const comparison = { priorContext: context({ engagementId: "prior", target: { id: "fixture", revision: "prior" } }), currentContext: context() };

describe("reviewed report populations #2127", () => {
  it.each(["Confirmed", "Likely", "Review"] as const)("does not promote scanner confidence %s to independent confirmation", (confidence) => {
    expect(assessmentFor({ ...fixture.templates.candidate!, confidence }).disposition).toBe("pending-review");
  });
  it("requires an attributable current source/runtime review for confirmation", () => {
    const good = scenario("AoP");
    expect(validateFindings(good).ok).toBe(true);
    const finding = good.findings[0]!;
    for (const bad of [ { ...finding.assessment!, review: undefined }, { ...finding.assessment!, evidenceKind: "scanner" }, { ...finding.assessment!, sourceScope: "historical" }, { ...finding.assessment!, reviewStatus: "unreviewed" } ]) {
      const doc = { ...good, findings: [{ ...finding, assessment: bad }] };
      expect(validateFindings(doc).ok).toBe(false);
      expect(() => buildHtml(doc as FindingsDocument)).toThrow(/Invalid assessment/);
    }
  });
  it("keeps concrete M10 exposure candidates in review rather than turning them into sensitivity inventory", () => {
    expect(assessmentFor({ ...fixture.templates.inventory!, category: "Data protection", taxonomy: "M10 — PII/PHI/PCI protection" }).disposition).toBe("pending-review");
  });
  it.each([["ATC", 8, 1312, 90, 83, 1502], ["AoP", 1, 708, 1, 0, 719]] as const)("delivers %s confirmed, pending, inventory and historical populations independently", (name, confirmed, pending, inventory, superseded, total) => {
    const input = scenario(name);
    const doc = assembleEngagementDocument([], { connected: false, dynamic: false, llm: false }, input.findings, input.meta, [], {}, input.testQuality);
    const summary = populationSummary(doc.findings);
    expect(summary.total).toBe(total);
    expect(summary.counts).toEqual({ confirmed, actionable: 6, "pending-review": pending, inventory, superseded, "false-positive": 3, "not-applicable": 0 });
    expect(doc.testQuality).toEqual(input.testQuality);
    expect(doc.testQuality?.mutationScore).toBe(39.7);
    expect(doc.testQuality?.mutationScoreBasedOnCoveredCode).toBe(58.6);
    const html = buildHtml(doc);
    expect(html).toContain(`data-disposition="confirmed" data-count="${confirmed}"`);
    expect(html).toContain(`data-chart-total="${confirmed + 6}"`);
    const actions = /<table class="action">[\s\S]*?<\/table>/.exec(html)![0];
    expect([...actions.matchAll(/data-finding-link=/g)]).toHaveLength(confirmed + 6);
    for (const type of ["candidate", "dependency", "inventory", "historical", "false-positive"]) expect(actions).not.toContain(`${name}-${type}-`);
    for (let module = 4; module <= 9; module++) expect(actions).toContain(`${name}-M${module}-0`);
    const ledger = conservationLedger(input.findings, doc.findings);
    expect(ledger.ok).toBe(true);
    expect(ledger.deliveredFromProduced).toBe(total);
    expect(renderFidelityBreaches(doc, html)).toEqual([]);
    expect(validateFindings(doc).ok).toBe(true);
  });
  it("fails conservation on count-preserving substitutions, ambiguous drop IDs and duplicated replacement bodies", () => {
    const a = { ...fixture.templates.candidate!, id: "collision", evidence: "A" };
    const b = { ...a, evidence: "B" };
    expect(conservationLedger([a, b], [a, a]).ok).toBe(false);
    expect(conservationLedger([a, b], [a], {}, [{ id: "collision", disposition: "suppressed", reason: "Reviewed false positive", by: "review" }]).ok).toBe(false);
    const good = conservationLedger([a, b], [a], {}, [{ id: "collision", contentKey: contentIdentity(b), disposition: "suppressed", reason: "Reviewed false positive B", by: "review" }]);
    expect(good.ok).toBe(true);
    expect(good.suppressed).toBe(1);
    expect(baselineLedger([a, b], [a, a]).ok).toBe(false);
  });
  it("keeps every occurrence under colliding/rekeyed/reordered producer IDs", () => {
    const a = { ...fixture.templates.candidate!, id: "collision", evidence: "A" };
    const b = { ...a, evidence: "B" };
    const prepared = prepareFindings([a, b, { ...a, id: "other" }]);
    const reverse = prepareFindings([{ ...a, id: "rekey-1" }, { ...b, id: "rekey-2" }, { ...a, id: "rekey-3" }].reverse());
    expect(prepared.map((f) => f.origin?.occurrenceKey).sort()).toEqual(reverse.map((f) => f.origin?.occurrenceKey).sort());
    expect(new Set(prepared.map((f) => f.id)).size).toBe(3);
    expect(conservationLedger([a, b, { ...a, id: "other" }], reverse).ok).toBe(true);
    const bad = { ...scenario("AoP"), findings: [{ ...prepared[0]!, evidence: "substitution", origin: prepared[0]!.origin }] };
    expect(validateFindings(bad).ok).toBe(false);
  });
  it("detects chart and action population leaks independently of total finding conservation", () => {
    const doc = scenario("AoP"); const html = buildHtml(doc);
    expect(renderFidelityBreaches(doc, html.replace('data-chart-total="7"', 'data-chart-total="719"')).some((b) => b.kind === "population-misclassified")).toBe(true);
    const leaked = html.replace(/(<table class="action">)/, '$1<tr><td><a data-finding-link="AoP-inventory-0">Remediate inventory</a></td></tr>');
    expect(renderFidelityBreaches(doc, leaked).some((b) => b.kind === "population-misclassified")).toBe(true);
  });
  it("renders every raw duplicate disposition and rejects missing or fabricated ledger reasons", () => {
    const input = scenario("AoP");
    const doc = assembleEngagementDocument([], { connected: false, dynamic: false, llm: false }, [...input.findings, input.findings[1]!, input.findings[1]!], input.meta, [], {});
    expect(doc.conservation).toMatchObject({ produced: 721, delivered: 719, deduped: 2, ok: true });
    const html = buildHtml(doc);
    expect(html).toContain("Produced 721 = delivered 719 + deduplicated 2");
    expect(html).toContain("2 byte-identical duplicate capture(s) collapsed");
    expect(renderFidelityBreaches(doc, html.replace(/<section class="conservation">[\s\S]*?<\/section>/, "")).some((b) => b.id === "raw-occurrences")).toBe(true);
    const invalid = { ...doc, conservation: { ...doc.conservation!, rows: [] } };
    expect(validateFindings(invalid).ok).toBe(false);
    expect(() => buildHtml(invalid)).toThrow(/non-delivery reasons/);
  });
  it("keeps occurrence attribution stable for different reviews and avoids natural/generated ID collisions", () => {
    const a = { ...fixture.templates.candidate!, id: "same" };
    const reviewed = { ...a, assessment: fixture.templates.confirmed!.assessment };
    const identityByDisposition = (rows: Finding[]) => prepareFindings(rows).map((f) => [f.assessment.disposition, f.origin?.occurrenceKey]).sort();
    expect(identityByDisposition([a, reviewed])).toEqual(identityByDisposition([reviewed, a]));
    const candidateId = prepareFindings([a, a])[0]!.id;
    const collision = prepareFindings([a, a, { ...a, id: candidateId }]);
    expect(new Set(collision.map((f) => f.id)).size).toBe(3);
    expect(conservationLedger([a, { ...a, id: candidateId }], prepareFindings([a, { ...a, id: candidateId }])).ok).toBe(true);
  });
});

describe("provenance-bound re-audit comparisons #2136", () => {
  it("keeps AoP 55→719 producer/scope expansion separate from regressions and resolutions", () => {
    const current = { ...scenario("AoP"), auditContext: context() };
    const prior = { ...current, findings: current.findings.slice(1, 56).map((f, i) => ({ ...f, id: `old-${i}`, taxonomy: `Legacy scanner: ${f.taxonomy}`, location: `legacy-layout/${i}.ts` })), auditContext: context({ engagementId: "old-audit", schemaVersion: "legacy", producerVersions: { scanner: "legacy" }, assessedScope: ["source"] }) };
    const doc = applyBaseline(current, prior);
    expect(doc.baseline?.comparison?.kind).toBe("tool-change");
    expect(doc.baseline?.counts).toEqual({ new: 0, resolved: 0, persistent: 0 });
    expect(doc.baseline?.comparison?.denominators).toMatchObject({ prior: 55, current: 719, matched: 0, comparableCurrent: 0, comparablePrior: 0, unresolvedCurrent: 719, unresolvedPrior: 55 });
    expect(baselineLedger(current.findings, doc.findings).ok).toBe(true);
    const html = buildHtml(doc);
    expect(html).toContain("Prior population 55; current population 719; matched evidence 0");
    expect(html).toContain("Producer, rule or schema versions changed");
  });
  it("labels ATC partial captures in the same engagement as checkpoints", () => {
    const current = { ...scenario("ATC"), auditContext: context({ engagementId: "ATC-one-engagement" }) };
    const prior = { ...current, findings: current.findings.slice(0, 8), auditContext: { ...current.auditContext, kind: "same-run-checkpoint" as const, scopeComplete: false } };
    const doc = applyBaseline(current, prior);
    expect(doc.baseline?.comparison?.kind).toBe("same-run-checkpoint");
    expect(doc.baseline?.counts).toMatchObject({ new: 0, resolved: 0 });
    expect(new Set(doc.findings.map((f) => f.baselineStatus))).toEqual(new Set(["checkpoint"]));
    expect(buildHtml(doc)).toContain("not a prior client audit");
  });
  it.each(["missing", "same-source", "scope-change", "target-change", "tool-change", "schema-change"])("does not attribute unmatched observations to source changes with %s context", (mode) => {
    const prior = [fixture.templates.confirmed!];
    const current = [{ ...fixture.templates.confirmed!, taxonomy: "Different rule", location: "src/new.ts" }];
    const options = mode === "missing" ? {} : { ...comparison, currentContext: mode === "same-source" ? { ...comparison.currentContext, target: comparison.priorContext.target } : mode === "scope-change" ? { ...comparison.currentContext, assessedScope: ["new-scope"] } : mode === "tool-change" ? { ...comparison.currentContext, producerVersions: { scanner: "changed" } } : mode === "schema-change" ? { ...comparison.currentContext, schemaVersion: "changed" } : { ...comparison.currentContext, target: { id: "other", revision: "current" } } };
    const diff = diffAgainstBaseline(prior, current, options);
    expect(diff.counts).toEqual({ new: 0, resolved: 0, persistent: 0 });
    expect(diff.unresolved).toHaveLength(1);
  });
  it("accepts explicit one-to-one reviewed identity migrations while rejecting ambiguous mappings", () => {
    const prior = [{ ...fixture.templates.confirmed!, location: "src/prior.ts" }];
    const current = [{ ...fixture.templates.confirmed!, id: "rekeyed", location: "src/renamed.ts", evidence: "Reworded reviewed evidence" }];
    const migration = { priorContentKey: contentIdentity(prior[0]!), currentContentKey: contentIdentity(current[0]!), reason: "Reviewed source rename", reviewedBy: "independent reviewer" };
    expect(diffAgainstBaseline(prior, current, comparison).counts).toEqual({ new: 0, resolved: 0, persistent: 0 });
    expect(diffAgainstBaseline(prior, current, { ...comparison, migrations: [migration] }).counts).toEqual({ new: 0, resolved: 0, persistent: 1 });
    const ambiguous = diffAgainstBaseline([prior[0]!, { ...prior[0]!, id: "duplicate" }], current, { ...comparison, migrations: [migration] });
    expect(ambiguous.counts).toEqual({ new: 0, resolved: 0, persistent: 0 });
    expect(ambiguous.unresolved).toHaveLength(2);
  });
  it("reserves explicitly reviewed migrations before automatic matches consume their prior occurrence", () => {
    const original = { ...fixture.templates.confirmed!, location: "src/old.ts" };
    const migrated = { ...original, id: "mapped", taxonomy: "Renamed rule", evidence: "Reviewed new wording" };
    const migration = { priorContentKey: contentIdentity(original), currentContentKey: contentIdentity(migrated), reason: "Reviewed rename", reviewedBy: "reviewer" };
    const result = diffAgainstBaseline([original], [{ ...original, id: "unmapped-duplicate" }, migrated], { ...comparison, migrations: [migration] });
    expect(result.findings[0]?.baselineStatus).toBe("unresolved");
    expect(result.findings[1]?.baselineStatus).toBe("persistent");
    expect(result.counts).toEqual({ new: 0, resolved: 0, persistent: 1 });
  });
  it("does not merge unrelated observations at one coarse location, and preserves duplicate multiplicity", () => {
    const prior = [{ ...fixture.templates.confirmed!, location: "repo-wide" }];
    const current = [{ ...prior[0]!, id: "another" }];
    expect(diffAgainstBaseline(prior, current, comparison).counts).toEqual({ new: 0, resolved: 0, persistent: 0 });
    const exact = scenario("AoP").findings[0]!;
    const duplicates = diffAgainstBaseline([exact, { ...exact, id: "twin" }], [{ ...exact, id: "rekey" }], comparison);
    expect(duplicates.counts.persistent).toBe(1);
    expect(duplicates.resolved).toHaveLength(0);
    expect(duplicates.unresolved).toHaveLength(1);
  });
  it("leaves even identical evidence unresolved when the target binding is unknown", () => {
    const exact = scenario("AoP").findings[0]!;
    const diff = diffAgainstBaseline([exact], [{ ...exact, id: "rekeyed" }]);
    expect(diff.counts).toEqual({ new: 0, resolved: 0, persistent: 0 });
    expect(diff.unresolved).toHaveLength(1);
    expect(diff.findings[0]?.baselineStatus).toBe("incompatible");
  });
  it("allows real changes only for reviewed/current health observations under complete comparable provenance", () => {
    const prior = [{ ...fixture.templates.confirmed!, taxonomy: "Old rule" }];
    const current = [{ ...fixture.templates.confirmed!, taxonomy: "New rule" }];
    expect(diffAgainstBaseline(prior, current, comparison).counts).toEqual({ new: 1, resolved: 1, persistent: 0 });
    expect(diffAgainstBaseline(prior, [{ ...current[0]!, assessment: undefined }], comparison).counts.new).toBe(0);
  });
});
