import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AUDIT_MODULES } from "./audit-coverage.js";
import { auditContextDigest, beginFreshAuditContext } from "./audit-context.js";
import { diffAgainstBaseline } from "./audit-diff.js";
import { assembleEngagementDocument } from "./audit-report.js";
import type { AuditContext, ReportMeta } from "./findings.js";
import { createProducerExecutionReceipt } from "./producer-execution-receipt.js";

const roots: string[] = [];
afterEach(() => { vi.unstubAllEnvs(); roots.splice(0).forEach((root) => rmSync(root, { recursive: true, force: true })); });
function fixture() {
  const root = mkdtempSync(join(tmpdir(), "harvey-fresh-context-"));
  roots.push(root);
  const target = join(root, "target");
  const engineRoot = join(root, "engine");
  mkdirSync(target); mkdirSync(join(engineRoot, "src"), { recursive: true });
  writeFileSync(join(target, "app.ts"), "export const n = 1;");
  writeFileSync(join(engineRoot, "src", "scanner.ts"), "export const version = 1;");
  return { root, target, engineRoot, configuration: { connected: false } };
}
function complete(capture: ReturnType<typeof beginFreshAuditContext>): AuditContext {
  for (const module of AUDIT_MODULES) capture.observeModule(module, [{ kind: "examined", unitsExamined: 1, scope: "fixture files", detail: "Executed in-process fixture", findings: [] }]);
  return capture.finish([]);
}
const kind = (a: AuditContext, b: AuditContext) => diffAgainstBaseline([], [], { priorContext: a, currentContext: b }).comparison;

describe("fresh audit execution context", () => {
  it("binds non-Git source bytes and distinguishes independent runs from a checkpoint", () => {
    const options = fixture();
    const a = complete(beginFreshAuditContext(options));
    const b = complete(beginFreshAuditContext(options));
    expect(a.engagementId).not.toBe(b.engagementId);
    expect(a.target).toEqual(b.target);
    expect(a.scopeComplete).toBe(true);
    expect(kind(a, b).kind).toBe("same-source");
    expect(kind(a, a).kind).toBe("same-run-checkpoint");
    writeFileSync(join(options.target, "app.ts"), "export const n = 2;");
    const changed = complete(beginFreshAuditContext(options));
    expect(changed.target.revision).not.toBe(a.target.revision);
    expect(kind(a, changed).kind).toBe("source-change");
    writeFileSync(join(options.engineRoot, "src", "scanner.ts"), "export const version = 2;");
    expect(kind(changed, complete(beginFreshAuditContext(options))).kind).toBe("tool-change");
  });

  it("includes dirty and untracked bytes alongside the observed Git revision", () => {
    const options = fixture();
    mkdirSync(join(options.target, ".git"));
    writeFileSync(join(options.target, ".git", "HEAD"), "a".repeat(40));
    const prior = complete(beginFreshAuditContext(options));
    writeFileSync(join(options.target, "untracked.ts"), "export const dirty = true;");
    const current = complete(beginFreshAuditContext(options));
    expect(prior.provenance?.target.gitRevision).toBe("a".repeat(40));
    expect(current.provenance?.target.gitRevision).toBe(prior.provenance?.target.gitRevision);
    expect(current.target.revision).not.toBe(prior.target.revision);
  });

  it("supports internal aliases and explicitly limits dangling, external and cyclic aliases", () => {
    const options = fixture();
    symlinkSync("app.ts", join(options.target, "alias.ts"));
    expect(complete(beginFreshAuditContext(options)).provenance?.target.complete).toBe(true);
    symlinkSync("missing.ts", join(options.target, "dangling.ts"));
    writeFileSync(join(options.root, "outside.ts"), "export const external = 1;");
    symlinkSync("../outside.ts", join(options.target, "external.ts"));
    symlinkSync(".", join(options.target, "cycle"));
    const context = complete(beginFreshAuditContext(options));
    expect(context.provenance?.target.complete).toBe(false);
    expect(context.scopeComplete).toBe(false);
    expect(context.limitations?.join(" ")).toMatch(/alias|could not be read/);
    expect(kind(context, context).kind).toBe("incompatible");
  });

  it("rejects a raced source or engine as a single comparable revision", () => {
    const options = fixture();
    const capture = beginFreshAuditContext(options);
    writeFileSync(join(options.target, "app.ts"), "changed during scan");
    writeFileSync(join(options.engineRoot, "src", "scanner.ts"), "changed during scan");
    const context = complete(capture);
    expect(context.provenance?.target.stable).toBe(false);
    expect(context.provenance?.engine.stable).toBe(false);
    expect(kind(context, context).limitations.join(" ")).toContain("changed during execution");
  });

  it("binds outside schema bytes and keeps historical, missing and changing inputs incomplete", () => {
    const options = fixture();
    const path = join(options.root, "schema.sql");
    writeFileSync(path, "create table a(id int);");
    const prior = complete(beginFreshAuditContext({ ...options, inputs: [{ role: "schema", path }] }));
    writeFileSync(path, "create table a(id text);");
    const current = complete(beginFreshAuditContext({ ...options, inputs: [{ role: "schema", path }] }));
    expect(current.target).toEqual(prior.target);
    expect(kind(prior, current).kind).toBe("scope-change");
    for (const input of [{ role: "historical", path, historical: true }, { role: "missing", path: join(options.root, "missing") }]) {
      const context = complete(beginFreshAuditContext({ ...options, inputs: [input] }));
      expect(context.scopeComplete).toBe(false);
      expect(context.provenance?.inputBindings[0]?.complete).toBe(false);
    }
    const capture = beginFreshAuditContext({ ...options, inputs: [{ role: "schema", path }] });
    writeFileSync(path, "changed during scan");
    expect(complete(capture).scopeComplete).toBe(false);
  });

  it("preserves measured partial populations and avoids accepting launcher versions as scanner identity", () => {
    const options = fixture();
    const capture = beginFreshAuditContext(options);
    capture.observeModule("M7", [{ kind: "examined", unitsExamined: 7, scope: "source files", detail: "static scan", findings: [], reason: "Connected database was not assessed." }]);
    capture.observeCommand("missing-scanner", undefined, { PATH: "" });
    const context = capture.finish([]);
    expect(context.provenance?.moduleObservations[0]).toMatchObject({ module: "M7", unitsExamined: 7 });
    expect(context.provenance?.producerIdentityComplete).toBe(false);
    expect(context.scopeComplete).toBe(false);
    expect(context.limitations?.join(" ")).toContain("nested scanner");
    expect(kind(context, { ...context, engagementId: "later" }).limitations.join(" ")).toContain("Connected database was not assessed");
  });

  it("accepts only the execution owner's context and keeps operator assertions out of assembly", () => {
    const observed = complete(beginFreshAuditContext(fixture()));
    const meta = { auditContext: { ...observed, engagementId: "operator-forgery" } } as ReportMeta;
    const unbound = assembleEngagementDocument([], { connected: false, dynamic: false, llm: false }, [], meta);
    expect(unbound.auditContext).toBeUndefined();
    expect(unbound.meta.auditContext).toBeUndefined();
    const bound = assembleEngagementDocument([], { connected: false, dynamic: false, llm: false }, [], meta, undefined, undefined, undefined, observed);
    expect(bound.auditContext).toEqual(observed);
    expect(bound.meta.auditContext).toEqual(observed);
  });

  it("binds raw scope identities separately from secret-safe display text", () => {
    vi.stubEnv("PUBLIC_URL", "/");
    vi.stubEnv("API_TOKEN", "owned-secret-fixture");
    const capture = beginFreshAuditContext(fixture());
    capture.observeModule("M7", [{ kind: "examined", unitsExamined: 1, scope: "source files", instance: "apps/owned-secret-fixture", detail: "fixture", findings: [] }]);
    const context = capture.finish([]);
    expect(context.provenance?.moduleObservations[0]?.instance).toBe("apps/[REDACTED]");
    expect(context.provenance?.observedScopesSha256).toBe(auditContextDigest([["M7", "apps/owned-secret-fixture"]]));
    expect(JSON.stringify(context)).not.toContain("owned-secret-fixture");
  });

  it("assigns observed implementations without guessing which sibling workspace ran a producer", () => {
    const options = fixture();
    const producer = createProducerExecutionReceipt({ executionId: "observed", producerId: "static:M7", implementationId: "src/static.ts#scan", module: "M7", tier: "free", findingFamilyIds: [], findingIds: [], edges: [{ kind: "semantic-call", from: "scan", to: "M7" }] });
    const single = beginFreshAuditContext(options);
    single.observeModule("M7", [{ kind: "examined", unitsExamined: 1, scope: "source files", findings: [], detail: "fixture" }]);
    const bound = single.finish([producer]);
    const token = JSON.stringify([producer.producerId, producer.implementationId]);
    expect(Object.keys(bound.producerAssignments!)).toEqual(bound.assessedScope);
    expect(bound.producerAssignments![bound.assessedScope[0]!]!).toContain(token);
    const siblings = beginFreshAuditContext(options);
    for (const instance of ["apps/a", "apps/b"]) siblings.observeModule("M7", [{ kind: "examined", unitsExamined: 1, instance, scope: "source files", findings: [], detail: "fixture" }]);
    const uncertain = siblings.finish([producer]);
    expect(Object.keys(uncertain.producerAssignments!).sort()).toEqual(uncertain.assessedScope);
    expect(Object.values(uncertain.producerAssignments!).flat()).not.toContain(token);
    expect(uncertain.provenance?.producerIdentityComplete).toBe(false);
    expect(uncertain.limitations?.join(" ")).toContain("not each workspace");
  });
});
