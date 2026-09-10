import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildHtml } from "../report-template/render.mjs";
import { buildDryRunFamily, publishDryRunFamily, validateDryRunFamily, type DryRunFamily } from "./dry-run-artifacts.js";
import type { Finding } from "./findings.js";
import type { DynamicScorecard } from "./pentest/scorecard.js";

const ROOT = resolve(import.meta.dirname, "..");
const CLI = join(ROOT, "src/cli/validate-findings.ts");
const row = (id: string, evidence = "retained evidence"): Finding => ({
  id, evidence, title: `${id} title`, severity: "High", confidence: "Confirmed", category: "Security",
  taxonomy: "M1-TEST", location: `src/${id}.ts:1`, status: "Open", impact: "tenant data", fix: "check the tenant", value: 3, ease: 3, safety: 3,
});
const source = { target: "targets/calibration", targetTree: "a".repeat(40) };
const family = (rows = [row("RETAINED"), row("PREVIOUS-ONLY")]) => buildDryRunFamily(rows, { profiles: { columns: [{ column: "email" }] } }, source);
const write = (dir: string, name: string, value: unknown) => writeFileSync(join(dir, name), JSON.stringify(value, null, 2));
const read = (dir: string, name: string) => JSON.parse(readFileSync(join(dir, name), "utf8")) as unknown;
const validateCli = (dir: string) => spawnSync(process.execPath, ["--import", "tsx", CLI, join(dir, "findings-report.json")], { cwd: ROOT, encoding: "utf8" });

let sandbox: string;
let out: string;
beforeEach(() => {
  sandbox = mkdtempSync(join(tmpdir(), "harvey-dry-run-family-"));
  out = join(sandbox, "dry-run");
});
afterEach(() => rmSync(sandbox, { recursive: true, force: true }));

describe("dry-run provenance and conservation at the repository/validator/report seam (#1957)", () => {
  it("gates the actual committed family, not only a plausible fixture", () => {
    expect(validateDryRunFamily(join(ROOT, "dry-run"))).toEqual({ ok: true, errors: [] });
  });

  it("accepts one generation through the real validation CLI and renders every retained finding", () => {
    const current = family();
    publishDryRunFamily(out, current, []);
    const result = validateCli(out);
    expect(result.status, result.stderr).toBe(0);
    const report = read(out, "findings-report.json") as DryRunFamily["findings-report.json"];
    const html = buildHtml(report);
    for (const finding of current["findings.json"]) {
      expect(html).toContain(finding.id);
      expect(html).toContain(finding.evidence);
    }
    expect(html).toContain(source.targetTree);
    expect(report.findings).toEqual(current["findings.json"]);
    expect(current["artifact-family.json"].transformations.report).toMatchObject({
      kind: "findings-envelope-v1", produced: 2, delivered: 2, deduped: 0, suppressed: 0, capped: 0, notApplicable: 0, synthesized: 0,
    });
  });

  it("the production CLI rejects a crossed-generation report with actionable difference counts", () => {
    const previous = family();
    publishDryRunFamily(out, family([row("RETAINED", "new evidence"), row("CURRENT-ONLY")]), []);
    write(out, "findings-report.json", previous["findings-report.json"]);
    const result = validateCli(out);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("raw-only=1, derived-only=1, same-ID-changed=1");
    expect(result.stderr).toContain("CURRENT-ONLY");
    expect(result.stderr).toContain("PREVIOUS-ONLY");
    expect(result.stderr).toContain("RETAINED");
    expect(result.stderr).toContain("src/cli/dry-run.ts");
  });

  it("rejects the raw-only falsifier even when the old report still validates as a document", () => {
    publishDryRunFamily(out, family(), []);
    write(out, "findings.json", [row("RETAINED", "another producer"), row("CURRENT-ONLY")]);
    const result = validateCli(out);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("raw-only=1, derived-only=1, same-ID-changed=1");
  });

  it("preserves schema validation for an unrelated engagement with the same report filename", () => {
    mkdirSync(out);
    const report: Partial<DryRunFamily["findings-report.json"]> = family()["findings-report.json"];
    delete report.artifactLinkage;
    report.meta!.auditor = "Engagement reviewer";
    write(out, "findings-report.json", report);
    expect(validateCli(out).status).toBe(0);
    report.meta!.auditor = "Harvey dry-run harness (src/cli/dry-run.ts)";
    write(out, "findings-report.json", report);
    expect(validateCli(out).status).toBe(1);
  });

  it("accepts JSON formatting and key order changes across the intentional report envelope", () => {
    const current = family();
    publishDryRunFamily(out, current, []);
    writeFileSync(join(out, "findings.json"), JSON.stringify(current["findings.json"].map((finding) => Object.fromEntries(Object.entries(finding).reverse()))));
    expect(validateDryRunFamily(out)).toEqual({ ok: true, errors: [] });
  });

  it.each(["pii-data-map.json", "scorecard.json", "artifact-family.json"] as const)("rejects missing or crossed %s", (name) => {
    publishDryRunFamily(out, family(), []);
    const prior = read(out, name);
    write(out, name, {});
    expect(validateDryRunFamily(out).ok).toBe(false);
    write(out, name, prior);
    rmSync(join(out, name));
    expect(validateDryRunFamily(out).ok).toBe(false);
  });

  it("rejects source-link removal, stale report prose, fictitious suppression, and malformed raw rows", () => {
    for (const mutate of [
      (f: DryRunFamily) => { delete (f["findings-report.json"] as Partial<DryRunFamily["findings-report.json"]>).artifactLinkage; },
      (f: DryRunFamily) => { f["findings-report.json"].meta.headline = "Stale generation"; },
      (f: DryRunFamily) => { f["artifact-family.json"].transformations.report.suppressed = 1; },
      (f: DryRunFamily) => { (f["findings.json"] as unknown[])[0] = null; },
    ]) {
      const corrupt = family();
      mutate(corrupt);
      mkdirSync(out, { recursive: true });
      for (const [name, value] of Object.entries(corrupt)) write(out, name, value);
      expect(validateDryRunFamily(out).ok).toBe(false);
    }
  });

  it("counts duplicate occurrences instead of hiding them behind a set of ids", () => {
    publishDryRunFamily(out, family(), []);
    write(out, "findings.json", [row("RETAINED"), row("RETAINED"), row("PREVIOUS-ONLY")]);
    expect(validateDryRunFamily(out).errors.join("\n")).toContain("raw-only=1, derived-only=0, same-ID-changed=0");
  });

  it("retains historical dynamic evidence explicitly and renders its date/target without claiming it ran now", () => {
    const dynamic: DynamicScorecard = {
      target: "http://127.0.0.1:9999", generatedAt: "2026-07-31T00:00:00.000Z", allowDestructive: true,
      probes: [{ findingId: "ANON-PRIVILEGED-RPC", status: "caught", severity: "Critical", evidence: "historical outcome" }],
      summary: { caught: 1, cleared: 0, "not-applicable": 0, "not-run": 0, "not-assessed": 0 },
    };
    const current = buildDryRunFamily([row("RETAINED")], {}, source, dynamic);
    dynamic.probes.length = 0; // The retained input is owned by the generation, not its caller.
    publishDryRunFamily(out, current, []);
    const html = buildHtml(current["findings-report.json"]);
    expect(html).toContain("2026-07-31T00:00:00.000Z");
    expect(html).toContain("http://127.0.0.1:9999");
    expect(html).toContain("this invocation ran no dynamic probes");
    expect(current["artifact-family.json"].retainedDynamic?.document.probes).toHaveLength(1);
    expect(validateDryRunFamily(out).ok).toBe(true);
  });

  it("refuses independent scorecard rebuilding inside the published family", () => {
    publishDryRunFamily(out, family(), []);
    const before = readFileSync(join(out, "scorecard.json"), "utf8");
    const result = spawnSync(process.execPath, ["--import", "tsx", join(ROOT, "src/cli/dry-run-scorecard.ts"), "--out", out], { cwd: ROOT, encoding: "utf8" });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("atomic artifact family");
    expect(readFileSync(join(out, "scorecard.json"), "utf8")).toBe(before);
  });

  it("the compatibility report builder validates rather than silently blessing a crossed family", () => {
    const wrapper = join(sandbox, "repo/dry-run");
    mkdirSync(join(sandbox, "repo/src"), { recursive: true });
    symlinkSync(join(ROOT, "node_modules"), join(sandbox, "repo/node_modules"));
    symlinkSync(join(ROOT, "src/cli"), join(sandbox, "repo/src/cli"));
    publishDryRunFamily(wrapper, family(), []);
    cpSync(join(ROOT, "dry-run/build-report-doc.mjs"), join(wrapper, "build-report-doc.mjs"));
    const run = () => spawnSync(process.execPath, [join(wrapper, "build-report-doc.mjs")], { cwd: join(sandbox, "repo"), encoding: "utf8" });
    expect(run().status).toBe(0);
    write(wrapper, "findings.json", [row("CROSSED")]);
    expect(run().status).toBe(1);
  });
});

describe("atomic dry-run publication", () => {
  it("leaves the previous family byte-for-byte intact on validation failure and preserves historical files", () => {
    publishDryRunFamily(out, family(), []);
    const history = "historical record, not this invocation\n";
    writeFileSync(join(out, "dynamic-scorecard.json"), history);
    writeFileSync(join(out, "quality-findings.json"), "[]\n");
    const before = readFileSync(join(out, "findings.json"), "utf8");
    const broken = family([row("NEXT")]);
    broken["findings-report.json"].findings = [];
    expect(() => publishDryRunFamily(out, broken, [])).toThrow("raw-only=1");
    expect(readFileSync(join(out, "findings.json"), "utf8")).toBe(before);
    expect(validateDryRunFamily(out).ok).toBe(true);
    publishDryRunFamily(out, family([row("NEXT")]), []);
    expect(readFileSync(join(out, "dynamic-scorecard.json"), "utf8")).toBe(history);
    expect(readFileSync(join(out, "quality-findings.json"), "utf8")).toBe("[]\n");
  });

  it.each(["throw", "kill"])("never presents a partial family if activation is interrupted by %s", (mode) => {
    publishDryRunFamily(out, family(), []);
    const current = family([row("NEXT")]);
    const candidate = join(sandbox, "candidate.json");
    writeFileSync(candidate, JSON.stringify(current));
    // Intercept the actual filesystem activation boundary in a real process, with no production
    // failpoint flag. A catchable failure must roll back; SIGKILL must retain a recoverable old dir.
    const script = `
      import fs from 'node:fs';
      import { syncBuiltinESMExports } from 'node:module';
      const rename = fs.renameSync;
      fs.renameSync = (from, to) => {
        if (String(from).endsWith('/staged')) {
          if (${JSON.stringify(mode)} === 'kill') process.kill(process.pid, 'SIGKILL');
          throw new Error('interrupted at activation');
        }
        return rename(from, to);
      };
      syncBuiltinESMExports();
      const { publishDryRunFamily } = await import(${JSON.stringify(join(ROOT, "src/dry-run-artifacts.ts"))});
      publishDryRunFamily(${JSON.stringify(out)}, JSON.parse(fs.readFileSync(${JSON.stringify(candidate)}, 'utf8')), []);
    `;
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script], { cwd: ROOT, encoding: "utf8" });
    const backup = join(sandbox, ".dry-run.generation-lock/previous");
    if (mode === "throw") {
      expect(result.status).toBe(1);
      expect(read(out, "findings.json")).toEqual(family()["findings.json"]);
      expect(validateDryRunFamily(out).ok).toBe(true);
      expect(existsSync(backup)).toBe(false);
    } else {
      expect(result.signal).toBe("SIGKILL");
      expect(existsSync(out)).toBe(false);
      expect(validateDryRunFamily(out).ok).toBe(false);
      const validation = validateCli(out);
      expect(validation.status).toBe(1);
      expect(validation.stderr).toContain(".dry-run.generation-lock");
      expect(validateDryRunFamily(backup).ok).toBe(true);
      expect(read(backup, "findings.json")).toEqual(family()["findings.json"]);
      expect(() => publishDryRunFamily(out, current, [])).toThrow("publication lock");
    }
  });
});
