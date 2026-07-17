import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { findFreshPass, ranFromPass } from "./audit-pass-artifact.js";
import type { RunContext } from "./audit-runner.js";
import { assessStandUpAbility, readRepoLayout, type RepoLayout, runDynamicValidation, type StandUpRunner } from "./dynamic-validate.js";
import type { Finding } from "./findings.js";

const layout = (over: Partial<RepoLayout> = {}): RepoLayout => ({
  hasSupabaseMigrations: true,
  scripts: { dev: "next dev", build: "next build" },
  externalSeamDeps: [],
  ...over,
});

describe("assessStandUpAbility (#450 — can we stand this up, and how fully?)", () => {
  it("is a hard no-go with no migrations — there is no RLS surface to probe", () => {
    const v = assessStandUpAbility(layout({ hasSupabaseMigrations: false }));
    expect(v.canStandUp).toBe(false);
    expect(v.coverage).toBe("none");
    expect(v.reason).toMatch(/no supabase\/migrations/);
  });

  it("is full coverage with migrations + a runnable app", () => {
    const v = assessStandUpAbility(layout());
    expect(v.canStandUp).toBe(true);
    expect(v.coverage).toBe("full");
    expect(v.limitations).toEqual([]);
  });

  it("degrades to postgrest-only when the app can't be run — and SAYS so, never silently", () => {
    const v = assessStandUpAbility(layout({ scripts: {} }));
    expect(v.canStandUp).toBe(true);
    expect(v.coverage).toBe("postgrest-only");
    expect(v.limitations.join(" ")).toMatch(/no dev\/build\/start script/);
  });

  it("discloses an external backend it can't stand up as a limitation, not a silent gap", () => {
    const v = assessStandUpAbility(layout({ externalSeamDeps: ["@pinecone-database/pinecone"] }));
    expect(v.canStandUp).toBe(true);
    expect(v.limitations.join(" ")).toMatch(/external backend/);
  });
});

// #450 acceptance: the go/no-go decision is exercised against real fixture repo LAYOUTS on disk —
// readRepoLayout reads the facts (migrations, scripts, deps incl. the external-seam regex) that
// assessStandUpAbility then judges. The in-memory tests above cover the decision; these cover the
// disk-reading half so the whole path (fixture → verdict) is proven, not just its second stage.
describe("readRepoLayout → assessStandUpAbility over fixture repo directories (#450)", () => {
  const root = mkdtempSync(join(tmpdir(), "harvey-dynval-fixtures-"));
  afterAll(() => rmSync(root, { recursive: true, force: true }));

  const fixture = (name: string, files: { migrations?: string[]; pkg?: object }): string => {
    const dir = join(root, name);
    mkdirSync(dir, { recursive: true });
    if (files.migrations) {
      const mig = join(dir, "supabase", "migrations");
      mkdirSync(mig, { recursive: true });
      for (const f of files.migrations) writeFileSync(join(mig, f), "-- sql\n");
    }
    if (files.pkg) writeFileSync(join(dir, "package.json"), JSON.stringify(files.pkg));
    return dir;
  };

  it("stand-up-able fixture (migrations + build script) reads as a full GO", () => {
    const dir = fixture("standupable", { migrations: ["0001_init.sql"], pkg: { scripts: { build: "next build" } } });
    const v = assessStandUpAbility(readRepoLayout(dir));
    expect(v.canStandUp).toBe(true);
    expect(v.coverage).toBe("full");
  });

  it("missing-migrations fixture is a hard NO-GO — nothing to probe", () => {
    const dir = fixture("no-migrations", { pkg: { scripts: { build: "next build" } } });
    const v = assessStandUpAbility(readRepoLayout(dir));
    expect(v.canStandUp).toBe(false);
    expect(v.coverage).toBe("none");
  });

  it("external-dep-blocked fixture stands up but discloses the seam it can't fake", () => {
    const dir = fixture("external-dep", {
      migrations: ["0001_init.sql"],
      pkg: { scripts: { build: "next build" }, dependencies: { "@pinecone-database/pinecone": "^1.0.0" } },
    });
    const layout = readRepoLayout(dir);
    expect(layout.externalSeamDeps).toContain("@pinecone-database/pinecone");
    expect(assessStandUpAbility(layout).limitations.join(" ")).toMatch(/external backend/);
  });
});

const FINDING = { id: "M2-IDOR-1", title: "cross-tenant read", category: "security", taxonomy: "M2 — Tenant isolation", location: "orders/[id]", status: "open", evidence: "e", impact: "i", fix: "f" } as unknown as Finding;

// A fake runner: each step's success is configurable, so the orchestration's decisions are tested
// without Docker/supabase.
const runner = (over: Partial<StandUpRunner> = {}): StandUpRunner => ({
  standUpDb: () => ({ ok: true, output: "" }),
  runApp: () => ({ ok: true, output: "" }),
  pentest: () => ({ ok: true, findings: [FINDING], output: "" }),
  ...over,
});

describe("runDynamicValidation (#450 orchestration + #448 emit)", () => {
  const dir = mkdtempSync(join(tmpdir(), "harvey-dynval-"));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));
  const now = () => "2026-07-17T12:00:00.000Z";

  it("stands up, pen-tests, and writes an M2.pass.json carrying the findings", () => {
    const r = runDynamicValidation({ targetDir: "/repo", layout: layout(), artifactsDir: dir, now, runner: runner() });
    expect(r.standUp).toBe(true);
    expect(r.coverage).toBe("full");
    expect(r.artifactPath).toBe(join(dir, "M2.pass.json"));
    const written = JSON.parse(readFileSync(r.artifactPath as string, "utf8"));
    expect(written.module).toBe("M2");
    expect(written.target).toBe("/repo");
    expect(written.findings).toHaveLength(1);
  });

  it("a no-go target writes NO artifact and says why — never a silent clean ran", () => {
    const r = runDynamicValidation({ targetDir: "/repo", layout: layout({ hasSupabaseMigrations: false }), artifactsDir: dir, now, runner: runner() });
    expect(r.standUp).toBe(false);
    expect(r.artifactPath).toBeNull();
    expect(r.reason).toMatch(/could not stand up.*no supabase\/migrations/);
  });

  it("a failed stand-up writes no artifact and reports the failure", () => {
    const r = runDynamicValidation({ targetDir: "/repo", layout: layout(), artifactsDir: dir, now, runner: runner({ standUpDb: () => ({ ok: false, output: "supabase start: port in use" }) }) });
    expect(r.standUp).toBe(false);
    expect(r.artifactPath).toBeNull();
    expect(r.reason).toMatch(/stand-up failed.*port in use/);
  });

  it("degrades to postgrest-only when the app won't run, discloses it, and still emits", () => {
    const r = runDynamicValidation({ targetDir: "/repo", layout: layout(), artifactsDir: dir, now, runner: runner({ runApp: () => ({ ok: false, output: "build error" }) }) });
    expect(r.standUp).toBe(true);
    expect(r.coverage).toBe("postgrest-only");
    expect(r.limitations.join(" ")).toMatch(/app failed to run/);
    expect(r.artifactPath).not.toBeNull();
  });

  it("a failed pen-test writes no artifact — no evidence, no ran", () => {
    const r = runDynamicValidation({ targetDir: "/repo", layout: layout(), artifactsDir: dir, now, runner: runner({ pentest: () => ({ ok: false, findings: [], output: "probe crashed" }) }) });
    expect(r.standUp).toBe(false);
    expect(r.artifactPath).toBeNull();
    expect(r.reason).toMatch(/pen-test failed/);
  });

  // #450 acceptance: the emitted M2.pass.json must round-trip through findFreshPass → ran, exactly as
  // run-audit --artifacts-dir consumes it (#416/#448). This proves the harness's output is the
  // evidence the M2 probe derives `ran` from — not just that the file has the right fields.
  it("the emitted M2.pass.json is read back by findFreshPass as fresh and derives ran, findings intact", () => {
    const target = "/engagement/repo";
    const r = runDynamicValidation({ targetDir: target, layout: layout(), artifactsDir: dir, now, runner: runner() });
    expect(r.artifactPath).not.toBeNull();

    const ctx: RunContext = {
      targetDir: target, // the audit's target must match the artifact's — that's what freshness gates on
      env: { connected: false, dynamic: true, llm: false },
      exec: () => ({ ok: true, output: "" }),
      exists: (p) => existsSync(p),
      artifactsDir: dir,
      readArtifact: (p) => (existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) : undefined),
      now: Date.parse(now()),
    };
    const pass = findFreshPass(ctx, "M2");
    expect(pass.fresh).toBe(true);
    if (pass.fresh) {
      expect(pass.artifact.pass).toBe("dynamic");
      expect(ranFromPass(pass.artifact, "dynamic pen-test").status).toBe("ran");
      expect(pass.artifact.findings).toHaveLength(1);
    }
  });
});
