// #544: jscpd (M4 duplication) runs WHOLE-REPO, not per-workspace. #519 had swept it into knip's
// per-workspace change, which on a monorepo structurally cannot see a block copy-pasted ACROSS
// workspaces — the most valuable duplication signal in a monorepo — and also silently dropped every
// workspace the shared discoverTargets glob can't expand (a `packages/**` double-star, #548). This
// drives the real CLI against a synthetic two-workspace monorepo whose only clone spans apps/web and
// a `packages/**` package: under per-workspace jscpd M4 sees nothing; under whole-repo it must find
// the cross-workspace pair. A regression back to per-workspace jscpd fails this test.

import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import type { Finding } from "../findings.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = join(REPO_ROOT, "src", "cli", "quality-scan.ts");

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

// A block long/token-dense enough to clear jscpd's default min-lines/min-tokens gate, so an
// identical copy in two workspaces is reported as one cross-file clone.
const CLONED_BLOCK = `export function summarizeOrder(order: { items: { price: number; qty: number }[]; tax: number }) {
  let subtotal = 0;
  for (const item of order.items) {
    subtotal += item.price * item.qty;
  }
  const taxAmount = subtotal * order.tax;
  const total = subtotal + taxAmount;
  return {
    subtotal: Math.round(subtotal * 100) / 100,
    taxAmount: Math.round(taxAmount * 100) / 100,
    total: Math.round(total * 100) / 100,
    itemCount: order.items.reduce((n, i) => n + i.qty, 0),
  };
}
`;

function monorepoFixture(): string {
  const repo = mkdtempSync(join(tmpdir(), "harvey-quality-cli-"));
  dirs.push(repo);
  writeFileSync(join(repo, "pnpm-workspace.yaml"), "packages:\n  - apps/*\n  - packages/**\n");
  writeFileSync(join(repo, "package.json"), JSON.stringify({ name: "fixture-root", private: true }));
  const write = (rel: string, text: string) => {
    mkdirSync(dirname(join(repo, rel)), { recursive: true });
    writeFileSync(join(repo, rel), text);
  };
  write("apps/web/package.json", JSON.stringify({ name: "web" }));
  write("apps/web/src/order.ts", CLONED_BLOCK);
  // packages/** — the double-star workspace discoverTargets doesn't even enumerate (#548); a
  // whole-repo jscpd walks it regardless of the workspace glob, a per-workspace one never sees it.
  write("packages/billing/package.json", JSON.stringify({ name: "@kit/billing" }));
  write("packages/billing/src/order.ts", CLONED_BLOCK);
  return repo;
}

// #1134: awaited spawn, not execFileSync. execFileSync blocks the vitest worker's event loop for the
// call's duration, and a blocked worker cannot service the birpc ack for a task update it already
// sent — vitest hardcodes a 60s window for that ack (see vitest.config.ts's HEAVY_CLI_TESTS comment,
// and #1120/#1133 which found run-audit.test.ts's beforeAll actually over that line). Measured calls
// here are ~0.7-1.7s each on this hardware, well under the ceiling either way, but the standing
// constraint is "no single blocking window may approach 60s" for every heavy CLI test.
function spawnCli(binPath: string, args: string[], cwd: string): Promise<void> {
  return new Promise((res, rej) => {
    const child = spawn(binPath, args, { cwd, stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    // setEncoding, never `stderr += <Buffer>` (#1759): string-concatenating a Buffer decodes THAT
    // CHUNK in isolation, so a multi-byte character straddling a chunk boundary decodes to U+FFFD.
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (d: string) => (stderr += d));
    child.on("error", rej);
    child.on("close", (code) => (code === 0 ? res() : rej(new Error(`${binPath} ${args.join(" ")} exited ${code}: ${stderr}`))));
  });
}

async function runCli(repo: string, args: string[] = []): Promise<Finding[]> {
  const outPath = join(repo, "quality-out.json");
  await spawnCli("node_modules/.bin/tsx", [CLI, repo, ...args, "--out", outPath], REPO_ROOT);
  return JSON.parse(readFileSync(outPath, "utf8")) as Finding[];
}

describe("quality-scan CLI — jscpd runs whole-repo so cross-workspace clones are detected (#544)", () => {
  // 30s: drives the real CLI end-to-end (jscpd whole-repo + per-workspace knip on the now-enumerated
  // packages/** workspace, #548) as a child process — well over vitest's 5s default under load.
  it("finds a clone spanning apps/web and a packages/** workspace", async () => {
    const findings = await runCli(monorepoFixture());
    const crossWorkspace = findings.filter(
      (f) => f.taxonomy.startsWith("M4 —") && f.location.includes("apps/web") && f.location.includes("packages/billing"),
    );
    expect(crossWorkspace.length).toBeGreaterThan(0);
  }, 30000);

  // #580: this target has NO vite markers and a healthy (mostly-used) file set — the disclosure
  // must stay silent on a target that never asked the question, matching "a normal Vite target
  // with the plugin active is unaffected" from a non-Vite target's side too.
  it("does not raise the M5-99 entry-uncertain disclosure on a normal, non-Vite target", async () => {
    const findings = await runCli(monorepoFixture());
    expect(findings.find((f) => f.id === "M5-99")).toBeUndefined();
  }, 30000);
});

// #580: MEASURED against a real knip run (2026-07-18) — a Vite target where `vite` is declared in
// no dependency at all (the issue's "vite not in deps" cause) leaves knip unable to activate its
// Vite plugin. It falls back to default index.*-only entry resolution: main.ts and its one real
// import stay "used", but vite.config.ts and every other file in src/utils/ come back unused (5 of
// the 7 scanned .ts files, 71%) even though the real Vite entry graph (index.html -> main.ts ->
// utils/a.ts) only leaves 4 of them (utils/b-e) genuinely dead. Regenerating this fixture and
// re-running `knip --reporter json` directly is how the #580 disclosure logic's numbers were
// grounded, not guessed.
function misresolvedViteFixture(): string {
  const repo = mkdtempSync(join(tmpdir(), "harvey-quality-vite-cli-"));
  dirs.push(repo);
  const write = (rel: string, text: string) => {
    mkdirSync(dirname(join(repo, rel)), { recursive: true });
    writeFileSync(join(repo, rel), text);
  };
  write("package.json", JSON.stringify({ name: "vite-fixture", private: true, version: "0.0.0" }));
  write("vite.config.ts", "export default {};\n");
  write("index.html", '<!doctype html>\n<html>\n  <body>\n    <script type="module" src="/src/main.ts"></script>\n  </body>\n</html>\n');
  write("src/main.ts", 'import { helperA } from "./utils/a";\nconsole.log(helperA());\n');
  write("src/utils/a.ts", "export function helperA() {\n  return \"a\";\n}\n");
  for (const n of ["b", "c", "d", "e"]) {
    write(`src/utils/${n}.ts`, `export function helper${n.toUpperCase()}() {\n  return "${n}";\n}\n`);
  }
  return repo;
}

// #693/AoP#566: Harvey merges knip's `ignoreExportsUsedInFile: { interface, type }` into the scan
// so a component Props/option type used only within its own file (exported by convention) isn't
// over-reported, while a type exported and referenced nowhere still surfaces. Pins the injection
// end-to-end through the CLI; the mechanism itself was verified directly against knip 5.88.1.
function exportedTypesFixture(): string {
  const repo = mkdtempSync(join(tmpdir(), "harvey-quality-types-cli-"));
  dirs.push(repo);
  const write = (rel: string, text: string) => {
    mkdirSync(dirname(join(repo, rel)), { recursive: true });
    writeFileSync(join(repo, rel), text);
  };
  write("package.json", JSON.stringify({ name: "types-fixture", private: true, version: "0.0.0", type: "module" }));
  write("src/index.ts", 'import { Widget } from "./widget.js";\nexport function main() {\n  return Widget({ label: "x" });\n}\n');
  write(
    "src/widget.ts",
    // WidgetProps: exported, used only in-file → must be suppressed by the injected config.
    // OrphanType: exported, referenced nowhere → must still surface (review-tier, not dead-code delete).
    "export interface WidgetProps {\n  label: string;\n}\nexport interface OrphanType {\n  gone: boolean;\n}\nexport function Widget(props: WidgetProps) {\n  return props.label;\n}\n",
  );
  return repo;
}

describe("quality-scan CLI — M5 injects knip ignoreExportsUsedInFile so exported-by-convention types aren't over-reported (#693/AoP#566)", () => {
  it("suppresses a Props type used only in-file but still reports a truly-unreferenced exported type", async () => {
    const findings = await runCli(exportedTypesFixture());
    const typeFinding = findings.find((f) => f.title.includes("Exported-but-unreferenced type"));
    expect(typeFinding).toBeDefined();
    expect(typeFinding?.evidence).toContain("OrphanType");
    expect(typeFinding?.evidence).not.toContain("WidgetProps");
    // and it stays the de-escalated review tier from #693, never confirmed dead code
    expect(typeFinding?.confidence).toBe("Review");
  }, 30000);
});

describe("quality-scan CLI — M5 discloses uncertain knip entry resolution on a mis-resolved Vite target (#580)", () => {
  it("raises M5-99 when vite.config.ts/index.html are present but `vite` isn't resolvable", async () => {
    const findings = await runCli(misresolvedViteFixture());
    const disclosure = findings.find((f) => f.id === "M5-99");
    expect(disclosure).toBeDefined();
    expect(disclosure?.taxonomy).toContain("M5");
    expect(disclosure?.evidence).toContain("isn't resolvable");
  }, 30000);
});

// #696: a config-less scan target gives knip no way to infer non-app entry points (test files above
// all), so it floods the unused-files list with test-only-imported libs. Harvey generates a knip
// config (test/script/load-test globs + framework entries) for a config-less scope, so those files
// resolve — but because the entry graph is INFERRED, the residual unused-FILE findings drop to
// review tier.
const write = (repo: string, rel: string, text: string) => {
  mkdirSync(dirname(join(repo, rel)), { recursive: true });
  writeFileSync(join(repo, rel), text);
};

function configlessNextFixture(): string {
  const repo = mkdtempSync(join(tmpdir(), "harvey-quality-next-cli-"));
  dirs.push(repo);
  // `next` dep → detectTargetFramework === "next"; ships NO knip config, so Harvey infers entries.
  write(repo, "package.json", JSON.stringify({ name: "next-fixture", private: true, version: "0.0.0", type: "module", dependencies: { next: "14.2.0" } }));
  write(repo, "app/page.tsx", 'import { used } from "../lib/used.js";\nexport default function Page() {\n  return used;\n}\n');
  write(repo, "lib/used.ts", 'export const used = "u";\n');
  // Reachable ONLY through a test file — knip would flag it dead without the generated test-glob
  // entry. Its survival is the proof the test-glob lever works.
  write(repo, "lib/testonly.ts", 'export const testHelper = "t";\n');
  write(repo, "lib/testonly.test.ts", 'import { testHelper } from "./testonly.js";\nconsole.log(testHelper);\n');
  // Genuinely dead: no entry (inferred or otherwise) reaches it — must still surface.
  write(repo, "lib/dead.ts", 'export const dead = "d";\n');
  return repo;
}

describe("quality-scan CLI — M5 generates a knip config for a config-less scope so entries resolve (#696)", () => {
  it("does not flag a test-only-imported lib (test globs make the test an entry), still flags a genuinely-dead lib as review-tier", async () => {
    const findings = await runCli(configlessNextFixture());
    const unusedFile = (name: string) => findings.find((f) => f.taxonomy.startsWith("M5 —") && f.title.startsWith("Unused") && f.location.endsWith(name));

    // test-only-imported file rescued by the generated test glob
    expect(unusedFile("lib/testonly.ts")).toBeUndefined();
    // page-imported file rescued by the generated app-router entry glob
    expect(unusedFile("lib/used.ts")).toBeUndefined();

    // genuinely-dead file still surfaces — but at review tier, since the entry graph was inferred
    const dead = unusedFile("lib/dead.ts");
    expect(dead).toBeDefined();
    expect(dead?.confidence).toBe("Review");
    expect(dead?.precisionTier).toBe("review");
    expect(dead?.impact).toContain("Harvey-inferred entry points");
  }, 30000);
});

function configlessViteFixture(): string {
  const repo = mkdtempSync(join(tmpdir(), "harvey-quality-vite696-cli-"));
  dirs.push(repo);
  write(repo, "package.json", JSON.stringify({ name: "vite696", private: true, version: "0.0.0", type: "module" }));
  write(repo, "vite.config.ts", "export default {};\n");
  write(repo, "index.html", '<!doctype html>\n<html>\n  <body>\n    <script type="module" src="/src/main.ts"></script>\n  </body>\n</html>\n');
  write(repo, "src/main.ts", 'import { used } from "./used.js";\nconsole.log(used);\n');
  write(repo, "src/used.ts", 'export const used = "u";\n');
  write(repo, "src/dead.ts", 'export const dead = "d";\n');
  return repo;
}

describe("quality-scan CLI — M5 resolves Vite entries (index.html/main/vite.config) from a generated config (#696)", () => {
  it("rescues vite.config.ts and main-reachable files, still flags a dead file at review tier", async () => {
    const findings = await runCli(configlessViteFixture());
    const unusedFile = (name: string) => findings.find((f) => f.taxonomy.startsWith("M5 —") && f.title.startsWith("Unused") && f.location.endsWith(name));

    // index.html/main entry declared by the generated Vite globs keeps main.ts + its import used;
    // vite.config.ts is declared an entry so it is no longer over-reported.
    expect(unusedFile("vite.config.ts")).toBeUndefined();
    expect(unusedFile("src/main.ts")).toBeUndefined();
    expect(unusedFile("src/used.ts")).toBeUndefined();

    const dead = unusedFile("src/dead.ts");
    expect(dead).toBeDefined();
    expect(dead?.confidence).toBe("Review");
  }, 30000);
});

function ownKnipConfigFixture(): string {
  const repo = mkdtempSync(join(tmpdir(), "harvey-quality-ownknip-cli-"));
  dirs.push(repo);
  write(repo, "package.json", JSON.stringify({ name: "ownknip", private: true, version: "0.0.0", type: "module" }));
  // The target's OWN knip config names a NON-standard entry Harvey's inferred globs would never
  // declare. If Harvey overrode entries, custom-entry.ts (and reachable.ts) would show unused.
  write(repo, "knip.json", JSON.stringify({ entry: ["custom-entry.ts"] }));
  write(repo, "custom-entry.ts", 'import { thing } from "./reachable.js";\nconsole.log(thing);\n');
  // LocalProps: exported, used only in-file → proves the #695 ignoreExportsUsedInFile merge STILL
  // happens even though entries are the target's own.
  write(repo, "reachable.ts", "export interface LocalProps {\n  x: number;\n}\nexport const thing: LocalProps = { x: 1 };\n");
  write(repo, "dead.ts", 'export const dead = "d";\n');
  return repo;
}

describe("quality-scan CLI — M5 never overrides a target's own knip entry config (#696), only merges ignoreExportsUsedInFile (#695)", () => {
  it("respects the target's entries (its config governs) and keeps its file findings Confirmed", async () => {
    const findings = await runCli(ownKnipConfigFixture());
    const unusedFile = (name: string) => findings.find((f) => f.taxonomy.startsWith("M5 —") && f.title.startsWith("Unused") && f.location.endsWith(name));

    // reachable via the TARGET's own custom entry — proves Harvey did not override entries.
    expect(unusedFile("reachable.ts")).toBeUndefined();

    // dead file surfaces at Confirmed tier — the target supplied its own entry graph, so its file
    // findings are NOT the review-tier inferred kind.
    const dead = unusedFile("dead.ts");
    expect(dead).toBeDefined();
    expect(dead?.confidence).toBe("Confirmed");
    expect(dead?.precisionTier).toBe("high");

    // the #695 merge still applies: an interface exported and used only in-file is not over-reported.
    const typeFinding = findings.find((f) => f.title.includes("Exported-but-unreferenced type") && f.evidence.includes("LocalProps"));
    expect(typeFinding).toBeUndefined();
  }, 30000);
});

// #810: the "NEEDS target npm install" prereq. This fixture ships a vite.config.ts that imports an
// uninstalled plugin (@vitejs/plugin-react) — exactly what a target with no node_modules looks like:
// knip aborts trying to LOAD that plugin config (MEASURED against knip 5.88.1: exit 2, no JSON).
// Before #810 M5 produced only the M5-00 "did not complete" gap (zero findings). Now it re-runs with
// every knip plugin disabled + inferred entries and surfaces the dead file at review tier, disclosing
// the reduced mode as M5-98. A regression that drops the retry produces M5-00 and no dead-code finding.
function noNodeModulesViteFixture(): string {
  const repo = mkdtempSync(join(tmpdir(), "harvey-quality-noinstall-cli-"));
  dirs.push(repo);
  write(repo, "package.json", JSON.stringify({ name: "noinstall", private: true, version: "0.0.0", type: "module", devDependencies: { vite: "^5.0.0", "@vitejs/plugin-react": "^4.0.0" } }));
  // Imports an uninstalled plugin → knip can't load this config without the target's node_modules.
  write(repo, "vite.config.cjs", 'require("node:fs").writeFileSync("target-provider-consumed", "yes");\nrequire("@vitejs/plugin-react");\nmodule.exports = {};\n');
  write(repo, "index.html", '<!doctype html>\n<html>\n  <body>\n    <script type="module" src="/src/main.ts"></script>\n  </body>\n</html>\n');
  write(repo, "src/main.ts", 'import { used } from "./used.js";\nconsole.log(used);\n');
  write(repo, "src/used.ts", 'export const used = "u";\n');
  write(repo, "src/dead.ts", 'export const dead = "d";\n');
  return repo;
}

describe("quality-scan CLI — M5 runs without the target's node_modules via a plugins-disabled retry (#810)", () => {
  it("produces dead-code findings on a no-node_modules target and discloses the reduced tier as M5-98, not the M5-00 gap", async () => {
    const findings = await runCli(noNodeModulesViteFixture());
    const unusedFile = (name: string) => findings.find((f) => f.taxonomy.startsWith("M5 —") && f.title.startsWith("Unused") && f.location.endsWith(name));

    // The dead file is surfaced even though knip could not load the target's config — at review tier
    // (entries were inferred by the degraded retry, same contingency as #696).
    const dead = unusedFile("src/dead.ts");
    expect(dead).toBeDefined();
    expect(dead?.confidence).toBe("Review");
    expect(dead?.precisionTier).toBe("review");

    // main-reachable file is NOT flagged — the inferred Vite/index.html entry globs still resolve it.
    expect(unusedFile("src/used.ts")).toBeUndefined();

    // reduced-mode disclosure present; the "did not complete" gap is NOT (it DID complete via retry).
    const reduced = findings.find((f) => f.id === "M5-98");
    expect(reduced).toBeDefined();
    expect(reduced?.taxonomy).toContain("M5");
    expect(reduced?.fix).toContain("dependencies");
    expect(findings.find((f) => f.id === "M5-00")).toBeUndefined();
  }, 30000);

  it("starts directly in the source-only tier when dependency preparation rejected the installed tree", async () => {
    const repo = noNodeModulesViteFixture();
    const findings = await runCli(repo, ["--degraded-knip-reason", "dependency preparation incomplete: clean install failed"]);
    expect(existsSync(join(repo, "target-provider-consumed"))).toBe(false);
    expect(findings).toContainEqual(expect.objectContaining({ id: "M5-01", location: expect.stringMatching(/src\/dead\.ts$/), confidence: "Review" }));
    expect(findings).toContainEqual(expect.objectContaining({ id: "M5-98", evidence: expect.stringContaining("dependency preparation incomplete") }));
    expect(findings.find((finding) => finding.id === "M5-00")).toBeUndefined();
  }, 30000);
});

// #948 (remainder of #931): jscpd resolves its `.jscpd.json` auto-discovery AND, separately, its
// own CWD's `.gitignore` (a second, less-anchored .gitignore reader in jscpd's own CLI package,
// distinct from the one @jscpd/finder uses for the scanned directory itself) relative to
// `process.cwd()` of the CHILD PROCESS — not the target directory passed on the command line.
// Confirmed by instrumenting jscpd 4.2.5 directly: a multi-segment `.gitignore` entry read from an
// unrelated CWD gets converted into an ANY-DEPTH glob that can accidentally match a directory name
// inside a wholly unrelated scanned tree, silently emptying jscpd's file list — exactly the
// "some absolute paths" cwd-dependence #931 measured on documenso. This engineers a deterministic
// collision (rather than relying on a real repo's real path to coincidentally collide) and proves
// quality-scan's own jscpd invocation is no longer cwd-dependent: pinning `cwd: dir` in runJscpd
// (src/cli/quality-scan.ts) makes the child read the TARGET's own .gitignore/.jscpd.json
// regardless of where quality-scan itself happens to be launched from.
function poisonCwdFixture(): { poisonCwd: string; target: string } {
  const poisonCwd = mkdtempSync(join(tmpdir(), "harvey-quality-poison-cwd-"));
  dirs.push(poisonCwd);
  execFileSync("git", ["init", "-q"], { cwd: poisonCwd });
  // A multi-segment, non-rooted .gitignore entry — jscpd's CWD-based reader (src/init/ignore.ts)
  // has no concept of a scan-relative baseDir, so it converts this into a bare "**/zzz/dup/**"
  // any-depth glob instead of anchoring it to poisonCwd, unlike @jscpd/finder's own (correct)
  // per-scanDir gitignore collector.
  writeFileSync(join(poisonCwd, ".gitignore"), "zzz/dup\n");

  const target = mkdtempSync(join(tmpdir(), "harvey-quality-poison-target-"));
  dirs.push(target);
  execFileSync("git", ["init", "-q"], { cwd: target });
  writeFileSync(join(target, "package.json"), JSON.stringify({ name: "poison-target-fixture", private: true }));
  // Every comparable source file lives under zzz/dup/ — if the poisoned CWD's any-depth glob
  // leaks into this scan, it excludes the target's ENTIRE file list, not just a subset.
  write(target, "zzz/dup/a.ts", CLONED_BLOCK);
  write(target, "zzz/dup/b.ts", CLONED_BLOCK);
  return { poisonCwd, target };
}

async function runCliFromCwd(cwd: string, repo: string): Promise<Finding[]> {
  const outPath = join(repo, "quality-out.json");
  // Absolute tsx path: `cwd` here is the whole point under test (an unrelated directory), so a
  // repo-relative "node_modules/.bin/tsx" (which every other helper in this file can use because
  // THEY pin cwd: REPO_ROOT) would not resolve.
  await spawnCli(join(REPO_ROOT, "node_modules", ".bin", "tsx"), [CLI, repo, "--out", outPath], cwd);
  return JSON.parse(readFileSync(outPath, "utf8")) as Finding[];
}

describe("quality-scan CLI — jscpd is not poisoned by an unrelated CWD's .gitignore/.jscpd.json (#948)", () => {
  it("finds the real cross-file clone even when launched from a CWD whose own .gitignore would (if leaked) exclude the whole target", async () => {
    const { poisonCwd, target } = poisonCwdFixture();
    const findings = await runCliFromCwd(poisonCwd, target);

    const clone = findings.filter((f) => f.taxonomy.startsWith("M4 —") && f.location.includes("zzz/dup/a.ts") && f.location.includes("zzz/dup/b.ts"));
    expect(clone.length).toBeGreaterThan(0);
    // The coverage-gap disclosure (jscpd wrote no report / analysed nothing) must NOT fire —
    // that's the exact symptom this test guards against regressing to.
    expect(findings.find((f) => f.id === "M4-99")).toBeUndefined();
  }, 30000);
});

// #1050: briefs/audit-modules.md names unused DEPENDENCIES as part of M5's dead-code output. knip
// reports them; Harvey's KnipIssue type had no field for them, so they were dropped at the type
// boundary and M5 under-reported with no disclosure — an absence that reads as a clean result.
// MEASURED against knip 5.88.1 (2026-07-25): the JSON reporter puts them on the package.json issue
// entry as `dependencies` / `devDependencies`, each [{ name, line, col, pos }]. This drives the real
// CLI so the field names stay pinned to what knip actually emits, not to what an issue claimed.
function unusedDependencyFixture(): string {
  const repo = mkdtempSync(join(tmpdir(), "harvey-quality-unuseddep-cli-"));
  dirs.push(repo);
  write(repo, "package.json", JSON.stringify({
    name: "unuseddep", private: true, version: "0.0.0", type: "module",
    dependencies: { "left-pad": "^1.3.0" },
    devDependencies: { rimraf: "^5.0.0" },
  }));
  write(repo, "src/index.ts", 'export const go = () => "used";\n');
  return repo;
}

describe("quality-scan CLI — M5 reports unused dependencies (#1050)", () => {
  it("surfaces a declared-but-never-imported runtime dependency and devDependency as M5 findings", async () => {
    const findings = await runCli(unusedDependencyFixture());
    const deps = findings.find((f) => f.title === "Unused dependencies declared in package.json");
    const devDeps = findings.find((f) => f.title === "Unused devDependencies declared in package.json");

    expect(deps?.evidence).toContain("left-pad");
    expect(deps?.taxonomy).toBe("M5 — Slop / dead code");
    // A runtime dependency nobody imports still ships into the installed tree — supply-chain
    // surface, which is why it is not filed as pure tidiness.
    expect(deps?.impact).toContain("supply-chain surface");
    expect(devDeps?.evidence).toContain("rimraf");
  }, 30000);
});
