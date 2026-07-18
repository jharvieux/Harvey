// #544: jscpd (M4 duplication) runs WHOLE-REPO, not per-workspace. #519 had swept it into knip's
// per-workspace change, which on a monorepo structurally cannot see a block copy-pasted ACROSS
// workspaces — the most valuable duplication signal in a monorepo — and also silently dropped every
// workspace the shared discoverTargets glob can't expand (a `packages/**` double-star, #548). This
// drives the real CLI against a synthetic two-workspace monorepo whose only clone spans apps/web and
// a `packages/**` package: under per-workspace jscpd M4 sees nothing; under whole-repo it must find
// the cross-workspace pair. A regression back to per-workspace jscpd fails this test.

import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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

function runCli(repo: string): Finding[] {
  const outPath = join(repo, "quality-out.json");
  execFileSync("node_modules/.bin/tsx", [CLI, repo, "--out", outPath], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    stdio: ["ignore", "ignore", "pipe"],
  });
  return JSON.parse(readFileSync(outPath, "utf8")) as Finding[];
}

describe("quality-scan CLI — jscpd runs whole-repo so cross-workspace clones are detected (#544)", () => {
  // 30s: drives the real CLI end-to-end (jscpd whole-repo + per-workspace knip on the now-enumerated
  // packages/** workspace, #548) as a child process — well over vitest's 5s default under load.
  it("finds a clone spanning apps/web and a packages/** workspace", () => {
    const findings = runCli(monorepoFixture());
    const crossWorkspace = findings.filter(
      (f) => f.taxonomy.startsWith("M4 —") && f.location.includes("apps/web") && f.location.includes("packages/billing"),
    );
    expect(crossWorkspace.length).toBeGreaterThan(0);
  }, 30000);

  // #580: this target has NO vite markers and a healthy (mostly-used) file set — the disclosure
  // must stay silent on a target that never asked the question, matching "a normal Vite target
  // with the plugin active is unaffected" from a non-Vite target's side too.
  it("does not raise the M5-99 entry-uncertain disclosure on a normal, non-Vite target", () => {
    const findings = runCli(monorepoFixture());
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

describe("quality-scan CLI — M5 discloses uncertain knip entry resolution on a mis-resolved Vite target (#580)", () => {
  it("raises M5-99 when vite.config.ts/index.html are present but `vite` isn't resolvable", () => {
    const findings = runCli(misresolvedViteFixture());
    const disclosure = findings.find((f) => f.id === "M5-99");
    expect(disclosure).toBeDefined();
    expect(disclosure?.taxonomy).toContain("M5");
    expect(disclosure?.evidence).toContain("isn't resolvable");
  }, 30000);
});
