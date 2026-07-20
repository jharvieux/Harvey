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
  it("suppresses a Props type used only in-file but still reports a truly-unreferenced exported type", () => {
    const findings = runCli(exportedTypesFixture());
    const typeFinding = findings.find((f) => f.title.includes("Exported-but-unreferenced type"));
    expect(typeFinding).toBeDefined();
    expect(typeFinding?.evidence).toContain("OrphanType");
    expect(typeFinding?.evidence).not.toContain("WidgetProps");
    // and it stays the de-escalated review tier from #693, never confirmed dead code
    expect(typeFinding?.confidence).toBe("Review");
  }, 30000);
});

describe("quality-scan CLI — M5 discloses uncertain knip entry resolution on a mis-resolved Vite target (#580)", () => {
  it("raises M5-99 when vite.config.ts/index.html are present but `vite` isn't resolvable", () => {
    const findings = runCli(misresolvedViteFixture());
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
  it("does not flag a test-only-imported lib (test globs make the test an entry), still flags a genuinely-dead lib as review-tier", () => {
    const findings = runCli(configlessNextFixture());
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
  it("rescues vite.config.ts and main-reachable files, still flags a dead file at review tier", () => {
    const findings = runCli(configlessViteFixture());
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
  it("respects the target's entries (its config governs) and keeps its file findings Confirmed", () => {
    const findings = runCli(ownKnipConfigFixture());
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
