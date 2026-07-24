import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { checkUnanalysedLanguages } from "./language-coverage.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function makeTarget(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "harvey-lang-"));
  dirs.push(dir);
  for (const [rel, text] of Object.entries(files)) {
    const full = join(dir, rel);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, text);
  }
  return dir;
}

describe("checkUnanalysedLanguages (#871)", () => {
  it("names every unanalysed language with its file count and an example path", () => {
    const dir = makeTarget({
      "services/billing/worker.py": "import psycopg2\n",
      "services/billing/tasks.py": "import psycopg2\n",
      "services/sync/main.go": "package main\n",
      "app/page.tsx": "export default function Page() { return null; }\n",
    });
    const [finding] = checkUnanalysedLanguages(dir);
    expect(finding).toMatchObject({ id: "M1-LANG-00", severity: "Info", confidence: "N/A" });
    expect(finding?.evidence).toContain("Python (2 files");
    expect(finding?.evidence).toContain("Go (1 file,");
    expect(finding?.evidence).toMatch(/services\/billing\/\w+\.py/);
    // The disclosure must not overstate the gap: the third-party packs do read some of these.
    expect(finding?.evidence).toContain("p/owasp-top-ten");
  });

  it("emits nothing for a pure JS/TS target (the languages M1 does analyse)", () => {
    const dir = makeTarget({
      "app/page.tsx": "export default function Page() { return null; }\n",
      "lib/db.ts": "export const q = 1;\n",
    });
    expect(checkUnanalysedLanguages(dir)).toEqual([]);
  });

  it("ignores vendored/installed trees — a target's own source is the subject", () => {
    const dir = makeTarget({
      "node_modules/some-pkg/setup.py": "from setuptools import setup\n",
      ".venv/lib/site.py": "x = 1\n",
      "app/page.tsx": "export default function Page() { return null; }\n",
    });
    expect(checkUnanalysedLanguages(dir)).toEqual([]);
  });
});

// The disclosure's premise is that every custom M1 rule is JS/TS-only. That is a claim about the
// rule set, and claims decay: if a rule is ever added for another language, this fails and the
// disclosure wording (and LANGUAGES list) must be revisited rather than silently over-claiming.
describe("the premise the #871 disclosure rests on", () => {
  it("every harvey-* semgrep rule still declares javascript/typescript only", () => {
    const rulesDir = join(dirname(fileURLToPath(import.meta.url)), "rules", "semgrep");
    const declared = readdirSync(rulesDir)
      .filter((f) => f.endsWith(".yml"))
      .flatMap((f) => [...readFileSync(join(rulesDir, f), "utf8").matchAll(/^\s*languages:\s*\[([^\]]+)\]/gm)].map((m) => m[1]!));
    expect(declared.length).toBeGreaterThan(0);
    for (const langs of declared) {
      expect(langs.split(",").map((l) => l.trim()).sort()).toEqual(["javascript", "typescript"]);
    }
  });
});
