// #1065 — the tripwire that would have made the missing-.js gap loud. Mirrors
// sfc-coverage.test.ts's (#919) shape for the sibling disclosure.

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadSources } from "../detectors/load-sources.js";
import { checkUnreadSourceExtensions } from "./ext-coverage.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function makeTarget(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "harvey-ext-"));
  dirs.push(dir);
  for (const [rel, text] of Object.entries(files)) {
    const full = join(dir, rel);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, text);
  }
  return dir;
}

const loadedPaths = (dir: string): string[] => loadSources(dir).map((f) => f.path);

describe("checkUnreadSourceExtensions (#1065)", () => {
  it("fires when the loader read only a fraction of the source-like files — the #1065 shape itself", () => {
    const dir = makeTarget({
      "package.json": '{"name":"js-app"}\n',
      "app/page.js": "export default function P() { return null; }\n",
      "app/api/a/route.js": "export const GET = () => null;\n",
      "app/api/b/route.js": "export const GET = () => null;\n",
      "lib/db.ts": "export const q = 1;\n",
    });
    // The pre-fix loader: TypeScript only. The row exists to catch exactly this.
    const [finding] = checkUnreadSourceExtensions(dir, ["package.json", "lib/db.ts"]);
    expect(finding).toMatchObject({ id: "M1-EXT-00", severity: "Info", confidence: "N/A" });
    expect(finding?.evidence).toContain("loaded 1 of 4 source-like files under the target (25%)");
    expect(finding?.evidence).toContain(".js (3 files)");
  });

  it("stays silent on the same target once the loader actually reads it", () => {
    const dir = makeTarget({
      "package.json": '{"name":"js-app"}\n',
      "app/page.js": "export default function P() { return null; }\n",
      "app/api/a/route.js": "export const GET = () => null;\n",
      "app/api/b/route.cjs": "module.exports = {};\n",
      "lib/db.ts": "export const q = 1;\n",
    });
    expect(checkUnreadSourceExtensions(dir, loadedPaths(dir))).toEqual([]);
  });

  it("counts deliberately-excluded minified output rather than dropping it silently", () => {
    const dir = makeTarget({
      "public/a.min.js": "var a=1;\n",
      "public/b.min.js": "var b=1;\n",
      "app/page.js": "export default function P() { return null; }\n",
    });
    const [finding] = checkUnreadSourceExtensions(dir, loadedPaths(dir));
    expect(finding?.evidence).toContain("2 minified/generated file(s) excluded by decision");
    expect(finding?.evidence).toContain("loaded 1 of 3 source-like files under the target (33%)");
  });

  it("emits nothing for an empty or non-source target", () => {
    expect(checkUnreadSourceExtensions(makeTarget({ "README.md": "hi\n" }), [])).toEqual([]);
  });

  it("ignores vendored/installed trees — a target's own source is the subject", () => {
    const dir = makeTarget({
      "node_modules/pkg/index.js": "module.exports = {};\n",
      "lib/db.ts": "export const q = 1;\n",
    });
    expect(checkUnreadSourceExtensions(dir, loadedPaths(dir))).toEqual([]);
  });
});
