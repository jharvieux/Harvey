// Calibration gate for the hook-deps adapter (#170): the upstream rule must fire on the
// planted missing-dep and stay silent on the corrected version — same fixture discipline as
// the other M7C classes.

import { readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { readEntriesSafe } from "../fs-walk.js";
import { fileURLToPath } from "node:url";
import { Linter } from "eslint";
import { describe, expect, it, vi } from "vitest";
import { detectHookDepFindings } from "./hook-deps.js";
import type { SourceInput } from "./common.js";

const FIXTURES_ROOT = fileURLToPath(new URL("./__fixtures__/perf/", import.meta.url));

function loadFixtureDir(relDir: string): SourceInput[] {
  const root = join(FIXTURES_ROOT, relDir);
  const files: SourceInput[] = [];
  const walk = (dir: string) => {
    for (const { name: entry, path: full, isDirectory } of readEntriesSafe(dir).entries) {
      if (isDirectory) walk(full);
      else if (entry.endsWith(".txt")) {
        files.push({ path: relative(root, full).replace(/\.txt$/, "").split(sep).join("/"), text: readFileSync(full, "utf8") });
      }
    }
  };
  walk(root);
  return files;
}

describe("missing hook dependencies (react-hooks/exhaustive-deps adapter)", () => {
  it("flags a useEffect reading a prop with an empty dependency array, as an Info-severity style note (#230 — not counted as a Perf finding)", () => {
    const hits = detectHookDepFindings(loadFixtureDir("hook-deps/positive"));
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ severity: "Info", confidence: "Likely", taxonomy: "M7 — Missing hook dependencies" });
    expect(hits[0]?.evidence).toContain("userId");
    expect(hits[0]?.location).toBe("components/profile.tsx:10"); // the rule anchors at the dep-array line
  });

  it("does not flag the corrected dependency list", () => {
    expect(detectHookDepFindings(loadFixtureDir("hook-deps/negative"))).toHaveLength(0);
  });

  it("emits M7H ids so it can merge with M7C findings without collision", () => {
    const hits = detectHookDepFindings(loadFixtureDir("hook-deps/positive"));
    expect(hits[0]?.id).toBe("M7H-01");
  });
});

// #1083: a file this pass's own ESLint+typescript-eslint config fails on used to be silently
// dropped (`catch { continue; }`), behind a comment claiming "the other detectors already skip
// it too" — false: the shared loader (load-sources.ts) has no try/catch, so an unreadable file
// throws there and fails the WHOLE pass loud, before hook-deps.ts ever sees it. This only covers a
// file that IS readable but this pass's own linter config chokes on. Simulated via a mocked
// Linter.prototype.verify (a real-world trigger wasn't reproducible: ESLint's own verify() catches
// parse errors and even parser stack overflows internally, converting them to `fatal` messages
// rather than throwing — TRIED 2026-07-25, see PR body).
describe("hook-deps lint parse failure disclosure (#1083)", () => {
  it("counts and discloses a file the linter throws on, instead of silently dropping it", () => {
    const spy = vi.spyOn(Linter.prototype, "verify").mockImplementation(() => {
      throw new Error("simulated linter crash");
    });
    try {
      const files: SourceInput[] = [{ path: "components/broken.tsx", text: "function Foo() { useEffect(() => { doSomething(userId) }, []) }" }];
      const hits = detectHookDepFindings(files);
      const coverage = hits.find((h) => h.id === "M7H-00");
      expect(coverage).toBeDefined();
      expect(coverage?.category).toBe("Coverage");
      expect(coverage?.severity).toBe("Info");
      expect(coverage?.evidence).toContain("components/broken.tsx");
    } finally {
      spy.mockRestore();
    }
  });
});
