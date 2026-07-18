import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { detectTargetFramework } from "./framework-detect.js";

// Each case writes a throwaway target tree (the probe is disk-based — it must see vite.config /
// index.html that the in-memory detector source set never carries) and asserts the coarse shape.
const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function makeTarget(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "harvey-fw-"));
  dirs.push(dir);
  for (const [rel, text] of Object.entries(files)) {
    const full = join(dir, rel);
    mkdirSync(join(full, ".."), { recursive: true });
    writeFileSync(full, text);
  }
  return dir;
}

describe("detectTargetFramework (#573)", () => {
  it("detects Vite from a vite.config + index.html + import.meta.env SPA export", () => {
    const dir = makeTarget({
      "vite.config.ts": `import { defineConfig } from "vite";\nexport default defineConfig({});\n`,
      "index.html": `<!doctype html><html><body><div id="root"></div><script type="module" src="/src/main.tsx"></script></body></html>`,
      "package.json": JSON.stringify({ name: "spa", devDependencies: { vite: "^5.0.0" } }),
      "src/lib/supabaseClient.ts": `const url = import.meta.env.VITE_SUPABASE_URL;\nexport const x = url;\n`,
    });
    expect(detectTargetFramework(dir)).toBe("vite");
  });

  it("detects Vite from index.html + import.meta.env even with no vite.config or vite dep", () => {
    const dir = makeTarget({
      "index.html": `<!doctype html><div id="root"></div>`,
      "package.json": JSON.stringify({ name: "spa", dependencies: { react: "^18.0.0" } }),
      "src/main.tsx": `const key = import.meta.env.VITE_OPENAI_API_KEY;\nexport default key;\n`,
    });
    expect(detectTargetFramework(dir)).toBe("vite");
  });

  it("detects Next from a `next` dependency in package.json", () => {
    const dir = makeTarget({
      "package.json": JSON.stringify({ name: "app", dependencies: { next: "14.2.0", react: "^18.0.0" } }),
      "app/page.tsx": `export default function Page() {\n  return <div />;\n}\n`,
    });
    expect(detectTargetFramework(dir)).toBe("next");
  });

  it("detects Next from a next.config file with no explicit dep entry", () => {
    const dir = makeTarget({
      "next.config.mjs": `export default {};\n`,
      "package.json": JSON.stringify({ name: "app" }),
      "app/page.tsx": `export default function Page() {\n  return <div />;\n}\n`,
    });
    expect(detectTargetFramework(dir)).toBe("next");
  });

  it("prefers Next when both Next and Vite signals are present (never suppress a real Next app)", () => {
    const dir = makeTarget({
      "next.config.js": `module.exports = {};\n`,
      "vite.config.ts": `export default {};\n`,
      "package.json": JSON.stringify({ name: "hybrid", dependencies: { next: "14.0.0" }, devDependencies: { vite: "^5.0.0" } }),
    });
    expect(detectTargetFramework(dir)).toBe("next");
  });

  it("returns `other` for a plain library with neither framework's shape", () => {
    const dir = makeTarget({
      "package.json": JSON.stringify({ name: "lib", dependencies: { lodash: "^4.0.0" } }),
      "src/index.ts": `export const add = (a: number, b: number) => a + b;\n`,
    });
    expect(detectTargetFramework(dir)).toBe("other");
  });

  it("treats a malformed package.json as no dependency signal (no crash)", () => {
    const dir = makeTarget({
      "package.json": `{ not valid json`,
      "vite.config.js": `export default {};\n`,
    });
    expect(detectTargetFramework(dir)).toBe("vite");
  });
});
