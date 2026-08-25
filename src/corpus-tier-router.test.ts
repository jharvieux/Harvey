import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const WORKFLOW = fileURLToPath(new URL("../.github/workflows/corpus-drift.yml", import.meta.url));

function routerScripts(yaml: string = readFileSync(WORKFLOW, "utf8")): string[] {
  const scripts: string[] = [];
  let cursor = 0;
  while (true) {
    const start = yaml.indexOf("\n          relevant=false\n", cursor);
    if (start === -1) break;
    const end = yaml.indexOf('echo "relevant=$relevant" >> "$GITHUB_OUTPUT"', start);
    if (end === -1) throw new Error("corpus router no longer emits its relevance decision");
    const lineEnd = yaml.indexOf("\n", end);
    const body = yaml.slice(start, lineEnd);
    if (!body.includes('case "$f" in')) throw new Error("extracted corpus span is not a path router");
    scripts.push(body);
    cursor = lineEnd;
  }
  if (scripts.length !== 2) throw new Error(`expected two corpus path routers, found ${scripts.length}`);
  return scripts;
}

function route(script: string, files: string[]): boolean {
  const dir = mkdtempSync(join(tmpdir(), "harvey-corpus-router-"));
  const out = join(dir, "github_output");
  try {
    execFileSync("bash", ["-c", `set -eu\n: > "$GITHUB_OUTPUT"\nfiles=$(cat)\n${script}\n`], {
      input: files.join("\n"),
      env: { ...process.env, GITHUB_OUTPUT: out },
      encoding: "utf8",
    });
    return readFileSync(out, "utf8").trim() === "relevant=true";
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("corpus hosted path routers", () => {
  it("short-circuits every focused local policy/docs path in both hosted routers", () => {
    const paths = [
      "AGENTS.md",
      "CLAUDE.md",
      "MODULES.md",
      "README.md",
      "SESSION.md",
      "docs/design/recorded-reasons.md",
      ".codex/agents/acceptance-verifier.toml",
    ];
    for (const script of routerScripts()) expect(route(script, paths)).toBe(false);
  });

  it("fails safe to a real corpus run for executable, manifest, and unknown paths", () => {
    for (const script of routerScripts()) {
      for (const path of [
        "src/findings.ts",
        "package.json",
        "targets/calibration/app.ts",
        "docs/data.json",
        ".codex/agents/unclassified.txt",
        ".codex/agents/team/nested.toml",
        "unknown.file",
      ]) {
        expect(route(script, [path]), path).toBe(true);
      }
      expect(route(script, ["SESSION.md", "src/findings.ts"])).toBe(true);
    }
  });

  it("refuses to test a workflow whose two shipped routers cannot be found", () => {
    expect(() => routerScripts("jobs: {}\n")).toThrow(/expected two corpus path routers/);
  });
});
