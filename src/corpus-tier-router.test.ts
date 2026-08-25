import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const WORKFLOW = fileURLToPath(new URL("../.github/workflows/corpus-drift.yml", import.meta.url));

function routerScripts(yaml: string = readFileSync(WORKFLOW, "utf8")): string[] {
  const marker = "        name: Route third-party corpus execution by event\n        run: |\n";
  const scripts: string[] = [];
  let cursor = 0;
  while (true) {
    const markerStart = yaml.indexOf(marker, cursor);
    if (markerStart === -1) break;
    const bodyStart = markerStart + marker.length;
    const bodyEnd = yaml.indexOf("\n      - ", bodyStart);
    if (bodyEnd === -1) throw new Error("corpus event router has no following workflow step");
    const body = yaml.slice(bodyStart, bodyEnd).replace(/^ {10}/gm, "");
    if (!body.includes('echo "relevant=false"') || !body.includes('echo "relevant=true"')) {
      throw new Error("corpus event router no longer emits both routing decisions");
    }
    scripts.push(body);
    cursor = bodyEnd;
  }
  if (scripts.length !== 1) throw new Error(`expected one corpus event router, found ${scripts.length}`);
  return scripts;
}

function route(script: string, event: string): boolean {
  const dir = mkdtempSync(join(tmpdir(), "harvey-corpus-router-"));
  const out = join(dir, "github_output");
  try {
    const hydrated = script.replaceAll("${{ github.event_name }}", event);
    execFileSync("bash", ["-c", `set -eu\n: > "$GITHUB_OUTPUT"\n${hydrated}\n`], {
      env: { ...process.env, GITHUB_OUTPUT: out },
      encoding: "utf8",
    });
    return readFileSync(out, "utf8").trim() === "relevant=true";
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("corpus hosted event routers", () => {
  it("defers every pull request and merge-group entry in the shard's defense-in-depth router", () => {
    for (const script of routerScripts()) {
      expect(route(script, "pull_request")).toBe(false);
      expect(route(script, "merge_group")).toBe(false);
    }
  });

  it("runs the complete external corpus on post-merge and monitoring events", () => {
    for (const script of routerScripts()) {
      for (const event of ["push", "schedule", "workflow_dispatch", "unknown-event"]) {
        expect(route(script, event), event).toBe(true);
      }
    }
  });

  it("refuses to test a workflow whose shipped event router cannot be found", () => {
    expect(() => routerScripts("jobs: {}\n")).toThrow(/expected one corpus event router/);
  });
});
