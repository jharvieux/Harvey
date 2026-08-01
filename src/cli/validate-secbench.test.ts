// #1756 — the SecBench gate used to invoke semgrep raw with the pre-#1664 swallow, so a
// semgrep-core crash that left a partial envelope on stdout was scored as a completed pass with
// fewer hits. SecBench is one of only three recall gates whose answer keys were written outside
// this repo, it runs monthly behind a `--min-sca-recall` floor, and its numbers get quoted in
// issues and docs as capability facts — so a crash-truncated run publishes a wrong number under a
// green check. That is exactly the #1664 misattribution ("113 rules never worked") in a second
// venue.
//
// #1407's lesson is why this spawns the real CLI rather than unit-testing the classifier: the
// classifier is already covered by src/scan/semgrep-crash.test.ts, and what was unguarded here is
// this file's own call to it. The semgrep shim replays the live crash shape measured in #1664 — a
// valid but EMPTY envelope on stdout with a non-zero exit — which is the case the old predicate
// accepted, because its only test was "is stdout non-empty".

import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { SECBENCH_CLASSES } from "../scan/secbench.js";

const CLI = fileURLToPath(new URL("./validate-secbench.ts", import.meta.url));

let root: string;
let corpus: string;
let osvReport: string;
let lockTree: string;

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "harvey-secbench-gate-"));
  corpus = join(root, "corpus");
  lockTree = join(root, "locks");
  // One entry per class: loadSecbenchCorpus refuses a partial load, so every class needs one.
  for (const cls of SECBENCH_CLASSES) {
    const slug = join(corpus, cls, "CVE-2020-0001");
    mkdirSync(slug, { recursive: true });
    writeFileSync(join(slug, "package.json"), JSON.stringify({ id: "CVE-2020-0001", dependencies: { "some-pkg": "1.0.0" } }));
    writeFileSync(join(slug, "exploit.js"), "require('some-pkg')('x');\n");
  }
  osvReport = join(root, "osv.json");
  writeFileSync(osvReport, JSON.stringify({ results: [] }));
  // A generated lockfile per entry, so `installable` is non-zero: the #1509 gate-liveness receipt
  // refuses a run that scored nothing, and a CONTROL that exits 1 for THAT reason would prove
  // nothing about the semgrep classification this file is testing.
  for (const cls of SECBENCH_CLASSES) {
    const slug = join(lockTree, cls, "CVE-2020-0001");
    mkdirSync(slug, { recursive: true });
    writeFileSync(join(slug, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages: {} }));
  }
});
afterAll(() => rmSync(root, { recursive: true, force: true }));

function shim(script: string): string {
  const dir = mkdtempSync(join(tmpdir(), "harvey-semgrep-shim-"));
  writeFileSync(join(dir, "semgrep"), script, { mode: 0o755 });
  return dir;
}

function run(shimDir: string): Promise<{ code: number | null; out: string }> {
  return new Promise((resolve) => {
    const child = spawn(
      "pnpm",
      ["exec", "tsx", CLI, "--dir", corpus, "--osv-report", osvReport, "--lockfile-tree", lockTree],
      { env: { ...process.env, PATH: `${shimDir}:${process.env.PATH ?? ""}` } },
    );
    let out = "";
    child.stdout.on("data", (d: Buffer) => (out += d.toString()));
    child.stderr.on("data", (d: Buffer) => (out += d.toString()));
    child.on("close", (code) => resolve({ code, out }));
  });
}

// The empty-envelope-plus-nonzero-exit shape #1664 measured live (`--config /dev/null` exits 7 with
// results: [] and an errors[] entry) — the one the swallow accepted, because stdout is non-empty.
const CRASHED = '#!/bin/bash\nif [ "$1" = "--version" ]; then echo "1.164.0"; exit 0; fi\necho \'{"version":"1.164.0","results":[],"errors":[{"level":"error","message":"semgrep-core exited with -10!"}],"paths":{"scanned":[],"skipped":[]}}\'\nexit 2\n';
const COMPLETED = '#!/bin/bash\nif [ "$1" = "--version" ]; then echo "1.164.0"; exit 0; fi\necho \'{"version":"1.164.0","results":[],"errors":[],"paths":{"scanned":[],"skipped":[]}}\'\nexit 0\n';

describe("the SecBench gate refuses to score a semgrep run that did not complete (#1756)", () => {
  it("exits 2 with SCAN DID NOT RUN, and prints no recall table", async () => {
    const dir = shim(CRASHED);
    try {
      const { code, out } = await run(dir);
      expect(out).toContain("SCAN DID NOT RUN");
      expect(out).toContain("did not complete");
      expect(out, "a gate that could not measure must not print a measurement").not.toContain("SecBench.js recall");
      expect(out).not.toContain("FREE/MECHANICAL-TIER RECALL");
      expect(code).toBe(2);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 120000);

  // The failing direction is only evidence if the SAME harness goes green on a completed run: an
  // exit 2 from a broken fixture path would satisfy the assertions above just as well.
  it("CONTROL — the identical invocation with a COMPLETED semgrep scores and exits 0", async () => {
    const dir = shim(COMPLETED);
    try {
      const { code, out } = await run(dir);
      expect(out).not.toContain("SCAN DID NOT RUN");
      expect(out).toContain("SecBench.js recall");
      expect(out).toContain(`${SECBENCH_CLASSES.length} classes`);
      expect(code).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 120000);
});
