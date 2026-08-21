import { spawn } from "node:child_process";
import { createServer, type Server } from "node:http";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const dir = mkdtempSync(join(tmpdir(), "harvey-file-findings-cli-"));
const target = join(dir, "client-checkout");
const source = join(target, "src/a.ts");
const alias = join(target, "alias.ts");
const findingsPath = join(dir, "findings.json");
const nonDirectory = join(dir, "not-a-directory");

let server: Server;
let jiraBaseUrl: string;
let requestCount = 0;
let createCount = 0;
let storedMarker: string | undefined;

function runCli(args: string[]): Promise<{ out: string; code: number }> {
  return new Promise((done, reject) => {
    const child = spawn("node", ["--import", "tsx", join(REPO_ROOT, "src/cli/file-findings.ts"), ...args], {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        JIRA_BASE_URL: jiraBaseUrl,
        JIRA_EMAIL: "test@example.com",
        JIRA_API_TOKEN: "local-test-token",
        JIRA_PROJECT_KEY: "TEST",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    child.stdout.setEncoding("utf8").on("data", (chunk: string) => { out += chunk; });
    child.stderr.setEncoding("utf8").on("data", (chunk: string) => { out += chunk; });
    child.once("error", reject);
    child.once("close", (code) => done({ out, code: code ?? 1 }));
  });
}

beforeAll(async () => {
  mkdirSync(join(target, "src"), { recursive: true });
  writeFileSync(source, "export const answer = 42;\n");
  symlinkSync("src/a.ts", alias);
  writeFileSync(nonDirectory, "not a directory\n");

  const base = {
    title: "Duplicate identity guard",
    severity: "High",
    confidence: "Confirmed",
    category: "Correctness",
    taxonomy: "M5 — Alias identity",
    status: "Open",
    evidence: "same finding through three path spellings",
    impact: "duplicate tickets",
    fix: "canonicalize at the repo root",
    precisionTier: "high",
    value: 3,
    ease: 3,
    safety: 3,
  };
  writeFileSync(findingsPath, JSON.stringify({ findings: [
    { ...base, id: "F-REL", location: "src/a.ts:1" },
    { ...base, id: "F-ABS", location: `${source}:1` },
    { ...base, id: "F-LINK", location: "alias.ts:1" },
  ] }));

  server = createServer((request, response) => {
    requestCount++;
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    if (request.method === "GET" && url.pathname === "/rest/api/3/search") {
      const jql = url.searchParams.get("jql") ?? "";
      const matches = storedMarker !== undefined && jql.includes(storedMarker);
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ issues: matches ? [{ key: "TEST-1" }] : [] }));
      return;
    }

    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk: string) => { body += chunk; });
    request.on("end", () => {
      if (request.method === "POST" && url.pathname === "/rest/api/3/issue") {
        createCount++;
        storedMarker = /<!-- harvey-finding:[0-9a-f]+ -->/.exec(body)?.[0];
        response.writeHead(201, { "content-type": "application/json" });
        response.end(JSON.stringify({ key: "TEST-1" }));
      } else if (request.method === "PUT" && url.pathname === "/rest/api/3/issue/TEST-1") {
        response.writeHead(204);
        response.end();
      } else {
        response.writeHead(404);
        response.end();
      }
    });
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("loopback Jira server did not bind a TCP port");
  jiraBaseUrl = `http://127.0.0.1:${address.port}`;
});

afterAll(async () => {
  await new Promise<void>((done, reject) => server.close((err) => err ? reject(err) : done()));
  rmSync(dir, { recursive: true, force: true });
});

describe("file-findings CLI binds identities to an explicit repository root (#1899 partial)", () => {
  it("collapses relative, absolute, and symlink aliases through the real Jira adapter", async () => {
    const before = requestCount;
    const result = await runCli([
      "--target", target,
      findingsPath,
      "--tracker", "jira",
      "--grouping", "flat",
      "--connected",
      "--confirm",
    ]);

    expect(result.code).toBe(0);
    expect(result.out).toContain("filed 1, skipped 2 already-present");
    expect(createCount).toBe(1);
    expect(requestCount - before).toBe(5); // 3 marker reads + 1 create + 1 label update, all loopback.
    expect(storedMarker).toMatch(/^<!-- harvey-finding:[0-9a-f]+ -->$/);
  });

  it.each([
    ["missing", []],
    ["nonexistent", ["--target", join(dir, "missing")]],
    ["non-directory", ["--target", nonDirectory]],
  ])("rejects a %s target before tracker traffic", async (_label, targetArgs) => {
    const before = requestCount;
    const result = await runCli([
      findingsPath,
      ...targetArgs,
      "--tracker", "jira",
      "--grouping", "flat",
      "--connected",
      "--confirm",
    ]);

    expect(result.code).toBe(1);
    expect(requestCount).toBe(before);
    expect(result.out).toMatch(targetArgs.length === 0 ? /--target <repo-root>/ : /--target must name an existing directory/);
  });
});
