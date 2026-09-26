import { spawn } from "node:child_process";
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { validateRestoredSemgrepPackArtifact } from "../corpus-mechanical-readiness.js";
import { REGISTRY_PACK_FETCH_POLICY, REGISTRY_PACKS } from "../scan/semgrep.js";

const ROOT = fileURLToPath(new URL("../..", import.meta.url));
const CLI = join(ROOT, "src/cli/materialize-current-semgrep.ts");
const roots: string[] = [];

function temporary(name: string): string {
  const root = mkdtempSync(join(tmpdir(), name));
  roots.push(root);
  return root;
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function fixture(): { bin: string; state: string } {
  const root = temporary("harvey-registry-cli-");
  const bin = join(root, "bin");
  const state = join(root, "state");
  const curl = join(bin, "curl");
  const semgrep = join(bin, "semgrep");
  mkdirSync(bin);
  writeFileSync(curl, `#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const args = process.argv.slice(2);
if (args[args.indexOf("--max-filesize") + 1] !== "33554432") process.exit(90);
const url = args.find((arg) => arg.startsWith("https://semgrep.dev/c/"));
if (!url) process.exit(91);
const pack = url.slice("https://semgrep.dev/c/".length);
const key = pack.replaceAll("/", "-");
fs.mkdirSync(process.env.FAKE_CURL_STATE, { recursive: true });
const countPath = path.join(process.env.FAKE_CURL_STATE, key);
const count = fs.existsSync(countPath) ? Number(fs.readFileSync(countPath, "utf8")) + 1 : 1;
fs.writeFileSync(countPath, String(count));
const mode = process.env.FAKE_CURL_MODE;
const fail = (status) => {
  const output = args[args.indexOf("--output") + 1];
  if (args.includes("--output")) fs.writeFileSync(output, "denied");
  process.stderr.write("curl: upstream authentication diagnostic [TEST_ONLY_registry-secret] denied\\n");
  if (args.includes("--write-out")) process.stdout.write(String(status));
  process.exit(args.includes("--write-out") ? 0 : 22);
};
if (mode === "transient-403" && pack === "p/typescript" && count === 1) fail(403);
if (mode === "transient-503" && pack === "p/typescript" && count < 3) fail(503);
if (mode === "persistent-403" && pack === "p/typescript") fail(403);
if (mode === "persistent-401" && pack === "p/typescript") fail(401);
if ((mode === "transient-partial" && pack === "p/typescript" && count === 1)
  || (mode === "persistent-partial" && pack === "p/typescript")) {
  fs.writeFileSync(args[args.indexOf("--output") + 1], "truncated registry-secret");
  process.stderr.write("curl: transfer closed with outstanding data\\n");
  process.exit(18);
}
if (mode === "oversized" && pack === "p/typescript") {
  const output = args[args.indexOf("--output") + 1];
  fs.writeFileSync(output, "");
  fs.truncateSync(output, 33554433);
  process.stdout.write("200");
  process.exit(0);
}
const body = mode === "invalid-sixth" && pack === "p/security-audit"
  ? "not-rules: true\\n"
  : mode === "id-only" && pack === "p/typescript"
  ? "rules:\\n  - id: missing-required-fields\\n"
  : mode === "empty-nextjs" && pack === "p/nextjs"
  ? "rules: []\\n"
  : mode === "bad-pattern-sixth" && pack === "p/security-audit"
  ? "rules:\\n  - id: malformed-pattern\\n    message: fixture\\n    severity: WARNING\\n    languages: [typescript]\\n    pattern: function (\\n"
  : "rules:\\n  - id: fixture-" + key + "\\n    message: fixture\\n    severity: WARNING\\n    languages: [typescript]\\n    pattern: $X\\n";
const outputIndex = args.indexOf("--output");
if (outputIndex >= 0) fs.writeFileSync(args[outputIndex + 1], body);
else process.stdout.write(body);
if (args.includes("--write-out")) process.stdout.write("200");
`);
  chmodSync(curl, 0o755);
  writeFileSync(semgrep, `#!/usr/bin/env node
const fs = require("node:fs");
const args = process.argv.slice(2);
if (args.join(" ") === "--version --disable-version-check") { process.stdout.write("1.173.0\\n"); process.exit(0); }
if (args[0] !== "scan" || !args.includes("--strict") || !args.includes("--json") || !args.includes("--disable-version-check") || args[args.indexOf("--metrics") + 1] !== "off") process.exit(91);
const target = args.at(-1);
if (fs.realpathSync(target) !== fs.realpathSync(process.cwd()) || fs.readdirSync(target).length !== 0) process.exit(93);
const files = args.flatMap((arg, index) => arg === "--config" ? [args[index + 1]] : []);
if (files.length !== 6) process.exit(92);
for (const file of files) {
  const body = fs.readFileSync(file, "utf8");
  if (!/^rules:/m.test(body)) process.exit(2);
  if (/rules:\\s*\\[\\s*\\]/m.test(body)) continue;
  for (const field of ["id", "message", "severity", "languages"]) {
    if (!new RegExp("^\\\\s*[- ]*" + field + ":", "m").test(body)) process.exit(2);
  }
  if (!/^\\s*(pattern|mode):/m.test(body)) process.exit(2);
  if (body.includes("pattern: function (")) process.exit(2);
}
process.stdout.write(JSON.stringify({ errors: [], paths: { scanned: [] }, skipped_rules: [] }));
`);
  chmodSync(semgrep, 0o755);
  return { bin, state };
}

function run(dir: string, fixtureRoot: { bin: string; state: string }, mode: string): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(process.execPath, ["--import", "tsx", CLI, "--dir", dir, "--out", join(dir, "receipt.json")], {
      cwd: ROOT,
      env: { ...process.env, PATH: `${fixtureRoot.bin}:${process.env.PATH ?? ""}`, FAKE_CURL_MODE: mode, FAKE_CURL_STATE: fixtureRoot.state },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "", stderr = "";
    child.stdout.setEncoding("utf8"); child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => { stdout += chunk; });
    child.stderr.on("data", (chunk: string) => { stderr += chunk; });
    child.on("error", rejectRun);
    child.on("close", (status) => resolveRun({ status, stdout, stderr }));
  });
}

async function runResponsive(dir: string, fixtureRoot: { bin: string; state: string }, mode: string) {
  let serviced = false;
  const heartbeat = new Promise<void>((resolveHeartbeat) => setImmediate(() => { serviced = true; resolveHeartbeat(); }));
  const result = await run(dir, fixtureRoot, mode);
  expect(serviced, "registry CLI child work must service the Vitest worker event loop").toBe(true);
  await heartbeat;
  return result;
}

function attempts(state: string, pack: string): number {
  const path = join(state, pack.replaceAll("/", "-"));
  return existsSync(path) ? Number(readFileSync(path, "utf8")) : 0;
}

function validate(dir: string, fixtureRoot: { bin: string; state: string }) {
  const previous = process.env.PATH;
  process.env.PATH = `${fixtureRoot.bin}:${previous ?? ""}`;
  try {
    return validateRestoredSemgrepPackArtifact(dir);
  } finally {
    process.env.PATH = previous;
  }
}

describe("current Semgrep registry materialization transport (#2171)", () => {
  it("keeps the six-pack retry budget within the prior six times 60 second bound", () => {
    expect(REGISTRY_PACK_FETCH_POLICY.perPackBudgetMs).toBe(60_000);
    expect(REGISTRY_PACK_FETCH_POLICY.perPackBudgetMs * REGISTRY_PACKS.length).toBe(360_000);
    expect(REGISTRY_PACK_FETCH_POLICY.validatorIdentityBudgetMs + REGISTRY_PACK_FETCH_POLICY.validationBudgetMs).toBe(30_000);
    expect(REGISTRY_PACK_FETCH_POLICY.maxResponseBytes).toBe(32 * 1024 * 1024);
    expect(REGISTRY_PACK_FETCH_POLICY.http403Attempts).toBeLessThan(REGISTRY_PACK_FETCH_POLICY.maxAttempts);
  });

  it("recovers one public-registry HTTP 403 and reports credential-free retry provenance", async () => {
    const f = fixture();
    const dir = join(temporary("harvey-registry-output-"), "registry");
    const result = await runResponsive(dir, f, "transient-403");
    expect(result.status, result.stderr).toBe(0);
    expect(attempts(f.state, "p/typescript")).toBe(2);
    for (const pack of REGISTRY_PACKS.slice(1)) expect(attempts(f.state, pack)).toBe(1);
    expect(result.stdout).toContain("p/typescript=2[http-403]");
    expect(`${result.stdout}\n${result.stderr}`).not.toContain("registry-secret");
    expect(validate(dir, f).files).toHaveLength(6);
  });

  it("uses the full transient HTTP retry budget before succeeding", async () => {
    const f = fixture();
    const dir = join(temporary("harvey-registry-output-"), "registry");
    const result = await runResponsive(dir, f, "transient-503");
    expect(result.status, result.stderr).toBe(0);
    expect(attempts(f.state, "p/typescript")).toBe(3);
    expect(result.stdout).toContain("p/typescript=3[http-503,http-503]");
    expect(validate(dir, f).files).toHaveLength(6);
  });

  it("retries a partial transport response and publishes only the complete retry", async () => {
    const f = fixture();
    const dir = join(temporary("harvey-registry-output-"), "registry");
    const result = await runResponsive(dir, f, "transient-partial");
    expect(result.status, result.stderr).toBe(0);
    expect(attempts(f.state, "p/typescript")).toBe(2);
    expect(result.stdout).toContain("p/typescript=2[curl-exit-18]");
    expect(`${result.stdout}\n${result.stderr}`).not.toContain("registry-secret");
    expect(validate(dir, f).files).toHaveLength(6);
  });

  it("exhausts the bounded retry budget for persistent partial responses", async () => {
    const f = fixture();
    const dir = join(temporary("harvey-registry-output-"), "registry");
    const result = await runResponsive(dir, f, "persistent-partial");
    expect(result.status).not.toBe(0);
    expect(attempts(f.state, "p/typescript")).toBe(3);
    expect(`${result.stdout}\n${result.stderr}`).toContain("curl-exit-18");
    expect(`${result.stdout}\n${result.stderr}`).not.toContain("registry-secret");
    expect(existsSync(join(dir, "receipt.json"))).toBe(false);
    expect(existsSync(join(dir, "registry-packs/current.json"))).toBe(false);
  });

  it("fails closed after the bounded HTTP 403 retry and invalidates stale bytes", async () => {
    const dir = join(temporary("harvey-registry-output-"), "registry");
    const seeded = fixture();
    expect((await runResponsive(dir, seeded, "success")).status).toBe(0);
    const producer = join(temporary("harvey-registry-producer-"), "registry");
    const replay = join(temporary("harvey-registry-replay-"), "registry");
    cpSync(dir, producer, { recursive: true });
    cpSync(dir, replay, { recursive: true });
    expect(validate(producer, seeded).identity).toBe(validate(replay, seeded).identity);

    const denied = fixture();
    const result = await runResponsive(dir, denied, "persistent-403");
    expect(result.status).not.toBe(0);
    expect(attempts(denied.state, "p/typescript")).toBe(2);
    expect(`${result.stdout}\n${result.stderr}`).toContain("http-403");
    expect(`${result.stdout}\n${result.stderr}`).not.toContain("registry-secret");
    expect(existsSync(join(dir, "receipt.json"))).toBe(false);
    expect(existsSync(join(dir, "registry-packs/current.json"))).toBe(false);
    expect(() => validateRestoredSemgrepPackArtifact(dir)).toThrow(/current\.json is missing|receipt\.json is missing/);
  });

  it("does not retry stable authentication failures", async () => {
    const f = fixture();
    const dir = join(temporary("harvey-registry-output-"), "registry");
    const result = await runResponsive(dir, f, "persistent-401");
    expect(result.status).not.toBe(0);
    expect(attempts(f.state, "p/typescript")).toBe(1);
    expect(`${result.stdout}\n${result.stderr}`).toContain("http-401");
  });

  it("rejects an invalid sixth config before publishing any usable receipt", async () => {
    const f = fixture();
    const dir = join(temporary("harvey-registry-output-"), "registry");
    const result = await runResponsive(dir, f, "invalid-sixth");
    expect(result.status).not.toBe(0);
    for (const pack of REGISTRY_PACKS) expect(attempts(f.state, pack)).toBe(1);
    expect(existsSync(join(dir, "receipt.json"))).toBe(false);
    expect(existsSync(join(dir, "registry-packs/current.json"))).toBe(false);
  });

  it("rejects id-only rules that Semgrep cannot load before publishing a receipt", async () => {
    const f = fixture();
    const dir = join(temporary("harvey-registry-output-"), "registry");
    const result = await runResponsive(dir, f, "id-only");
    expect(result.status).not.toBe(0);
    expect(`${result.stdout}\n${result.stderr}`).toContain("semgrep validator exited with code 2");
    expect(existsSync(join(dir, "receipt.json"))).toBe(false);
    expect(existsSync(join(dir, "registry-packs/current.json"))).toBe(false);
  });

  it("rejects a malformed pattern in the sixth config before publishing a receipt", async () => {
    const f = fixture();
    const dir = join(temporary("harvey-registry-output-"), "registry");
    const result = await runResponsive(dir, f, "bad-pattern-sixth");
    expect(result.status).not.toBe(0);
    expect(`${result.stdout}\n${result.stderr}`).toContain("semgrep validator exited with code 2");
    for (const pack of REGISTRY_PACKS) expect(attempts(f.state, pack)).toBe(1);
    expect(existsSync(join(dir, "receipt.json"))).toBe(false);
    expect(existsSync(join(dir, "registry-packs/current.json"))).toBe(false);
  });

  it("rejects a response above the restored 32 MiB cap without reading or publishing it", async () => {
    const f = fixture();
    const dir = join(temporary("harvey-registry-output-"), "registry");
    const result = await runResponsive(dir, f, "oversized");
    expect(result.status).not.toBe(0);
    expect(attempts(f.state, "p/typescript")).toBe(1);
    expect(`${result.stdout}\n${result.stderr}`).toContain("response-too-large");
    expect(existsSync(join(dir, "receipt.json"))).toBe(false);
    expect(existsSync(join(dir, "registry-packs/current.json"))).toBe(false);
  });

  it("preserves a valid empty registry pack in the complete six-file artifact", async () => {
    const f = fixture();
    const dir = join(temporary("harvey-registry-output-"), "registry");
    const result = await runResponsive(dir, f, "empty-nextjs");
    expect(result.status, result.stderr).toBe(0);
    expect(validate(dir, f).files).toHaveLength(6);
    const manifest = JSON.parse(readFileSync(join(dir, "registry-packs/current.json"), "utf8"));
    expect(readFileSync(join(dir, "registry-packs", manifest.identity, "2-p-nextjs.yml"), "utf8")).toBe("rules: []\n");
    expect(attempts(f.state, "p/nextjs")).toBe(1);
  });
});
