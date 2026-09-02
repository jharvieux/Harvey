// #1033 acceptance: "a gate that has never fired on a known-bad input is not evidence." These run
// the real CLI as a child process against a planted corpus — one reason whose falsifier now succeeds
// (the blocker is gone, the text still asserts it) and one malformed block — and assert the gate
// exits non-zero naming both.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = "src/cli/validate-reasons.ts";
const TSX_IMPORT = ["--import", join(REPO_ROOT, "node_modules/tsx/dist/loader.mjs")];
const POSITIVE_REGISTER = ["Verified", "live"].join(" ");

function plant(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "harvey-reasons-"));
  for (const [name, body] of Object.entries(files)) writeFileSync(join(dir, name), body);
  return dir;
}

type ChildResult = { code: number; out: string };

function run(command: string, args: string[], cwd = REPO_ROOT, env: NodeJS.ProcessEnv = {}): Promise<ChildResult> {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(command, args, { cwd, env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => (stdout += chunk));
    child.stderr.on("data", (chunk: string) => (stderr += chunk));
    child.once("error", rejectRun);
    child.once("close", (code) => resolveRun({ code: code ?? 1, out: `${stdout}${stderr}` }));
  });
}

async function runOk(command: string, args: string[], cwd = REPO_ROOT): Promise<string> {
  const result = await run(command, args, cwd);
  if (result.code !== 0) throw new Error(`${command} exited ${result.code}\n${result.out}`);
  return result.out;
}

const gate = (root: string, args: string[] = [], env: NodeJS.ProcessEnv = {}): Promise<ChildResult> => run(process.execPath, [...TSX_IMPORT, CLI, "--root", root, ...args], REPO_ROOT, env);

/** The per-block validation errors the gate printed, so a control can assert it tripped ONE rule. */
const errors = (out: string): string[] => [...out.matchAll(/^ *• (.*)$/gm)].map((m) => m[1] ?? "");

const STALE_REASON = [
  "// REASON: nothing in this repo can do the thing (planted; its falsifier succeeds)",
  "// KIND: empirical",
  "// PROVENANCE: ASSUMED 2026-07-25",
  "// FALSIFIER: true",
].join("\n");

const LIVE_REASON = [
  "// REASON: the blocker this one describes really is still standing",
  "// KIND: empirical",
  "// PROVENANCE: MEASURED 2026-07-25",
  "// FALSIFIER: false",
].join("\n");

// A supervised-path blocker correctly routed to a human — everything but the relay venue, which each
// control below supplies, so the DECISION: line is the only thing under test.
const RELAYED_REASON = [
  "// REASON: not wired up: .github/workflows/ is supervised and needs operator approval",
  "// KIND: decisional",
  "// PROVENANCE: MEASURED 2026-07-27",
  "// OWNER: operator",
].join("\n");

const DECISIONAL_REASON = [
  "REASON: out of scope pending an operator ruling",
  "KIND: decisional",
  "PROVENANCE: ASSUMED 2026-07-25",
  "OWNER: operator",
  "DECISION: docs/design/infrastructure-out-of-scope.md",
].join("\n");

// A live-only falsifier planted with `true` would go STALE if run — so it running offline would fail
// the gate. It must not: skipped-with-a-reason offline, executed only under --live (#1072).
const LIVE_TIER_REASON = [
  "// REASON: only a live Lighthouse pass can re-test this (planted; its falsifier would succeed if run)",
  "// KIND: empirical",
  "// PROVENANCE: MEASURED 2026-07-26",
  "// FALSIFIER: true",
  "// FALSIFIER-TIER: lighthouse",
].join("\n");

// The shape that made all five live falsifiers unfalsifiable until #1072's second half: `true <x>`
// would exit 0 (STALE) if the placeholder were bound, and exit 1 unrun — reading as "holds" — if it
// reached the shell verbatim. Which of those the gate reports is the whole point.
const PLACEHOLDER_REASON = [
  "// REASON: only a live Lighthouse pass can re-test this, against an operator-supplied target",
  "// KIND: empirical",
  "// PROVENANCE: MEASURED 2026-07-27",
  "// FALSIFIER: true <served-target>",
  "// FALSIFIER-TIER: lighthouse",
].join("\n");

describe("validate-reasons falsifier argv boundary (#1778)", () => {
  const SHELL_FIXTURE = `#!/usr/bin/env node
const fs = require("node:fs");
const runSync = require("node:child_process")["spawn" + "Sync"];
const args = process.argv.slice(2);
const receipt = { argv: args, program: process.env.HARVEY_RECORDED_FALSIFIER_PROGRAM, pid: process.pid };
fs.writeFileSync(process.env.HARVEY_SH_RECEIPT, JSON.stringify(receipt));
if (process.env.HARVEY_SH_MODE === "timeout") setInterval(() => {}, 1000);
else {
  const result = runSync("/bin/sh", args, { env: process.env, stdio: ["inherit", "pipe", "pipe"], encoding: "utf8", timeout: 2000 });
  fs.writeFileSync(process.env.HARVEY_SH_RECEIPT, JSON.stringify({ ...receipt, status: result.status, stdout: result.stdout, stderr: result.stderr }));
  process.stdout.write(result.stdout || ""); process.stderr.write(result.stderr || "");
  process.exit(result.status === null ? 127 : result.status);
}
`;
  interface ShellReceipt { argv: string[]; program?: string; pid: number; status?: number; stdout?: string; stderr?: string }
  async function falsifier(program: string, extraEnv: NodeJS.ProcessEnv = {}): Promise<ChildResult & { receipt?: ShellReceipt; requestedTimeout?: number }> {
    const dir = plant({ "reason.md": [
      "REASON: a controlled fixture still describes a blocker",
      "KIND: empirical", "PROVENANCE: MEASURED 2026-08-26",
      "FALSIFIER: :; <fixture-program>", "FALSIFIER-TIER: lighthouse",
    ].join("\n") });
    const bin = plant({ sh: SHELL_FIXTURE });
    chmodSync(join(bin, "sh"), 0o755);
    const receiptPath = join(bin, "shell.json");
    const timeoutPath = join(bin, "timeout.json");
    // Exercise the real spawnSync timeout with one bounded child, without waiting two minutes or
    // changing the production limit. No shell descendant is launched in this fixture mode.
    const preload = join(bin, "timeout.cjs");
    writeFileSync(preload, `const cp=require("node:child_process"); const original=cp.spawnSync; cp.spawnSync=function(bin,args,options){ if(bin==="sh"){require("node:fs").writeFileSync(${JSON.stringify(timeoutPath)},JSON.stringify(options.timeout)); options={...options,timeout:300};} return original(bin,args,options); }; require("node:module").syncBuiltinESMExports();`);
    try {
      const result = await gate(dir, ["--revalidate", "--tier", "lighthouse"], {
        ...extraEnv, PATH: `${bin}:${process.env.PATH ?? ""}`, HARVEY_SH_RECEIPT: receiptPath,
        HARVEY_FALSIFIER_FIXTURE_PROGRAM: program,
        ...(extraEnv.HARVEY_SH_MODE === "timeout" ? { NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ""} --require=${preload}` } : {}),
      });
      return { ...result, receipt: existsSync(receiptPath) ? JSON.parse(readFileSync(receiptPath, "utf8")) as ShellReceipt : undefined,
        requestedTimeout: existsSync(timeoutPath) ? JSON.parse(readFileSync(timeoutPath, "utf8")) as number : undefined };
    } finally {
      rmSync(dir, { recursive: true, force: true });
      rmSync(bin, { recursive: true, force: true });
    }
  }

  it("delivers the expanded opaque falsifier through environment without exposing its canary in shell argv", async () => {
    const canary = "harvey-falsifier-argv-canary-1778";
    const program = `printf '%s\\n' 'https://fixture-user:${canary}@example.invalid/path'; exit 0`;
    const result = await falsifier(program);
    expect(result.code).toBe(1);
    expect(result.out).toContain("STALE");
    expect(result.receipt?.program).toBe(`:; ${program}`);
    expect(result.receipt?.stdout).toContain(canary);
    expect(JSON.stringify(result.receipt?.argv)).not.toContain(canary);
  });

  it("preserves multiline heredocs, literal shell syntax and stdin EOF for falsifiers", async () => {
    const program = ["if read unexpected; then exit 90; fi", "value=$(cat <<'HARVEY_FIXTURE_EOF'", "literal 'quotes' \"$dollar\" `not-run` \\backslash", "line two", "HARVEY_FIXTURE_EOF", ")", "printf '%s\\n' \"$value\"", "printf 'positional:%s\\n' \"$#\"", "exit 0"].join("\n");
    const result = await falsifier(program);
    expect(result.code).toBe(1);
    expect(result.out).toContain("STALE");
    expect(result.receipt?.program).toBe(`:; ${program}`);
    expect(result.receipt?.stdout).toBe("literal 'quotes' \"$dollar\" `not-run` \\backslash\nline two\npositional:0\n");
    expect(result.receipt?.stderr).toBe("");
  });

  it.each([[7, 0, "no reason has outlived its truth"], [127, 1, "UNVERIFIABLE"]] as const)("preserves falsifier exit %i and its ordinary diagnostics", async (status, gateCode, diagnostic) => {
    const result = await falsifier(`printf 'ordinary diagnostic\\n' >&2; exit ${status}`);
    expect(result.code).toBe(gateCode);
    expect(result.out).toContain(diagnostic);
    expect(result.receipt?.status).toBe(status);
    expect(result.receipt?.stderr).toBe("ordinary diagnostic\n");
  });

  it("reports an actual bounded shell timeout as UNVERIFIABLE without leaving its child alive", async () => {
    const result = await falsifier("false", { HARVEY_SH_MODE: "timeout" });
    expect(result.requestedTimeout).toBe(120_000);
    expect(result.code).toBe(1);
    expect(result.out).toContain("UNVERIFIABLE");
    expect(result.out).toContain("signal/timeout");
    expect(result.receipt?.pid).toBeTypeOf("number");
    expect(() => process.kill(result.receipt!.pid, 0)).toThrow();
  });

  it("refuses a watched placeholder binding in the fixed shell argv before launching the child", async () => {
    const result = await falsifier("false", { HARVEY_FALSIFIER_WATCHED: 'eval "$HARVEY_RECORDED_FALSIFIER_PROGRAM"' });
    expect(result.code).toBe(1);
    expect(result.out).toContain("refusing to spawn");
    expect(result.receipt).toBeUndefined();
    expect(result.out).not.toContain("no reason has outlived its truth");
  });
});

describe("validate-reasons CLI", () => {
  it("skips a live-only falsifier offline — disclosed, not run, not a failure — and runs it under --live (#1072)", async () => {
    const dir = plant({ "live-tier.ts": LIVE_TIER_REASON });
    const offline = await gate(dir, ["--revalidate"]);
    expect(offline.code).toBe(0);
    expect(offline.out).toContain("SKIPPED-LIVE");
    expect(offline.out).toContain("live-only skipped");
    const live = await gate(dir, ["--revalidate", "--live"]);
    expect(live.code).toBe(1);
    expect(live.out).toContain("STALE");
  });

  it("refuses an unknown --tier rather than silently enabling nothing", async () => {
    const { code, out } = await gate(plant({ "live-tier.ts": LIVE_TIER_REASON }), ["--revalidate", "--tier", "made-up"]);
    expect(code).toBe(1);
    expect(out).toContain("unknown --tier");
  });

  it("fails loud on a planted reason whose falsifier now succeeds, and leaves the still-true one alone", async () => {
    const { code, out } = await gate(plant({ "stale.ts": STALE_REASON, "live.ts": LIVE_REASON }), ["--revalidate"]);
    expect(code).toBe(1);
    expect(out).toContain("STALE");
    expect(out).toContain("planted; its falsifier succeeds");
    expect(out).not.toContain("really is still standing");
  });

  it("passes when every falsifier still exits non-zero", async () => {
    const { code, out } = await gate(plant({ "live.ts": LIVE_REASON }), ["--revalidate"]);
    expect(code).toBe(0);
    expect(out).toContain("no reason has outlived its truth");
  });

  it("excludes decisional reasons from the re-validation pass instead of re-testing a human ruling", async () => {
    const { code, out } = await gate(plant({ "d.md": DECISIONAL_REASON }), ["--revalidate"]);
    expect(code).toBe(0);
    expect(out).toContain("Re-validated 0 empirical falsifier(s); 0 live-only skipped; 1 decisional reason(s) excluded by kind");
  });

  it("reports an unbound live-tier placeholder UNVERIFIABLE instead of letting the shell eat it as a redirect (#1072)", async () => {
    const dir = plant({ "placeholder.ts": PLACEHOLDER_REASON });
    const unbound = await gate(dir, ["--revalidate", "--tier", "lighthouse"]);
    expect(unbound.code).toBe(1);
    expect(unbound.out).toContain("UNVERIFIABLE");
    expect(unbound.out).toContain("HARVEY_FALSIFIER_SERVED_TARGET");

    const bound = await gate(dir, ["--revalidate", "--tier", "lighthouse"], { HARVEY_FALSIFIER_SERVED_TARGET: "/dev/null" });
    expect(bound.code).toBe(1);
    expect(bound.out).toContain("STALE");
    expect(bound.out).toContain("true /dev/null");
  });

  it("fails structurally — with no command run — on an empirical reason carrying no falsifier", async () => {
    const { code, out } = await gate(plant({ "bad.md": STALE_REASON.split("\n").slice(0, 3).join("\n").replace(/\/\/ /g, "") }));
    expect(code).toBe(1);
    expect(out).toContain("unfalsifiable and therefore permanent");
  });

  it("fails on a TOUCHES: path that is not in the checkout — a typo makes drift silent forever (#1246)", async () => {
    const { code, out } = await gate(plant({ "typo.ts": `${LIVE_REASON}\n// TOUCHES: src/detectors/no-such-file.ts` }));
    expect(code).toBe(1);
    expect(out).toContain("is not a path in this checkout");
  });

  // Silence from a reason with nothing to watch looks exactly like silence from a quiet subsystem,
  // so the two are separated in the output rather than left to be inferred (#1246).
  it("counts the empirical reasons subsystem drift can and cannot watch", async () => {
    const { code, out } = await gate(plant({ "unwatched.ts": LIVE_REASON }));
    expect(code).toBe(0);
    expect(out).toContain("Subsystem drift watches 0/1 empirical reason(s)");
  });

  // #1319's rules reach the CLI, not just validateRecordedReason: the planted violations below must
  // take the real gate to a non-zero exit, or the rules are unit-tested prose. Each asserts EXACTLY
  // ONE error — a control that trips two rules at once no longer proves the rule it is named for.
  it("fails on impossibility vocabulary spent over an ASSUMED provenance (#1319)", async () => {
    const planted = STALE_REASON.replace("can do the thing", "is out of reach").replace("FALSIFIER: true", "FALSIFIER: false");
    const { code, out } = await gate(plant({ "budget.ts": planted }));
    expect(code).toBe(1);
    expect(errors(out)).toEqual([expect.stringContaining('says "out of reach" on an ASSUMED provenance')]);
  });

  it("fails on a supervised-path blocker recorded as empirical rather than relayed (#1319)", async () => {
    const planted = LIVE_REASON.replace("the blocker this one describes really is still standing", "not wired up: .github/workflows/ is supervised and needs operator approval");
    const { code, out } = await gate(plant({ "supervised.ts": planted }));
    expect(code).toBe(1);
    expect(errors(out)).toEqual([expect.stringContaining("produces a RELAY, never a silent stop")]);
  });

  it("fails when a package.json authorization blocker is recorded as empirical (#2018)", async () => {
    const planted = LIVE_REASON.replace("the blocker this one describes really is still standing", "package.json is sensitive and requires operator approval");
    const { code, out } = await gate(plant({ "dependency-policy.ts": planted }));
    expect(code).toBe(1);
    expect(errors(out)).toEqual([expect.stringContaining("produces a RELAY, never a silent stop")]);
  });

  it("passes the package.json blocker once it is relayed to a findable venue (#2018)", async () => {
    const planted = [
      "// REASON: package.json is sensitive and requires operator approval",
      "// KIND: decisional",
      "// PROVENANCE: MEASURED 2026-09-02",
      "// OWNER: operator",
      "// DECISION: #2018",
    ].join("\n");
    const { code, out } = await gate(plant({ "dependency-relay.ts": planted }));
    expect(errors(out)).toEqual([]);
    expect(code).toBe(0);
  });

  // The venue rule shipped as /#\d+|\//, where any slash satisfied it. A relay with no findable venue
  // is the silent close wearing a field name, so a bare "go/no-go" must not buy one.
  it("fails on a supervised-path relay whose DECISION names no findable venue (#1319)", async () => {
    const planted = [RELAYED_REASON, "// DECISION: pending a go/no-go"].join("\n");
    const { code, out } = await gate(plant({ "no-venue.ts": planted }));
    expect(code).toBe(1);
    expect(errors(out)).toEqual([expect.stringContaining("names no venue for a supervised-path blocker")]);
  });

  it("passes the same relay once the DECISION points at the issue or the decision record (#1319)", async () => {
    for (const venue of ["#1319", "docs/design/recorded-reasons.md"]) {
      const { code, out } = await gate(plant({ "relay.ts": [RELAYED_REASON, `// DECISION: ${venue}`].join("\n") }));
      expect(errors(out)).toEqual([]);
      expect(code).toBe(0);
    }
  });

  // The negative control for the supervised-path rule's precision: this reason CITES a supervised
  // path as the record of a ruling rather than naming it as the blocker, and both vocabularies are
  // present one clause apart. Refusing it would be the gate crying wolf on a legitimate reason.
  it("passes an empirical reason that merely cites a supervised path as its reference (#1319)", async () => {
    const planted = LIVE_REASON.replace(
      "the blocker this one describes really is still standing",
      "the source loader does not read .svelte files; the scope rationale and the operator ruling behind it are recorded in docs/design/infrastructure-out-of-scope.md",
    );
    const { code, out } = await gate(plant({ "cites.ts": planted }));
    expect(errors(out)).toEqual([]);
    expect(code).toBe(0);
  });

  it("passes a measured reason that merely cites package.json (#2018)", async () => {
    const planted = LIVE_REASON.replace(
      "the blocker this one describes really is still standing",
      "the measured resolver reads package.json; the operator approval policy is recorded in AGENTS.md",
    );
    const { code, out } = await gate(plant({ "dependency-citation.ts": planted }));
    expect(errors(out)).toEqual([]);
    expect(code).toBe(0);
  });

  it("counts claim-shaped prose outside every block instead of reading well-formed as complete (#1246)", async () => {
    const { code, out } = await gate(plant({ "prose.md": "Harvey cannot analyse Elixir today.\n" }), ["--census"]);
    expect(code).toBe(0);
    expect(out).toContain("Untriaged claim-shaped lines");
    expect(out).toContain("prose.md:1  Harvey cannot analyse Elixir today.");
  });

  // #1347 — the census read `.md` only until 2026-07-28, so a claim written as a source comment
  // moved nothing. Through the CLI end-to-end, and paired with the code line beside it: a widening
  // to whole-file `.ts` would light the second one, which is ordinary code prose.
  it("censuses a claim in a .ts COMMENT and not the code line under it (#1347)", async () => {
    const src = '// Harvey cannot analyse Elixir today.\nthrow new Error("cannot parse");\n';
    const { code, out } = await gate(plant({ "loader.ts": src }), ["--census"]);
    expect(code).toBe(0);
    expect(out).toContain("loader.ts:1  // Harvey cannot analyse Elixir today.");
    expect(out).not.toContain("loader.ts:2");
  });

  it("derives every disclosed census metric from each shipping CLI population (#1410)", async () => {
    const populationA = plant({
      "a.md": `${POSITIVE_REGISTER} against fixture A.\n`,
      "a.ts": `// ${POSITIVE_REGISTER} in a source comment.\nthrow new Error("${POSITIVE_REGISTER} in code");\n`,
    });
    const populationB = plant({
      "b.md": `${POSITIVE_REGISTER} against fixture B.\n${POSITIVE_REGISTER} against fixture C.\n`,
      "extra.md": "Ordinary prose still belongs to the examined population.\n",
      "b.ts": `// ${POSITIVE_REGISTER} in another source comment.\nthrow new Error("${POSITIVE_REGISTER} in code");\nthrow new Error("${POSITIVE_REGISTER} in more code");\n`,
      "extra.sql": "-- Ordinary source comments also belong to the examined population.\n",
    });

    const [a, b, generated] = await Promise.all([
      gate(populationA, ["--census"]),
      gate(populationB, ["--census"]),
      gate("src/unstructured-claims-baseline.ts", ["--census"]),
    ]);
    expect(a.code).toBe(0);
    expect(b.code).toBe(0);
    expect(generated.code).toBe(0);
    expect(a.out).toContain("Untriaged claim-shaped lines (advisory, LOWER BOUND — a fixed vocabulary): 2");
    expect(b.out).toContain("Untriaged claim-shaped lines (advisory, LOWER BOUND — a fixed vocabulary): 3");
    expect(a.out).toContain("CENSUSED WHOLE: 1 prose surface(s)");
    expect(b.out).toContain("CENSUSED WHOLE: 2 prose surface(s)");
    expect(a.out).toContain("CENSUSED COMMENTS ONLY: 1 .ts/.yml/.sql surface(s)");
    expect(b.out).toContain("CENSUSED COMMENTS ONLY: 2 .ts/.yml/.sql surface(s)");
    expect(a.out).toContain("NOT CENSUSED: 0 file(s)");
    expect(generated.out).toContain("NOT CENSUSED: 1 file(s)");
    expect(generated.out).toContain("CENSUSED WHOLE: 0 prose surface(s)");
    expect(generated.out).toContain("CENSUSED COMMENTS ONLY: 0 .ts/.yml/.sql surface(s)");
    expect(generated.out).toContain("0 matching code line(s) were excluded");
    expect(generated.out).toContain("0 accepted row(s) use that phrase");
    expect(a.out).toContain("1 matching code line(s) were excluded");
    expect(b.out).toContain("2 matching code line(s) were excluded");
    expect(a.out).toContain("2 accepted row(s) use that phrase");
    expect(b.out).toContain("3 accepted row(s) use that phrase");
  });

  it("reads every open-issue and comment page in the disclosed prose population without calling them repository files", async () => {
    const dir = plant({ "source.md": `${POSITIVE_REGISTER} in repository prose.\n` });
    const bin = plant({
      gh: `#!/usr/bin/env node
const args = process.argv.slice(2);
const query = args.find((arg) => arg.startsWith("query=")) ?? "";
const send = (value) => process.stdout.write(JSON.stringify(value));
if (args[0] === "repo") process.stdout.write("jharvieux/Harvey\\n");
else if (query.includes("issues(first:100")) {
  if (args.includes("after=issue-page-1")) send({ data: { repository: { issues: {
    pageInfo: { hasNextPage: false, endCursor: null },
    nodes: [{ number: 1412, body: "${POSITIVE_REGISTER} in the second issue page. " + "x".repeat(1024 * 1024 + 1), comments: { totalCount: 0, pageInfo: { hasNextPage: false, endCursor: null }, nodes: [] } }],
  } } } });
  else send({ data: { repository: { issues: {
    pageInfo: { hasNextPage: true, endCursor: "issue-page-1" },
    nodes: [
      { number: 1410, body: "${POSITIVE_REGISTER} in the first issue page.", comments: { totalCount: 1, pageInfo: { hasNextPage: false, endCursor: null }, nodes: [{ body: "An ordinary comment." }] } },
      { number: 1411, body: "An ordinary issue body.", comments: { totalCount: 2, pageInfo: { hasNextPage: true, endCursor: "comment-page-1" }, nodes: [{ body: "An ordinary first comment." }] } },
    ],
  } } } });
} else if (query.includes("issue(number:$number)")) send({ data: { repository: { issue: { comments: {
  totalCount: 2, pageInfo: { hasNextPage: false, endCursor: null }, nodes: [{ body: "${POSITIVE_REGISTER} in the second comment page." }],
} } } } });
else process.exitCode = 9;
`,
    });
    chmodSync(join(bin, "gh"), 0o755);
    try {
      const { code, out } = await gate(dir, ["--census", "--issues"], { PATH: `${bin}:${process.env.PATH ?? ""}` });
      expect(code).toBe(0);
      expect(out).toContain(`CENSUSED WHOLE: 7 prose surface(s) across ${dir} and 6 open-issue body/comment surface(s)`);
      expect(out).toContain("4 accepted row(s) use that phrase");
      expect(out).toContain(`issue #1410:1  ${POSITIVE_REGISTER} in the first issue page.`);
      expect(out).toContain(`issue #1411 (comment 2):1  ${POSITIVE_REGISTER} in the second comment page.`);
      expect(out).toContain(`issue #1412:1  ${POSITIVE_REGISTER} in the second issue page.`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
      rmSync(bin, { recursive: true, force: true });
    }
  });

  it("reports a tracker child signal as a signal, not a guessed authentication failure", async () => {
    const dir = plant({ "source.md": "Ordinary prose.\n" });
    const bin = plant({
      gh: `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === "repo") process.stdout.write("jharvieux/Harvey\\n");
else { process.stderr.write("credential expired\\n"); process.kill(process.pid, "SIGTERM"); }
`,
    });
    chmodSync(join(bin, "gh"), 0o755);
    try {
      const { code, out } = await gate(dir, ["--issues"], { PATH: `${bin}:${process.env.PATH ?? ""}` });
      expect(code).toBe(1);
      expect(out).toContain("was terminated by signal SIGTERM");
      expect(out).toContain("credential expired");
      expect(out).not.toContain("needs an authenticated gh");
    } finally {
      rmSync(dir, { recursive: true, force: true });
      rmSync(bin, { recursive: true, force: true });
    }
  });

  it("names a null tracker response instead of throwing a generic TypeError", async () => {
    const dir = plant({ "source.md": "Ordinary prose.\n" });
    const bin = plant({
      gh: `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === "repo") process.stdout.write("jharvieux/Harvey\\n");
else process.stdout.write("null");
`,
    });
    chmodSync(join(bin, "gh"), 0o755);
    try {
      const { code, out } = await gate(dir, ["--issues"], { PATH: `${bin}:${process.env.PATH ?? ""}` });
      expect(code).toBe(1);
      expect(out).toContain("open-issue query returned no top-level response object");
      expect(out).not.toContain("TypeError");
    } finally {
      rmSync(dir, { recursive: true, force: true });
      rmSync(bin, { recursive: true, force: true });
    }
  });

  it("refuses repeated issue and comment cursors rather than silently looping or truncating", async () => {
    const dir = plant({ "source.md": "Ordinary prose.\n" });
    const bin = plant({
      gh: `#!/usr/bin/env node
const args = process.argv.slice(2);
const query = args.find((arg) => arg.startsWith("query=")) ?? "";
const send = (value) => process.stdout.write(JSON.stringify(value));
if (args[0] === "repo") process.stdout.write("jharvieux/Harvey\\n");
else if (query.includes("issues(first:100")) {
  const comments = process.env.REPEAT_KIND === "comments"
    ? { totalCount: 3, pageInfo: { hasNextPage: true, endCursor: "repeat" }, nodes: [{ body: "one" }] }
    : { totalCount: 0, pageInfo: { hasNextPage: false, endCursor: null }, nodes: [] };
  const pageInfo = process.env.REPEAT_KIND === "comments" ? { hasNextPage: false, endCursor: null } : { hasNextPage: true, endCursor: "repeat" };
  send({ data: { repository: { issues: { pageInfo, nodes: [{ number: 1410, body: "body", comments }] } } } });
} else if (query.includes("issue(number:$number)")) send({ data: { repository: { issue: { comments: {
  totalCount: 3, pageInfo: { hasNextPage: true, endCursor: "repeat" }, nodes: [{ body: "two" }],
} } } } });
else process.exitCode = 9;
`,
    });
    chmodSync(join(bin, "gh"), 0o755);
    try {
      for (const [repeat, message] of [["issues", "open-issue query repeated a page cursor"], ["comments", "issue #1410 repeated a comment-page cursor"]]) {
        const { code, out } = await gate(dir, ["--issues"], { PATH: `${bin}:${process.env.PATH ?? ""}`, REPEAT_KIND: repeat });
        expect(code).toBe(1);
        expect(out).toContain(message);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
      rmSync(bin, { recursive: true, force: true });
    }
  });

  it("does not execute a falsifier fetched from an untrusted issue body", async () => {
    const dir = plant({ "source.md": "Ordinary prose.\n" });
    const marker = join(dir, "untrusted-falsifier-ran");
    const bin = plant({
      gh: `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === "repo") process.stdout.write("jharvieux/Harvey\\n");
else process.stdout.write(JSON.stringify({ data: { repository: { issues: {
  pageInfo: { hasNextPage: false, endCursor: null },
  nodes: [{ number: 1410, body: "REASON: untrusted issue input\\nKIND: empirical\\nPROVENANCE: MEASURED 2026-08-25\\nFALSIFIER: touch ${marker}", comments: { totalCount: 0, pageInfo: { hasNextPage: false, endCursor: null }, nodes: [] } }],
} } } }));
`,
    });
    chmodSync(join(bin, "gh"), 0o755);
    try {
      const { code, out } = await gate(dir, ["--issues", "--revalidate"], { PATH: `${bin}:${process.env.PATH ?? ""}` });
      expect(code).toBe(0);
      expect(out).toContain("NOT RE-TESTED  issue #1410:1");
      expect(existsSync(marker)).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
      rmSync(bin, { recursive: true, force: true });
    }
  });
});

// #1616 — the RATCHET path, which every test above skips by construction. `--root` narrows the
// census to a caller-chosen surface, and the ratchet declines to score a narrowed run (it would
// compare two different populations against a baseline written for DEFAULT_ROOTS). So the two
// `spawnSync` helpers that feed `attributeClaim` in that path — `blameLine` and `branchCommits`
// (#1401) — were reachable by no test at all: MEASURED 2026-07-31 by the acceptance verifier on
// PR #1613, stubbing `blameLine` to `return undefined` left `vitest run src/recorded-reasons.test.ts
// src/cli/validate-reasons.test.ts` at 88 passed. Every attributed row would have silently degraded
// to "provenance unavailable" — the #1407 shape, a library-level test with the CLI's own call site
// unproven.
//
// The fixture is a SELF-CONTAINED git repo, not a worktree of this one, and that is the load-bearing
// choice: attribution is a question about the commit range between HEAD and the base branch, so
// borrowing this checkout's history would make the answer depend on how CI cloned it — `attributeClaim`
// itself degrades to "no commit range" on a depth-1 checkout. A fresh `git init` over every tracked file
// gives full fidelity (every path a TOUCHES: line names exists, so the structural pass is clean) with
// a history the test writes itself.
//
// It copies the WORKING TREE (`git ls-files` piped through tar), not `git archive HEAD`. The archive
// form was written first and is wrong in a way that hides: it exports the COMMITTED tree, so an
// uncommitted edit to validate-reasons.ts is invisible to the fixture and the negative control below
// passed with the helper stubbed out. In CI the checkout is the commit under review either way, which
// is exactly what makes that a silent hole rather than a loud one.
describe("the claim ratchet's provenance attribution, through the real CLI (#1616)", () => {
  const PLANT = "src/planted-claim.ts";
  const CLAIM = "// A planted census line: this shape cannot be attributed without a blame lookup.";
  let fixture: string;

  const git = (...args: string[]): Promise<string> => runOk("git", ["-c", "user.email=t@example.com", "-c", "user.name=Test", "-c", "commit.gpgsign=false", ...args], fixture);

  /** The real CLI over the fixture as its OWN repo root — no `--root`, so the ratchet scores. */
  const ratchet = (): Promise<ChildResult> => run(process.execPath, [...TSX_IMPORT, join(fixture, CLI)]);

  /** The `↳` line the CLI prints under the planted row — the whole point of the attribution. */
  const attribution = (out: string): string => out.split("\n").find((l) => l.includes("↳"))?.trim() ?? "(no attribution line printed)";

  beforeAll(async () => {
    fixture = mkdtempSync(join(tmpdir(), "harvey-ratchet-"));
    await runOk("sh", ["-c", `git ls-files -z | tar --null -T - -cf - | tar -x -C '${fixture}'`]);
    // The fixture is a copy of the TRACKED tree only, so it has no node_modules. The CLI resolves
    // its imports relative to its own path, so anything it pulls in from a package must resolve
    // inside the fixture. node_modules is untracked, so the tar leaves it out; symlink the real one
    // in. This broke `main` once already (2026-07-31), when #1732 gave src/scored-gates.ts a
    // `yaml` import that this CLI transitively loads.
    symlinkSync(join(REPO_ROOT, "node_modules"), join(fixture, "node_modules"), "dir");
    await git("init", "-q", "-b", "main");
    await git("add", "-A");
    await git("commit", "-q", "-m", "fixture base");
    // Rebuild the baseline from the fixture itself, so the ONLY breach below is the planted line
    // whatever state this checkout's committed baseline happens to be in.
    await runOk(process.execPath, [...TSX_IMPORT, join(fixture, CLI), "--update-baseline"]);
    await git("add", "-A");
    await git("commit", "-q", "--allow-empty", "-m", "fixture baseline");
  }, 120_000);

  afterAll(() => {
    if (fixture) rmSync(fixture, { recursive: true, force: true });
  });

  it("scores clean with nothing planted — so a breach below is the plant, not the fixture", async () => {
    const { code, out } = await ratchet();
    // Prefix only, NOT the full banner: #1732 renamed it to `Ratchet (#1318/#1399/#1685)` and the
    // original assertion's closing paren made it stop matching. That broke `main` (2026-07-31)
    // together with the node_modules symlink above — two independent interactions from one merge
    // pair, neither PR wrong alone. Assert the part that identifies the SCORED branch (the not-run
    // branch prints `Ratchet (#1318): not scored`) and let the issue list grow.
    expect(out).toContain("Ratchet (#1318/");
    expect(out).not.toContain("CLAIM RATCHET");
    expect(code).toBe(0);
  });

  it("says AUTHORED on this branch when the breaching line's commit is in the branch range", async () => {
    await git("checkout", "-q", "-b", "feature/planted");
    writeFileSync(join(fixture, PLANT), `${CLAIM}\n`);
    await git("add", "-A");
    await git("commit", "-q", "-m", "plant a claim line");
    const sha = (await git("rev-parse", "--short", "HEAD")).trim();

    const { code, out } = await ratchet();
    expect(code).toBe(1);
    expect(out).toContain(`NEW  ${PLANT}:1  ${CLAIM}`);
    // Both helpers had to work: branchCommits() to produce a range at all, blameLine() to name the
    // commit. The sha proves the blame lookup ran rather than defaulting.
    expect(attribution(out)).toBe(`↳ AUTHORED on this branch by ${sha} plant a claim line`);
    expect(out).toContain("1 row(s) AUTHORED on this branch, 0 INHERITED from the base branch, 0 unattributable.");
  });

  it("says INHERITED for the SAME line once its commit is reachable from the base branch", async () => {
    await git("checkout", "-q", "main");
    await git("merge", "-q", "--ff-only", "feature/planted");
    const sha = (await git("rev-parse", "--short", "HEAD")).trim();

    const { code, out } = await ratchet();
    expect(code).toBe(1);
    // Same file, same line, same blame sha — only the RANGE moved, so this verdict and the one above
    // pin down both helpers together. MEASURED 2026-07-31 by stubbing each in turn: `blameLine`
    // returning undefined reddens both, and a `branchCommits` returning an empty set unconditionally
    // reddens the AUTHORED one while leaving this one green.
    expect(attribution(out)).toBe(`↳ INHERITED — already on the base branch by ${sha} plant a claim line`);
    expect(out).toContain("0 row(s) AUTHORED on this branch, 1 INHERITED from the base branch, 0 unattributable.");
  });

  it("says provenance unavailable, naming the blame, when the breaching line is not committed yet", async () => {
    await git("checkout", "-q", "-b", "feature/uncommitted");
    await git("rm", "-q", "--cached", PLANT);
    await git("commit", "-q", "-m", "untrack the planted line");

    const { code, out } = await ratchet();
    expect(code).toBe(1);
    // blameLine's OWN failing direction: `git blame` exits non-zero on an untracked path, so the
    // helper returns undefined and the CLI states that rather than guessing an author.
    expect(attribution(out)).toBe(`↳ provenance unavailable: git blame could not read ${PLANT}:1 — an uncommitted line has no commit yet`);
    expect(out).toContain("0 row(s) AUTHORED on this branch, 0 INHERITED from the base branch, 1 unattributable.");
  });

  it("says provenance unavailable, naming the missing range, when no base branch resolves", async () => {
    await git("checkout", "-q", "--detach");
    await git("branch", "-q", "-D", "main");
    await git("branch", "-q", "-D", "feature/planted");
    await git("branch", "-q", "-D", "feature/uncommitted");
    writeFileSync(join(fixture, PLANT), `${CLAIM}\n`);

    const { code, out } = await ratchet();
    expect(code).toBe(1);
    // branchCommits' OWN failing direction, and it needs its own control: neither `origin/main` nor
    // `main` resolves, so `git merge-base` fails for both and the helper returns undefined BEFORE
    // blameLine is consulted. It is the shallow-CI-checkout case the CLI degrades to on purpose.
    expect(attribution(out)).toContain("↳ provenance unavailable: no commit range against the base branch");
    expect(out).toContain("0 row(s) AUTHORED on this branch, 0 INHERITED from the base branch, 1 unattributable.");
  });

  async function driftFixture(localBody: string, issueBody = "", comments: string[] = []): Promise<ChildResult & { calls: { argv: string[]; input?: string; status: number; stdout: string }[] }> {
    const root = plant({ "reason.md": localBody });
    const bin = plant({
      "observe.cjs": `const cp=require("node:child_process"), fs=require("node:fs"); const original=cp.spawnSync;
cp.spawnSync=function(file,args,options){const result=original(file,args,options); if(file==="git" && args[0]==="log" && args.some(a=>a.startsWith("--since="))) fs.appendFileSync(process.env.HARVEY_DRIFT_RECEIPT,JSON.stringify({argv:args,input:options.input,status:result.status,stdout:result.stdout})+"\\n"); return result;}; require("node:module").syncBuiltinESMExports();`,
      "issue.json": JSON.stringify({ data: { repository: { issues: { pageInfo: { hasNextPage: false, endCursor: null }, nodes: [{ number: 1778, body: issueBody,
        comments: { totalCount: comments.length, pageInfo: { hasNextPage: false, endCursor: null }, nodes: comments.map((body) => ({ body })) } }] } } } }),
      gh: `#!/usr/bin/env node
if(process.argv[2]==="repo") process.stdout.write("fixture/reasons\\n");
else process.stdout.write(require("node:fs").readFileSync(process.env.HARVEY_DRIFT_ISSUE,"utf8"));`,
    });
    chmodSync(join(bin, "gh"), 0o755);
    const receipt = join(bin, "calls.jsonl");
    try {
      const result = await run(process.execPath, [...TSX_IMPORT, join(fixture, CLI), "--root", root, ...(issueBody ? ["--issues"] : [])], REPO_ROOT, {
        PATH: `${bin}:${process.env.PATH ?? ""}`, HARVEY_DRIFT_RECEIPT: receipt, HARVEY_DRIFT_ISSUE: join(bin, "issue.json"),
        NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ""} --require=${join(bin, "observe.cjs")}`,
      });
      return { ...result, calls: existsSync(receipt) ? readFileSync(receipt, "utf8").trim().split("\n").map((line) => JSON.parse(line)) : [] };
    } finally {
      rmSync(root, { recursive: true, force: true });
      rmSync(bin, { recursive: true, force: true });
    }
  }

  it("keeps file and issue TOUCHES out of git argv while preserving native path history (#1778)", async () => {
    const canary = "harvey-touches-argv-canary-1778";
    const paths = [`src/${canary}-é.ts`, `"${canary}-\\quote.ts`, `--${canary}.ts`];
    for (const path of paths) {
      writeFileSync(join(fixture, path), "export const fixtureValue = 1;\n");
      await git("add", "--", path);
      await git("commit", "-q", "-m", "add a path-history fixture");
    }
    writeFileSync(join(fixture, paths[0]!), "export const fixtureValue = 2;\n");
    await git("add", "--", paths[0]!);
    await git("commit", "-q", "-m", "move one path-history fixture");
    const expected = await Promise.all(paths.map((path) => git("log", "--since=2020-01-01 23:59:59", "--format=%h", "--", path)));
    expect(new Set(expected).size).toBe(3);
    const empirical = (path: string): string => `REASON: controlled path-history observation\nKIND: empirical\nPROVENANCE: MEASURED 2020-01-01\nFALSIFIER: false\nTOUCHES: ${path}`;
    const decisional = empirical(paths[1]!).replace("KIND: empirical", "KIND: decisional").replace("FALSIFIER: false", "OWNER: operator\nDECISION: issue #1778");
    const malformed = empirical(paths[2]!).replace("FALSIFIER: false\n", "");
    const result = await driftFixture([empirical(paths[0]!), decisional, malformed].join("\n\n"), empirical(paths[0]!), [decisional, malformed]);
    expect(result.code).toBe(1);
    expect(result.out).toContain("2 malformed reason block(s)");
    expect(result.out.match(/SUBSYSTEM MOVED/g)).toHaveLength(6);
    expect(result.calls).toHaveLength(6);
    expect(result.calls.map((call) => call.stdout)).toEqual([...expected, ...expected]);
    for (const call of result.calls) {
      expect(call.status).toBe(0);
      expect(JSON.stringify(call.argv)).not.toContain(canary);
      expect(call.argv).toEqual(["log", "--since=2020-01-01 23:59:59", "--format=%h", "--stdin"]);
      expect(call.input).toMatch(/^--\n.+\n$/s);
    }
  });

  it.each(["--format=%h", "invalid\0path"])("refuses untransportable or argv-colliding TOUCHES before git: %s", async (path) => {
    const result = await driftFixture(`REASON: controlled path-history observation\nKIND: empirical\nPROVENANCE: MEASURED 2020-01-01\nFALSIFIER: false\nTOUCHES: ${path}`);
    expect(result.code).toBe(1);
    expect(result.out).toContain("refusing");
    expect(result.calls).toEqual([]);
  });
});
