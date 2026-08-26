import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { SecretInArgvError } from "../secret-argv.js";
import { buildVerificationEvidence, extractCiRunSteps, runBaseline } from "./verify-harness.js";
import { computeGreen, detectorHalfClean, discoverVerifyCommands, observedClientCommandConcurrency, runCommand, scrubSecrets, type CommandRun, type DetectorRun } from "./verify.js";

// Observe the real child's resolved shell argv, not merely the argument handed to Node's wrapper.
vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return { ...actual, spawn: vi.fn(actual.spawn) };
});

beforeEach(() => {
  vi.mocked(spawn).mockClear();
});
afterEach(() => {
  vi.unstubAllEnvs();
});

const node = process.execPath;

describe("discoverVerifyCommands", () => {
  it("prefers a single verify script over everything else", () => {
    expect(discoverVerifyCommands({ verify: "x", typecheck: "y", test: "z" })).toEqual(["pnpm run verify"]);
  });

  it("falls back to the typecheck/lint/test union when there is no verify/check/ci", () => {
    expect(discoverVerifyCommands({ typecheck: "x", lint: "y", test: "z" })).toEqual([
      "pnpm run typecheck",
      "pnpm run lint",
      "pnpm run test",
    ]);
  });

  it("appends CI-only steps that the scripts don't already cover", () => {
    expect(discoverVerifyCommands({ verify: "x" }, "pnpm", ["pnpm knip", "pnpm run verify"])).toEqual([
      "pnpm run verify",
      "pnpm knip",
    ]);
  });

  it("returns nothing when there are no scripts at all", () => {
    expect(discoverVerifyCommands(undefined)).toEqual([]);
  });
});

describe("runCommand", () => {
  it("captures a real exit code and output — it never trusts a claim of green", async () => {
    const ok = await runCommand(`${node} -e "console.log('built ok')"`, process.cwd());
    expect(ok.exitCode).toBe(0);
    expect(ok.outputTail).toContain("built ok");
    // `>= 0` has no failing direction: every unsigned elapsed time satisfies it, and so does a hardcoded 0.
    // Spawning a node process is never free, so `> 0` is the form that goes red if `durationMs`
    // ever stops being a measurement (#1674).
    expect(ok.durationMs).toBeGreaterThan(0);

    const bad = await runCommand(`${node} -e "process.exit(3)"`, process.cwd());
    expect(bad.exitCode).toBe(3);
  });

  it("keeps discovered multiline workflow programs in the environment through baseline and fixed checks", async () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "harvey-command-transport-")));
    const workflows = join(dir, ".github/workflows");
    const literal = 'synthetic-client-value-1778: quotes \' " $(printf forbidden-expansion) `printf forbidden-backtick` $PATH \\';
    const command = [
      "cat <<'HARVEY_COMMAND_EOF'",
      literal,
      "HARVEY_COMMAND_EOF",
      'printf "cwd=%s\\n" "$PWD"',
      'printf "parent=%s\\n" "$HARVEY_CLIENT_TEST_PARENT"',
    ].join("\n");
    vi.stubEnv("HARVEY_CLIENT_TEST_PARENT", "inherited-parent-value");
    vi.stubEnv("HARVEY_CLIENT_VERIFY_COMMAND", "stale-parent-program-must-not-run");
    mkdirSync(workflows, { recursive: true });
    writeFileSync(join(workflows, "verify.yml"), [
      "on: pull_request",
      "jobs:",
      "  verify:",
      "    steps:",
      "      - run: |",
      ...command.split("\n").map((line) => `          ${line}`),
      "",
    ].join("\n"));
    try {
      const commands = extractCiRunSteps(workflows);
      expect(commands).toEqual([{ command, workspace: "", source: "ci-workflow (verify.yml)" }]);
      const baseline = await runBaseline(commands, dir);
      const evidence = await buildVerificationEvidence({
        findingId: "synthetic-transport-fixture",
        baselineCommit: "synthetic-baseline",
        worktreeCommit: "synthetic-fixed",
        detectorBefore: { detectorId: "synthetic-detector", fired: true, output: "fixture" },
        detectorAfter: { detectorId: "synthetic-detector", fired: false, output: "fixture" },
        commands,
        baseline,
        attempts: 1,
      }, dir);
      expect(evidence.green).toBe(true);
      expect(evidence.clientChecks).toHaveLength(1);
      for (const run of [...baseline.values(), ...evidence.clientChecks]) {
        expect(run).toMatchObject({ command, cwd: dir, exitCode: 0 });
        expect(run.outputTail).toBe(`${literal}\ncwd=${dir}\nparent=inherited-parent-value\n`);
      }
      expect(spawn).toHaveBeenCalledTimes(2);
      for (const result of vi.mocked(spawn).mock.results) {
        expect(result.type).toBe("return");
        const child = result.value as ReturnType<typeof spawn>;
        expect(child.spawnargs).not.toContain(command);
        expect(child.spawnargs.join("\n")).not.toContain("synthetic-client-value-1778");
      }
      for (const call of vi.mocked(spawn).mock.calls) {
        const options = typeof call[1] === "object" && !Array.isArray(call[1]) ? call[1] : call[2];
        expect(options).toEqual(expect.objectContaining({
          cwd: dir,
          env: expect.objectContaining({
            HARVEY_CLIENT_VERIFY_COMMAND: command,
            HARVEY_CLIENT_TEST_PARENT: "inherited-parent-value",
          }),
        }));
      }
      expect(process.env.HARVEY_CLIENT_VERIFY_COMMAND).toBe("stale-parent-program-must-not-run");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("leaves stdin as an open pipe and preserves caller-supplied bytes and EOF", async () => {
    const pending = runCommand('IFS= read -r line; if IFS= read -r extra; then exit 12; fi; printf "%s\\n" "$line"', process.cwd());
    const child = vi.mocked(spawn).mock.results[0]?.value as ReturnType<typeof spawn>;
    expect(child.stdin).not.toBeNull();
    expect(child.stdin?.writableEnded).toBe(false);
    child.stdin?.end("synthetic-stdin-value-1778\n");
    const result = await pending;
    expect(result.exitCode).toBe(0);
    expect(result.outputTail).toBe("synthetic-stdin-value-1778\n");
  });

  it("refuses a watched command collision before spawning or counting a client command", async () => {
    const before = observedClientCommandConcurrency();
    const command = "HARVEY_CLIENT_VERIFY_COMMAND";
    let refusal: unknown;
    try {
      await runCommand(command, process.cwd());
    } catch (error) {
      refusal = error;
    }
    expect(refusal).toBeInstanceOf(SecretInArgvError);
    expect(String(refusal)).not.toContain(command);
    expect(spawn).not.toHaveBeenCalled();
    expect(observedClientCommandConcurrency()).toBe(before);
  });

  it.each(["", "synthetic-client-value-1778\0hidden"])("refuses an unrepresentable command before spawning (%j)", async (command) => {
    await expect(async () => runCommand(command, process.cwd())).rejects.toThrow(SecretInArgvError);
    expect(spawn).not.toHaveBeenCalled();
  });

  it("refuses Windows before spawning instead of claiming cmd expansion preserves arbitrary programs", async () => {
    const descriptor = Object.getOwnPropertyDescriptor(process, "platform");
    const command = "echo synthetic-client-value-1778";
    try {
      // Local selection proof only: this does not execute or certify a Windows shell.
      Object.defineProperty(process, "platform", { value: "win32" });
      let refusal: unknown;
      try {
        await runCommand(command, process.cwd());
      } catch (error) {
        refusal = error;
      }
      expect(refusal).toBeInstanceOf(SecretInArgvError);
      expect(String(refusal)).toContain("Windows");
      expect(String(refusal)).not.toContain(command);
      expect(spawn).not.toHaveBeenCalled();
    } finally {
      if (descriptor !== undefined) Object.defineProperty(process, "platform", descriptor);
    }
  });
});

describe("scrubSecrets", () => {
  it("redacts tokens, keys, and bearer values but leaves ordinary text", () => {
    expect(scrubSecrets("using ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")).toContain("[REDACTED]");
    expect(scrubSecrets("Authorization: Bearer abcdefgh12345678")).toContain("[REDACTED]");
    expect(scrubSecrets("all tests passed in 4.2s")).toBe("all tests passed in 4.2s");
  });
});

describe("computeGreen", () => {
  const check = (o: Partial<CommandRun>): CommandRun => ({
    command: "pnpm run test",
    cwd: ".",
    exitCode: 0,
    durationMs: 10,
    outputTail: "",
    ...o,
  });

  it("is green only when the detector is clean and no client check newly fails", () => {
    expect(
      computeGreen({ detectorAfter: { detectorId: "d", fired: false, output: "" }, clientChecks: [check({})] }),
    ).toBe(true);
  });

  it("is not green if the detector still fires, even with all checks passing", () => {
    expect(
      computeGreen({ detectorAfter: { detectorId: "d", fired: true, output: "" }, clientChecks: [check({})] }),
    ).toBe(false);
  });

  it("is not green if a non-skipped client check fails", () => {
    expect(
      computeGreen({ detectorAfter: { detectorId: "d", fired: false, output: "" }, clientChecks: [check({ exitCode: 1 })] }),
    ).toBe(false);
  });

  it("is not green when the detector did not run — an unrun detector is not a clean one", () => {
    expect(
      computeGreen({
        detectorAfter: { detectorId: "d", fired: false, output: "", notRun: "no resolver for taxonomy" },
        clientChecks: [check({})],
      }),
    ).toBe(false);
  });

  it("does not count skipped checks (needs-ci / pre-existing) against green", () => {
    expect(
      computeGreen({
        detectorAfter: { detectorId: "d", fired: false, output: "" },
        clientChecks: [check({ exitCode: 1, skipped: "pre-existing-failure-on-baseline" }), check({ skipped: "needs-ci" })],
      }),
    ).toBe(true);
  });

  // #1272, the vacuous-truth defect. `[].every(...)` is true, so for as long as the only production
  // assembler hardcoded `clientChecks: []` the client half of this decision silently PASSED — a fix
  // that broke the client's own suite could be reported verified. Pinned here because the failure mode
  // is invisible by construction: nothing about an empty array looks like a missing measurement.
  it("is NOT green on an empty clientChecks — nothing ran, so nothing passed", () => {
    expect(computeGreen({ detectorAfter: { detectorId: "d", fired: false, output: "" }, clientChecks: [] })).toBe(false);
  });

  it("the empty case is the ONLY thing separating it from the detector half — which is a named function", () => {
    // Guards the split: a caller that legitimately scores only the detector half (runFixAcceptance
    // over a single-file corpus) must say so by calling detectorHalfClean, not by passing [].
    const clean: DetectorRun = { detectorId: "d", fired: false, output: "" };
    expect(detectorHalfClean(clean)).toBe(true);
    expect(computeGreen({ detectorAfter: clean, clientChecks: [] })).toBe(false);
    expect(detectorHalfClean({ ...clean, notRun: "no resolver" })).toBe(false);
    expect(detectorHalfClean({ ...clean, fired: true })).toBe(false);
  });
});

describe("runCommand — the timeout bound", () => {
  // Both cases assert ELAPSED time, not just the exit code and the banner. Without that they pass on
  // a runner that never actually bounds anything: `timedOut` is set by the timer regardless of
  // whether the kill landed, so the banner and the non-zero exit still show up — five seconds late.
  // That is exactly how the broken bound shipped.
  it("bounds a command that overruns and reports the timeout in its own output, never a silent 0", async () => {
    const start = Date.now();
    const slow = await runCommand(`${node} -e "setTimeout(() => {}, 5000)"`, process.cwd(), 300);
    expect(Date.now() - start).toBeLessThan(2000);
    expect(slow.exitCode).not.toBe(0);
    expect(slow.outputTail).toContain("exceeded the client-check timeout");
  }, 20_000);

  // The simple case above is the one that stayed green while the bound was broken on macOS: a shell
  // handed a single command execs itself away, so killing the wrapper pid happens to kill the work.
  // A COMPOUND line leaves the shell resident and the grandchild unreached — and compound is what
  // arrives in practice, since extractCiRunSteps emits a multi-line `run: |` block as one command
  // and client scripts chain with `&&`. Reverting `detached` + the group kill in runCommand turns
  // this red at ~5s.
  it("bounds a COMPOUND command too — inherited pipes cannot hold the verification open", async () => {
    const start = Date.now();
    const slow = await runCommand(`${node} -e "setTimeout(() => {}, 5000)" ; true`, process.cwd(), 300);
    expect(Date.now() - start).toBeLessThan(2000);
    expect(slow.exitCode).not.toBe(0);
    expect(slow.outputTail).toContain("exceeded the client-check timeout");
  }, 20_000);

  it("bounds an && chain, the shape a client verify script actually uses", async () => {
    const start = Date.now();
    const slow = await runCommand(`true && ${node} -e "setTimeout(() => {}, 5000)"`, process.cwd(), 300);
    expect(Date.now() - start).toBeLessThan(2000);
    expect(slow.exitCode).not.toBe(0);
  }, 20_000);

  it("bounds a self-detaching descendant that keeps the inherited pipes open (#1797)", async () => {
    const grandchild =
      'const { spawn } = require("node:child_process"); ' +
      'spawn(process.execPath, ["-e", "setTimeout(() => {}, 5000)"], { detached: true, stdio: "inherit" }).unref();';
    const start = Date.now();
    const slow = await runCommand(`${node} -e ${JSON.stringify(grandchild)}`, process.cwd(), 300);
    expect(Date.now() - start).toBeLessThan(2000);
    expect(slow.exitCode).not.toBe(0);
    expect(slow.outputTail).toContain("exceeded the client-check timeout");
  }, 20_000);

  it("keeps the client suite in the caller's foreground process group so SIGINT reaches it (#1797)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-run-command-sigint-"));
    const ready = join(dir, "ready");
    const interrupted = join(dir, "interrupted");
    const client =
      `const fs=require("node:fs"); fs.writeFileSync(${JSON.stringify(ready)},String(process.pid)); ` +
      `process.on("SIGINT",()=>{fs.writeFileSync(${JSON.stringify(interrupted)},"yes");process.exit(130)}); setTimeout(()=>{},5000);`;
    const command = `${node} -e ${JSON.stringify(client)}`;
    const moduleUrl = new URL("./verify.ts", import.meta.url).href;
    const driver = `import { runCommand } from ${JSON.stringify(moduleUrl)}; void runCommand(${JSON.stringify(command)}, ${JSON.stringify(process.cwd())}, 5000);`;
    const processGroup = spawn(resolve("node_modules/.bin/tsx"), ["-e", driver], {
      cwd: process.cwd(),
      detached: true,
      stdio: "ignore",
    });
    const waitFor = async (file: string, timeoutMs: number) => {
      const deadline = Date.now() + timeoutMs;
      while (Date.now() < deadline) {
        if (existsSync(file)) return true;
        await new Promise((done) => setTimeout(done, 10));
      }
      return false;
    };
    try {
      expect(await waitFor(ready, 2000)).toBe(true); // clock starts after the client itself is ready
      if (processGroup.pid === undefined) throw new Error("SIGINT test driver has no pid");
      process.kill(-processGroup.pid, "SIGINT");
      expect(await waitFor(interrupted, 2000)).toBe(true);
    } finally {
      if (existsSync(ready)) {
        const clientPid = Number(readFileSync(ready, "utf8"));
        try {
          process.kill(clientPid, "SIGKILL");
        } catch {
          // The client already exited after receiving SIGINT.
        }
      }
      if (processGroup.pid !== undefined) {
        try {
          process.kill(-processGroup.pid, "SIGKILL");
        } catch {
          // The driver already exited after the foreground-group SIGINT.
        }
      }
      rmSync(dir, { recursive: true, force: true });
    }
  }, 20_000);
});
