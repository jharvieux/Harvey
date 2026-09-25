#!/usr/bin/env node
import { appendFileSync, closeSync, openSync, readFileSync, readdirSync, realpathSync, renameSync, writeFileSync, writeSync } from "node:fs";
import { spawn } from "node:child_process";
import { basename } from "node:path";

const binary = basename(process.argv[1]);
const args = process.argv.slice(2);
const validationConfigNames = ["0-p-typescript.yml", "1-p-react.yml", "2-p-nextjs.yml", "3-p-owasp-top-ten.yml", "4-p-secrets.yml", "5-p-security-audit.yml"];

function semgrepValidationEvidence() {
  if (binary !== "semgrep" || args.length !== 19 || args[0] !== "scan") return {};
  for (let ordinal = 0; ordinal < validationConfigNames.length; ordinal += 1) {
    if (args[1 + (ordinal * 2)] !== "--config" || basename(args[2 + (ordinal * 2)]) !== validationConfigNames[ordinal]) return {};
  }
  if (JSON.stringify(args.slice(13, 18)) !== JSON.stringify(["--json", "--strict", "--metrics", "off", "--disable-version-check"])) return {};
  const target = args[18];
  try {
    const targetIsCwd = realpathSync(target) === realpathSync(process.cwd());
    return { targetIsCwd, targetEntries: targetIsCwd ? readdirSync(target) : undefined };
  } catch {
    return {};
  }
}

if (args.includes("--version") || args.includes("version")) {
  console.log(`${binary} ${process.env.HARVEY_PREFLIGHT_TOOL_VERSION ?? "fixture-1"}`);
} else {
  const validationEvidence = semgrepValidationEvidence();
  const registryValidation = validationEvidence.targetEntries?.length === 0;
  appendFileSync(process.env.HARVEY_PREFLIGHT_TRACE, `${JSON.stringify({ binary, args, cwd: process.cwd(), ...validationEvidence })}\n`);
  if (process.env.HARVEY_PREFLIGHT_HANG === binary && !registryValidation) {
    const record = process.env.HARVEY_PREFLIGHT_CANCEL_RECORD;
    if (!record) throw new Error("hanging fixture tool requires a lifecycle record path");
    // Publish readiness only after the cancellation behavior and descendant event loop exist.
    process.on("SIGTERM", () => {});
    const descendant = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000); process.send({ ready: true, pid: process.pid });"], { stdio: ["ignore", "ignore", "ignore", "ipc"] });
    await new Promise((resolve, reject) => {
      descendant.once("error", reject);
      descendant.once("exit", () => reject(new Error("fixture descendant exited before readiness")));
      descendant.once("message", (message) => {
        if (message?.ready !== true || message.pid !== descendant.pid) reject(new Error("invalid fixture descendant readiness"));
        else resolve();
      });
    });
    let beat = 0;
    const writeRecord = () => {
      const payload = JSON.stringify({ version: 1, toolPid: process.pid, descendantPid: descendant.pid, beat: ++beat });
      const staged = `${record}.tmp`;
      const marker = process.env.HARVEY_PREFLIGHT_CANCEL_STAGED_WRITE;
      if (marker && beat === 2) {
        // Force cancellation into a real interrupted write, instead of hoping for a timing race.
        const fd = openSync(staged, "w");
        const split = Math.floor(payload.length / 2);
        writeSync(fd, payload.slice(0, split));
        writeFileSync(`${marker}.tmp`, JSON.stringify({ staged, beat }));
        renameSync(`${marker}.tmp`, marker);
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 30_000);
        writeSync(fd, payload.slice(split));
        closeSync(fd);
      } else writeFileSync(staged, payload);
      renameSync(staged, record);
    };
    writeRecord();
    globalThis.setInterval(writeRecord, 10);
    await new Promise(() => {});
  }
  if (binary === "semgrep") {
    const { parse } = await import("yaml");
    const config = args[args.indexOf("--config") + 1];
    const rules = parse(readFileSync(config, "utf8")).rules;
    const changed = process.env.HARVEY_PREFLIGHT_CHANGED_OUTPUT === "1" && !registryValidation;
    console.log(JSON.stringify({
      results: [],
      errors: changed ? [{ path: "index.ts", message: "physically changed Semgrep semantic output", type: "PartialParsing" }] : [],
      paths: { scanned: ["index.ts"], skipped: [] },
      time: { rules: rules.map((rule) => rule.id), fixpoint_timeouts: [] },
    }));
  } else if (binary === "gitleaks") {
    const index = args.indexOf("--report-path");
    if (index >= 0) writeFileSync(args[index + 1], "[]\n");
  } else if (binary === "osv-scanner") {
    console.log(JSON.stringify({ results: [] }));
  } else if (binary !== "trufflehog") {
    throw new Error(`unexpected external tool ${binary}`);
  }
}
