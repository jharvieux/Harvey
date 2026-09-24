#!/usr/bin/env node
import { appendFileSync, readFileSync, readdirSync, realpathSync, writeFileSync } from "node:fs";
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
    const descendant = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
    let beat = 0;
    const writeRecord = () => writeFileSync(record, JSON.stringify({ toolPid: process.pid, descendantPid: descendant.pid, beat: ++beat }));
    writeRecord();
    // The parent needs SIGKILL after its group receives SIGTERM. Its child uses the default
    // disposition, proving the harness waits for both levels before deleting fixture state.
    process.on("SIGTERM", () => {});
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
