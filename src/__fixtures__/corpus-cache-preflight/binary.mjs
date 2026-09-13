#!/usr/bin/env node
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { basename } from "node:path";

const binary = basename(process.argv[1]);
const args = process.argv.slice(2);
if (args.includes("--version") || args.includes("version")) {
  console.log(`${binary} ${process.env.HARVEY_PREFLIGHT_TOOL_VERSION ?? "fixture-1"}`);
} else {
  appendFileSync(process.env.HARVEY_PREFLIGHT_TRACE, `${JSON.stringify({ binary, args })}\n`);
  if (process.env.HARVEY_PREFLIGHT_HANG === binary) {
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
    const changed = process.env.HARVEY_PREFLIGHT_CHANGED_OUTPUT === "1";
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
