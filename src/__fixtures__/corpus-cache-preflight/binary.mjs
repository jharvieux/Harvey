#!/usr/bin/env node
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { basename } from "node:path";
import { parse } from "yaml";

const binary = basename(process.argv[1]);
const args = process.argv.slice(2);
if (args.includes("--version") || args.includes("version")) {
  console.log(`${binary} ${process.env.HARVEY_PREFLIGHT_TOOL_VERSION ?? "fixture-1"}`);
} else {
  appendFileSync(process.env.HARVEY_PREFLIGHT_TRACE, `${JSON.stringify({ binary, args })}\n`);
  if (binary === "semgrep") {
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
