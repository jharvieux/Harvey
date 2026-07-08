// M7 (performance) — pulls the Supabase performance advisor for a client project via the
// Management API and shapes the "lints" into Finding[] for §3b of the report. Merge the
// result into the engagement's findings.json alongside the other modules' findings and meta,
// then `pnpm validate:findings`.
//
//   SUPABASE_ACCESS_TOKEN=sbp_... pnpm perf-scan <project-ref> [--out findings.perf.json]
//
// Requires a Supabase personal access token (https://supabase.com/dashboard/account/tokens)
// with read access to the client's project — ask the client to mint a scoped token for the
// engagement.
//
// Endpoint: GET https://api.supabase.com/v1/projects/{ref}/advisors/performance. The
// /advisors/security path is documented (https://supabase.com/docs/guides/database/database-
// advisors); /performance is the sibling advisor type returning the same { lints: [...] }
// shape (same family the `get_advisors` MCP tool calls with `type: "performance"`) but wasn't
// independently exercised against a live project while writing this module — the advisors API
// is marked experimental by Supabase, so confirm the path/shape against current docs or a
// dashboard Network-tab capture before the first live engagement run.

import { writeFileSync } from "node:fs";
import type { Finding } from "../findings.js";
import { parseAdvisorFindings, type AdvisorReport } from "../perf-scan.js";

const args = process.argv.slice(2);
const projectRef = args.find((a) => !a.startsWith("--"));
const outIdx = args.indexOf("--out");
const outPath = outIdx >= 0 ? args[outIdx + 1] : undefined;

if (!projectRef) {
  console.error("usage: SUPABASE_ACCESS_TOKEN=sbp_... pnpm perf-scan <project-ref> [--out findings.perf.json]");
  process.exit(2);
}

const token = process.env.SUPABASE_ACCESS_TOKEN;
if (!token) {
  console.error("missing SUPABASE_ACCESS_TOKEN (a Supabase personal access token scoped to the client's project)");
  process.exit(2);
}

async function fetchPerformanceAdvisors(ref: string, accessToken: string): Promise<AdvisorReport> {
  const res = await fetch(`https://api.supabase.com/v1/projects/${ref}/advisors/performance`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) {
    throw new Error(`Supabase advisors API returned ${res.status}: ${await res.text()}`);
  }
  return (await res.json()) as AdvisorReport;
}

const report = await fetchPerformanceAdvisors(projectRef, token);
const findings: Finding[] = parseAdvisorFindings(report);

console.error(`M7 performance advisor: ${report.lints.length} lint(s) -> ${findings.length} grouped finding(s)`);

const json = JSON.stringify(findings, null, 2);
if (outPath) {
  writeFileSync(outPath, json + "\n");
  console.error(`wrote ${findings.length} findings to ${outPath}`);
} else {
  console.log(json);
}
