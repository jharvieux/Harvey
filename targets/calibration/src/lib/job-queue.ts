import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { defaultRetention, loadQueue, params } from "./job-config.js";

// #1544 NEGATIVE — the sibling of job-runner.ts, for the OTHER half of the RSC request-source
// discriminator. job-runner.ts covers a plain-identifier PARAMETER named `params`; these three
// bindings are not parameters at all — a for-of loop variable over DB rows, an array-destructured
// tuple element, and an imported module constant. None of them is reachable from a request.
//
// Before #1544 the shared `x-request-source` block reached the name without requiring its binding
// form, and its three not-insides could see only assignments and parameter lists — so all three
// lines below fired exactly as an unguarded bare name would (MEASURED 2026-07-31, semgrep 1.164.0).
// The block now requires the access to sit inside an OBJECT-DESTRUCTURING binding of the name, the
// shape a real Server Component page actually has, which is what spares this file.
//
// The paired POSITIVE that must keep firing is src/owasp-react/rsc-fetch-unvalidated.tsx. This file
// going silent must never be bought by that page going silent too.
export function runQueuedJobs(): string[] {
  const out: string[] = [];
  for (const params of loadQueue()) {
    out.push(execSync(`/opt/jobs/${params.script}`).toString());
  }
  return out;
}

export function readOldestJobLog(): string {
  const [searchParams] = loadQueue();
  return readFileSync(`/var/log/jobs/${searchParams.logfile}`, "utf8");
}

export function readDefaultArchive(): string {
  return readFileSync(`/var/archive/${params.archive}/${defaultRetention}`, "utf8");
}
