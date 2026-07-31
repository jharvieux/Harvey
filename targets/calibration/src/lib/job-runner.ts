import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";

// #1344 NEGATIVE — a scheduler's job runner. Nothing here is reachable from a request: the argument
// bag is built by the scheduler from a database row, and the parameter is a PLAIN IDENTIFIER named
// `params` / `searchParams`.
//
// This is the shape #1240's RSC taint source got wrong. That source reached `params.<field>` by
// NAME, and its only guard excluded a name bound by ASSIGNMENT — a function parameter is never
// assigned, so every one of these lines became request-tainted. MEASURED 2026-07-27: this file's
// twin with the parameter renamed to `opts` produced 3 findings; this one produced 6, including
// `harvey-command-injection` at Critical / precisionTier "high", i.e. GRADED.
//
// The reason recorded here for reaching by name — that semgrep OSS is incapable of matching a
// destructured object parameter — was ASSUMED and is false (#1544, MEASURED 2026-07-31, semgrep
// 1.164.0). The binding form is now a required conjunct of the source; the plain-parameter
// exclusion this file guards is kept as a second, independent narrowing. Its sibling negative for
// the new requirement is src/lib/job-queue.ts.
//
// The paired POSITIVE that must keep firing is src/owasp-react/rsc-fetch-unvalidated.tsx, whose
// page takes `{ params }` destructured — so this file going silent must never be bought by the RSC
// source going silent too.
interface JobSpec {
  script: string;
  logfile: string;
  archive: string;
}

export function runScheduledJob(params: JobSpec): string {
  return execSync(`/opt/jobs/${params.script}`).toString();
}

export function readJobLog(params: JobSpec): string {
  return readFileSync(`/var/log/jobs/${params.logfile}`, "utf8");
}

export function readJobArchive(searchParams: JobSpec): string {
  return readFileSync(`/var/archive/${searchParams.archive}`, "utf8");
}
