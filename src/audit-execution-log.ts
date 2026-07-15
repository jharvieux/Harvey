// The execution-record store behind #284 — what makes MODULES_NEVER_EXECUTED a DERIVED value.
//
// Before this, the never-run ledger was a hand-kept Set: someone had to remember to delete "M6" the
// first time M6 ran (a false alarm if forgotten), and — the worse half — someone had to remember to
// ADD a new module that had never run, or it silently never got the loud treatment M6 got. The
// mechanism that catches "was this recorded honestly" was itself unrecorded.
//
// Now the ledger is the complement of this log: a module is never-run because nothing has ever
// recorded it running, not because a human curated it. The default for an unknown module is
// never-run, which is the fail-loud direction — a new module added to AUDIT_MODULES is never-run
// from its first commit until it actually executes, with nobody needing to notice.
//
// Why a committed file rather than a derived-at-runtime scan: "has M6 EVER run, in any engagement"
// is a claim across time and machines, so the evidence has to outlive the process that observed it.
// It is append-only in practice — an entry is written by the #229 orchestrator when a probe reports
// `ran`, and removing one is a claim that an execution never happened.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
// Type-only: audit-coverage derives MODULES_NEVER_EXECUTED from this file at module-init, so a
// VALUE import back would be an initialization cycle. The module enumeration is passed in instead.
import type { AuditModule } from "./audit-coverage.js";

export interface ExecutionRecord {
  module: AuditModule;
  // When the module last produced real output, and against what. Provenance, so a reader can audit
  // the claim rather than trust it — an entry with no evidence is indistinguishable from the
  // hand-kept Set this replaced.
  firstRan: string;
  target: string;
  evidence: string;
}

export const EXECUTION_LOG_PATH = fileURLToPath(new URL("../audit-execution-log.json", import.meta.url));

export function readExecutionLog(path: string = EXECUTION_LOG_PATH): ExecutionRecord[] {
  return JSON.parse(readFileSync(path, "utf8")) as ExecutionRecord[];
}

// A module is never-run iff no record claims it ran. Derived, so it cannot go stale in either
// direction: it can't hold a false alarm for a module that has run, and it can't miss a module
// nobody thought to list.
export function neverExecutedModules(modules: readonly AuditModule[], log: ExecutionRecord[]): Set<AuditModule> {
  const executed = new Set(log.map((r) => r.module));
  return new Set(modules.filter((module) => !executed.has(module)));
}

// Merges the modules that just ran into the log, preserving each module's FIRST execution date —
// the never-run question is "ever", so an existing record is evidence already banked.
export function recordExecutions(
  modules: readonly AuditModule[],
  log: ExecutionRecord[],
  ran: AuditModule[],
  target: string,
  when: string,
  evidence: string,
): ExecutionRecord[] {
  const known = new Set(log.map((r) => r.module));
  const additions = ran.filter((module) => !known.has(module)).map((module) => ({ module, firstRan: when, target, evidence }));
  return [...log, ...additions].sort((a, b) => modules.indexOf(a.module) - modules.indexOf(b.module));
}
