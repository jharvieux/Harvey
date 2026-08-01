// #1689 — the DETECTOR-level member of the coverage-disclosure family. M1-EXT-00 says how many
// source files the passes read; M1-LANG-00 names the languages M1 does not analyse; M1-JOBPATH-00
// names background-job directories outside the job-path convention. None of them answers the
// question this file exists for: a detector whose filter is a DIRECTORY CONVENTION reads zero files
// on a repo that does not follow it, and a zero from an unread population is indistinguishable in
// the output from a clean scan.
//
// MEASURED 2026-07-31 (#1269, re-measured for #1689): across the three pinned tenant-scope clones
// `bola-owner` read 0 files and `job-tenant-scope` read 0 files, because none of those repos is a
// Next.js app or ships a background-job directory. Both detectors contributed 0 findings on every
// corpus-drift run, forever, with nothing saying they never looked.
//
// POPULATION AND HOW IT WAS ENUMERATED, so this is a rule rather than a pair of names. A detector
// belongs here when its ENTRY POINT narrows the file set to a directory convention before doing
// anything — i.e. a repo can be fully scanned and still hand the detector nothing. Applying that
// rule across `src/scan` and `src/detectors` (`git grep -n "test(f\.path)" -- src/scan src/detectors`,
// 2026-07-31) selects exactly two: `bola-owner` (`pages/api/**`) and `job-tenant-scope` (JOB_PATH).
// Four near-misses were read and are OUT of the population, with the reason rather than by silence:
// `leftover-auth`, `env-schema`, `app-router` and `auth-guard-discovery` all walk the WHOLE source
// tree and apply a path convention per CLASS inside it, so their file population is the tree and
// only individual classes can go unexercised. That is a real second question and a narrower one;
// it is tracked separately rather than folded in here.

import type { Finding } from "../findings.js";
import type { SourceInput } from "../detectors/common.js";
import { bolaOwnerScannedFiles } from "./bola-owner.js";
import { jobTenantScopeScannedFiles } from "./job-tenant-scope.js";

export interface PathScopedDetector {
  /** Row id emitted when this detector's filter admits nothing. */
  rowId: string;
  detector: string;
  /** What the filter admits, in the words a client reads. */
  convention: string;
  /** THE detector's own exported filter — never a copy of it. */
  select: (files: readonly SourceInput[]) => SourceInput[];
  /** The classes that go unassessed when the population is empty. */
  classes: string;
}

export const PATH_SCOPED_DETECTORS: readonly PathScopedDetector[] = [
  {
    rowId: "M1-PATHSCOPE-BOLA-00",
    detector: "bola-owner",
    convention: "Next.js Pages Router API routes (`pages/api/**`, excluding test/example trees)",
    select: bolaOwnerScannedFiles,
    classes: "a request-supplied owner id trusted by an authenticated Pages Router handler (BOLA)",
  },
  {
    rowId: "M1-PATHSCOPE-JOB-00",
    detector: "job-tenant-scope",
    convention: "conventional background-job directories (`inngest/`, `jobs/`, `queues/`, `workers/`, `app/api/cron/`)",
    select: jobTenantScopeScannedFiles,
    classes: "a service-role query with no tenant predicate running outside a request context",
  },
];

export interface PathScopeCensusRow {
  rowId: string;
  detector: string;
  convention: string;
  filesRead: number;
}

/** Per-detector file counts — the number acceptance asks to be published, not inferred. */
export function pathScopeCensus(files: readonly SourceInput[]): PathScopeCensusRow[] {
  return PATH_SCOPED_DETECTORS.map((d) => ({ rowId: d.rowId, detector: d.detector, convention: d.convention, filesRead: d.select(files).length }));
}

/**
 * One counted not-assessed row per path-scoped detector whose filter admitted no file.
 *
 * Deliberately silent when the target has no source files at all: that target's problem is the
 * whole scan, and M1-EXT-00 already reports it. Emitting two more rows there would report the same
 * fact three times and bury the one that names the cause.
 */
export function pathScopeNotAssessedRows(files: readonly SourceInput[]): Finding[] {
  if (files.length === 0) return [];
  return PATH_SCOPED_DETECTORS.filter((row) => row.select(files).length === 0).map((row) => ({
      id: row.rowId,
      title: `Not assessed: the ${row.detector} check found no files in its scope`,
      severity: "Info" as const,
      confidence: "N/A" as const,
      category: "Coverage",
      taxonomy: `Coverage — ${row.detector} read zero files (its path convention matched nothing)`,
      location: "(repo-wide)",
      status: "Open" as const,
      evidence: `The ${row.detector} check reads only ${row.convention}. This target has ${files.length} source file(s) and NONE of them are in that scope, so the check ran over an empty file set. Its zero findings are a statement about the scope, not about the code.`,
      impact: `This check would not have detected ${row.classes} here, wherever such code actually lives in this repo. Recorded so the absence of its findings reads as 'not assessed', not 'assessed and clean'.`,
      fix: `If this repo does hold code of that kind under a different layout, review those files by hand, or move them under the conventional path so the check reaches them. If it holds none, this row is the record that the check had nothing to look at.`,
      value: 1,
      ease: 4,
      safety: 5,
      mechanical: true,
  }));
}
