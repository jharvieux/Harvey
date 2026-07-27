// SecBench.js external recall gate (#879). SecBench.js (Staicu et al., ICSE 2023) is ~600 REAL
// npm vulnerabilities across five server-side-JS classes, each shipping a pinned vulnerable
// package version, an executable jest exploit, and ground-truth metadata (CVE id, advisory links,
// sink location). Unlike the six planted-bug corpus targets (external-corpus.ts) these are real
// CVEs, so this is Harvey's first HELD-OUT, real-code recall measurement.
//
// WHAT THIS MEASURES, AND WHAT IT DOES NOT — the load-bearing finding (measured 2026-07-24):
// SecBench's vulnerability lives INSIDE the vulnerable library (the sink is e.g. `index.js:18:3`
// in the dependency), and the exploit is a jest test that `require`s the library and calls it with
// a hardcoded payload. It is NOT application code with an HTTP request source. Harvey's mechanical
// tier has two source-security engines and one dependency engine:
//   - semgrep `harvey-*` rules — TAINT rules whose sources are req.query/body/params/searchParams.
//     Measured 2026-07-24: 0 hits across all 600 exploit test files (validate-secbench.ts runs this
//     pass live). SecBench does not exercise Harvey's 92 source rules, because the vulnerable code
//     is in node_modules (not scanned) and the exploit test carries no request source. The issue's
//     hypothesis that it "exercises M1's injection/XSS/prototype-pollution/path-traversal/command-
//     injection rules" is FALSIFIED by measurement — see docs/design/secbench-recall-measurement.md.
//   - the dependency-CVE (SCA) engine — osv-scanner over the target's lockfile. This IS the pathway
//     that scores SecBench: every entry pins a KNOWN-vulnerable version, so osv flags it. This gate
//     therefore measures Harvey's SCA recall, reported as a distinct per-tier number so #868 never
//     inherits it as if it were a source-detector recall.
// There are NO benign negatives in SecBench (every entry is a positive), so precision/FPR are NOT
// measurable here — the vibe-dummy FP oracle remains the precision gate (the issue's guardrail).

import type { OsvScanResult } from "./dependencies.js";

export const SECBENCH_REPO = "cristianstaicu/SecBench.js";
// Pinned commit measured 2026-07-24. The loader/matcher are only meaningful against this tree.
export const SECBENCH_PIN = "bc315621913899dcaa7613cd60948514ae63bdfe";

export const SECBENCH_CLASSES = [
  "prototype-pollution",
  "redos",
  "command-injection",
  "path-traversal",
  "code-injection",
] as const;
export type SecbenchClass = (typeof SECBENCH_CLASSES)[number];

export interface SecbenchEntry {
  // "<class>/<slug>" — the join key against the osv lockfile tree and semgrep hit paths.
  key: string;
  cls: SecbenchClass;
  slug: string; // e.g. "aaptjs_1.3.1"
  // The single vulnerable package under test. null for the handful of multi-dependency entries
  // (recorded, matched on "any declared dep flagged" rather than one target — see matchEntryOsv).
  pkg: string | null;
  version: string | null;
  deps: Record<string, string>; // all declared deps (always >= 1)
  cveId: string | null; // meta.id when it is a real CVE, else null (SecBench leaves it "" or "n/a")
  // Advisory identifiers we can cross-reference an osv hit against: the CVE id plus any GHSA/SNYK
  // ids parsed out of the entry's `links`. An exact match means osv reported THE advisory SecBench
  // curated, not merely some advisory on the same package.
  advisoryIds: string[];
  sink: string | null;
}

interface RawMeta {
  id?: string;
  dependencies?: Record<string, string>;
  links?: Record<string, string>;
  sink?: string;
  sinkLocation?: string;
}

const GHSA_RE = /GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}/gi;
const SNYK_RE = /SNYK-[0-9A-Z-]+/gi;
const CVE_RE = /CVE-\d{4}-\d+/gi;

function isRealCve(id: string | undefined): id is string {
  return !!id && id.trim() !== "" && id.trim().toLowerCase() !== "n/a";
}

function extractAdvisoryIds(meta: RawMeta): string[] {
  const blob = [meta.id ?? "", ...Object.values(meta.links ?? {})].join(" ");
  const ids = new Set<string>();
  for (const re of [GHSA_RE, SNYK_RE, CVE_RE]) {
    for (const m of blob.matchAll(re)) ids.add(m[0].toUpperCase());
  }
  return [...ids];
}

// Reads a SecBench.js checkout into the ground-truth corpus. Skips a class folder that isn't
// present (fail-loud is the CLI's job: it asserts all five classes loaded before scoring).
export function loadSecbenchCorpus(
  root: string,
  fs: { readdirSync: (p: string) => string[]; readFileSync: (p: string) => string; existsSync: (p: string) => boolean },
): SecbenchEntry[] {
  const entries: SecbenchEntry[] = [];
  for (const cls of SECBENCH_CLASSES) {
    const clsDir = `${root}/${cls}`;
    if (!fs.existsSync(clsDir)) continue;
    for (const slug of fs.readdirSync(clsDir).sort()) {
      const pjPath = `${clsDir}/${slug}/package.json`;
      if (!fs.existsSync(pjPath)) continue;
      let meta: RawMeta;
      try {
        meta = JSON.parse(fs.readFileSync(pjPath)) as RawMeta;
      } catch {
        continue; // a malformed metadata file is not an entry; the CLI reports the count gap
      }
      const deps = meta.dependencies ?? {};
      const depNames = Object.keys(deps);
      const single = depNames.length === 1 ? depNames[0]! : null;
      entries.push({
        key: `${cls}/${slug}`,
        cls,
        slug,
        pkg: single,
        version: single ? deps[single]! : null,
        deps,
        cveId: isRealCve(meta.id) ? meta.id!.trim().toUpperCase() : null,
        advisoryIds: extractAdvisoryIds(meta),
        sink: meta.sink ?? meta.sinkLocation ?? null,
      });
    }
  }
  return entries;
}

interface EntryOsvMatch {
  // osv reported >= 1 advisory on the entry's OWN target package (not merely a transitive dep). The
  // headline SCA-recall signal: Harvey flagged the known-vulnerable dependency.
  targetFlagged: boolean;
  // Advisory ids/aliases osv reported on the target package.
  reportedIds: string[];
  // reportedIds intersect the entry's curated advisoryIds — osv found THE advisory SecBench pinned.
  exactAdvisory: boolean;
}

// Indexes an osv-scanner recursive report by entry key ("<class>/<slug>"), derived from each
// result's source.path (…/<class>/<slug>/package-lock.json). Values are the per-package vuln-id
// lists (ids + aliases), so the matcher can scope to the entry's OWN target package.
export function indexOsvByEntry(report: OsvScanResult): Map<string, { name: string; ids: string[] }[]> {
  const byEntry = new Map<string, { name: string; ids: string[] }[]>();
  for (const result of report.results ?? []) {
    const path = result.source?.path ?? "";
    const m = path.match(/([^/]+)\/([^/]+)\/package-lock\.json$/);
    if (!m) continue;
    const key = `${m[1]}/${m[2]}`;
    const pkgs: { name: string; ids: string[] }[] = [];
    for (const p of result.packages ?? []) {
      const vulns = p.vulnerabilities ?? [];
      if (vulns.length === 0) continue;
      const ids = new Set<string>();
      for (const v of vulns) {
        if (v.id) ids.add(v.id.toUpperCase());
        for (const a of v.aliases ?? []) ids.add(a.toUpperCase());
      }
      pkgs.push({ name: (p.package?.name ?? "").toLowerCase(), ids: [...ids] });
    }
    byEntry.set(key, pkgs);
  }
  return byEntry;
}

// osv-scanner's JSON emits a result block ONLY for a lockfile with >= 1 vulnerability — a scanned-
// but-clean lockfile is absent. So absence from the index is NOT "no data": it means osv found
// nothing for that entry (a MISS, e.g. the vuln is Snyk-only and not in the OSV/GHSA database).
// Installability (was a lockfile generated at all) is tracked SEPARATELY, from the lockfile tree —
// see scoreSecbench's installableKeys — so the recall denominator is every installable entry and an
// osv-clean entry counts against recall instead of being silently dropped (the inflation trap #879
// warns about: excluding real misses from the denominator manufactures a higher number).
export function matchEntryOsv(entry: SecbenchEntry, index: Map<string, { name: string; ids: string[] }[]>): EntryOsvMatch {
  const pkgs = index.get(entry.key) ?? [];
  // The entry's target package(s): the single pinned pkg, or (multi-dep) any declared dep name.
  const targetNames = new Set((entry.pkg ? [entry.pkg] : Object.keys(entry.deps)).map((n) => n.toLowerCase()));
  const reported = new Set<string>();
  let targetFlagged = false;
  for (const p of pkgs) {
    if (!targetNames.has(p.name)) continue;
    targetFlagged = true;
    for (const id of p.ids) reported.add(id);
  }
  const curated = new Set(entry.advisoryIds.map((a) => a.toUpperCase()));
  const exactAdvisory = [...reported].some((id) => curated.has(id));
  return { targetFlagged, reportedIds: [...reported], exactAdvisory };
}

interface ClassRecall {
  cls: SecbenchClass | "ALL";
  total: number; // entries in class
  installable: number; // entries whose lockfile was generated — the SCA-recall denominator
  notInstallable: number; // declared env gap (pkg/version no longer on npm), excluded from denom
  // SCA (osv) recall over INSTALLABLE entries — the free/mechanical-tier number for #868.
  scaFlagged: number;
  // Of those, how many matched THE curated advisory id (stricter).
  scaExact: number;
  // semgrep source-rule hits (measured — expected 0; a nonzero is a real signal to record).
  semgrepHits: number;
}

// installableKeys: entry keys ("<class>/<slug>") whose package-lock WAS generated. An entry not in
// this set is a declared environment gap (its package no longer resolves from npm), excluded from
// the recall denominator and named separately. An installable entry that osv did not flag is a MISS.
export function scoreSecbench(
  entries: SecbenchEntry[],
  index: Map<string, { name: string; ids: string[] }[]>,
  installableKeys: Set<string>,
  semgrepHitKeys: Set<string>,
): { perClass: ClassRecall[]; all: ClassRecall } {
  const blank = (cls: SecbenchClass | "ALL"): ClassRecall => ({
    cls, total: 0, installable: 0, notInstallable: 0, scaFlagged: 0, scaExact: 0, semgrepHits: 0,
  });
  const byCls = new Map<SecbenchClass, ClassRecall>();
  for (const cls of SECBENCH_CLASSES) byCls.set(cls, blank(cls));
  const all = blank("ALL");
  for (const e of entries) {
    const row = byCls.get(e.cls)!;
    row.total += 1; all.total += 1;
    if (!installableKeys.has(e.key)) {
      row.notInstallable += 1; all.notInstallable += 1;
    } else {
      row.installable += 1; all.installable += 1;
      const m = matchEntryOsv(e, index);
      if (m.targetFlagged) { row.scaFlagged += 1; all.scaFlagged += 1; }
      if (m.exactAdvisory) { row.scaExact += 1; all.scaExact += 1; }
    }
    if (semgrepHitKeys.has(e.key)) { row.semgrepHits += 1; all.semgrepHits += 1; }
  }
  return { perClass: [...byCls.values()], all };
}

export function recallPct(caught: number, denom: number): string {
  return denom === 0 ? "n/a" : `${((caught / denom) * 100).toFixed(1)}%`;
}

// #946: LIBRARY-INTERNAL SOURCE recall — the pathway the request-sourced semgrep pass (semgrepHits
// above) cannot measure. SecBench's vulnerability lives inside the target package's own source (the
// `sink` field points at e.g. lib/read-file.js in the dependency), which is in node_modules and NOT
// in the scanned exploit dir — so the request rules score 0/600 by construction. The library-taint
// rules (harvey-lib-*) treat a PARAMETER of a public library entry point as the taint source, so
// scanning the INSTALLED target-package source scores this axis. Denominator is the entries whose
// target-package source was present to scan (`scannedKeys`), mirroring the SCA installable/flagged
// split — an installed-but-unflagged entry is a MISS, never dropped.
interface LibrarySourceRecall {
  cls: SecbenchClass | "ALL";
  scanned: number; // entries whose target-package source was present to scan
  libFlagged: number; // of those, whose source drew a harvey-lib-* finding
}

export function scoreLibrarySource(
  entries: SecbenchEntry[],
  scannedKeys: Set<string>,
  libHitKeys: Set<string>,
): { perClass: LibrarySourceRecall[]; all: LibrarySourceRecall } {
  const blank = (cls: SecbenchClass | "ALL"): LibrarySourceRecall => ({ cls, scanned: 0, libFlagged: 0 });
  const byCls = new Map<SecbenchClass, LibrarySourceRecall>();
  for (const cls of SECBENCH_CLASSES) byCls.set(cls, blank(cls));
  const all = blank("ALL");
  for (const e of entries) {
    if (!scannedKeys.has(e.key)) continue;
    const row = byCls.get(e.cls)!;
    row.scanned += 1; all.scanned += 1;
    if (libHitKeys.has(e.key)) { row.libFlagged += 1; all.libFlagged += 1; }
  }
  return { perClass: [...byCls.values()], all };
}
