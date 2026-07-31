// briefs/anti-patterns.md is Harvey's VENDORED copy of ATC's canonical D-091 catalog, and
// briefs/scan-extras.txt is the M1 semantic brief derived from it. This diffs the vendored copy
// against a target repo that ships its OWN copy of the same catalog (conventionally at
// docs/runbooks/anti-patterns.md in the target — the target's layout, not Harvey's), so an engagement fails loud
// when Harvey's brief is BEHIND the source it was derived from (#678). Comparison is by class
// TITLE (not the item number) because Harvey renumbers — a reworded or added class in the target
// is exactly the drift we want to surface.

const CLASS_HEADER = /^#{2,3}\s+\d+\.\s+(.+?)\s*$/gm;

function normalizeTitle(raw: string): string {
  return raw
    .replace(/\s*\([^)]*#\d[^)]*\)\s*$/, "") // drop a trailing (…#nnn…) issue-ref parenthetical
    .replace(/[`*_]/g, "") // strip markdown emphasis
    .toLowerCase()
    .replace(/[.\s]+$/, "")
    .replace(/\s+/g, " ")
    .trim();
}

function parseCatalogClasses(md: string): string[] {
  return [...md.matchAll(CLASS_HEADER)].map((m) => normalizeTitle(m[1] ?? ""));
}

interface CatalogDiff {
  missing: string[]; // classes catalogued in the target, absent from the vendored copy → drift
  vendoredExtra: string[]; // classes the vendored copy has that the target lacks (informational)
}

export function diffCatalog(vendoredMd: string, targetMd: string): CatalogDiff {
  const vendored = new Set(parseCatalogClasses(vendoredMd));
  const target = new Set(parseCatalogClasses(targetMd));
  return {
    missing: [...target].filter((t) => !vendored.has(t)),
    vendoredExtra: [...vendored].filter((v) => !target.has(v)),
  };
}


// #678 criterion 2 — WHICH catalog version the brief was built from. `pnpm brief-freshness` answers
// "is the vendored copy behind THIS target?", which needs a target that ships the catalog; a client
// repo does not, and then nothing in the run says what the M1 semantic brief was derived from. The
// provenance line in briefs/anti-patterns.md is the single source: it names the ATC commit and the
// class count, and it is the line a re-sync has to update anyway.
//
// Read, not restated: a hardcoded copy here would be the "two documents citing one guess" shape —
// it would keep printing 04a565d after someone re-synced the catalog and forgot this file.
const PROVENANCE_LINE = /Last synced from ATC @ `([0-9a-f]{7,40})`\s*\(([^)]*)\)/;

interface CatalogProvenance {
  commit: string;
  synced: string;
  classes: number;
}

/** Parsed from the vendored catalog's own provenance line; undefined when that line is absent. */
export function catalogProvenance(vendoredMd: string): CatalogProvenance | undefined {
  const m = PROVENANCE_LINE.exec(vendoredMd);
  if (!m) return undefined;
  return { commit: m[1]!, synced: m[2]!.trim(), classes: parseCatalogClasses(vendoredMd).length };
}

/** One line for the engagement banner and the report's methodology record. */
export function formatCatalogProvenance(p: CatalogProvenance | undefined): string {
  if (!p) return "M1 semantic brief (D-091): vendored catalog carries NO provenance line — version unrecorded (#678).";
  return `M1 semantic brief (D-091): ${p.classes} classes, vendored from ATC @ ${p.commit} (${p.synced}).`;
}

/**
 * The engagement-start check (#678 criterion 1). Returns the banner lines to print and whether the
 * run should fail loud: the vendored brief being BEHIND a target that ships the same catalog means
 * the M1 semantic pass is about to hunt an out-of-date class list.
 */
export function briefFreshnessBanner(vendoredMd: string, targetMd: string | undefined): { lines: string[]; behind: string[] } {
  const lines = [formatCatalogProvenance(catalogProvenance(vendoredMd))];
  if (targetMd === undefined) {
    lines.push("  target ships no D-091 catalog of its own — nothing to diff the vendored brief against.");
    return { lines, behind: [] };
  }
  const { missing, vendoredExtra } = diffCatalog(vendoredMd, targetMd);
  if (vendoredExtra.length) lines.push(`  ${vendoredExtra.length} vendored-only class(es) the target does not catalogue (informational).`);
  if (missing.length === 0) lines.push("  vendored brief covers every class the target catalogues.");
  else lines.push(`  BEHIND the target by ${missing.length} class(es): ${missing.join("; ")}`);
  return { lines, behind: missing };
}
