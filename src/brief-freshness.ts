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
