// CycloneDX 1.5 SBOM export (#887) — the procurement artifact. Not a detection capability: an SBOM
// finds nothing. It exists because enterprise and public-sector buyers require one contractually
// and it is a line on every vendor security questionnaire. Hand-rolled: CycloneDX is plain JSON.
//
// ── Where the component list comes from ──────────────────────────────────────────────────────────
// The issue that asked for this assumed Harvey already parses lockfiles. It does not — measured
// 2026-07-23: `checkLockfilePresence` only checks that a lockfile EXISTS, and osv-scanner (an
// external binary) does the parsing, reporting back only the packages that have vulnerabilities
// (7 of 393 on targets/calibration). So the parsing is here, dependency-free, per format.
//
// ── Completeness is the whole risk with an SBOM ──────────────────────────────────────────────────
// An SBOM's failure mode is identical to the coverage ledger's: a partial one presented as whole is
// worse than none, because the buyer's tooling will treat the missing components as absent rather
// than unlisted. So completeness is stated in the document, three ways:
//   • `compositions[].aggregate` — CycloneDX's own field for exactly this ("complete" only when a
//     lockfile was fully parsed; "incomplete" for a manifest-only fallback; "unknown" otherwise).
//   • `metadata.properties` — a plain-text "harvey:completeness" note naming the source and, when
//     the tree is not resolved, saying so in a sentence a human reads.
//   • buildSbom returns `warning`, so the CLI prints it and the operator sees it at generation time.
// A lockfile Harvey cannot parse never yields a silently-thinner BOM: it degrades to the manifest's
// direct dependencies and says that is what happened.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const SPEC_VERSION = "1.5";

type SbomCompleteness = "complete" | "incomplete" | "unknown";

interface SbomComponent {
  name: string;
  version: string;
  dev?: boolean;
}

interface DependencySource {
  components: SbomComponent[];
  source: string; // the file the components came from
  completeness: SbomCompleteness;
  note: string;
}

// package-lock.json v2/v3 keys every installed package by its node_modules path; v1 nests them
// under `dependencies`. Both carry the RESOLVED version, which is what an SBOM needs.
export function parsePackageLock(text: string): SbomComponent[] {
  const lock = JSON.parse(text) as {
    packages?: Record<string, { version?: string; dev?: boolean }>;
    dependencies?: Record<string, { version?: string; dev?: boolean; dependencies?: Record<string, unknown> }>;
  };
  const out = new Map<string, SbomComponent>();

  for (const [path, meta] of Object.entries(lock.packages ?? {})) {
    // "" is the root project itself, not a dependency; it is the BOM's subject, not a component.
    if (path === "" || !meta.version) continue;
    const name = path.replace(/^(?:.*\/)?node_modules\//, "");
    if (!name) continue;
    out.set(`${name}@${meta.version}`, { name, version: meta.version, ...(meta.dev ? { dev: true } : {}) });
  }

  const walkV1 = (deps: Record<string, { version?: string; dev?: boolean; dependencies?: Record<string, unknown> }>): void => {
    for (const [name, meta] of Object.entries(deps)) {
      if (meta.version) out.set(`${name}@${meta.version}`, { name, version: meta.version, ...(meta.dev ? { dev: true } : {}) });
      if (meta.dependencies) walkV1(meta.dependencies as Record<string, { version?: string; dev?: boolean }>);
    }
  };
  if (!lock.packages && lock.dependencies) walkV1(lock.dependencies);

  return [...out.values()];
}

// pnpm-lock.yaml, `packages:` section only. Three key shapes across lockfile versions:
//   v5: /braces/2.3.2:      v6: /braces@2.3.2:      v9: 'braces@2.3.2':
// Parsed by line rather than with a YAML dependency (adding one is an operator decision, and the
// section's grammar is this narrow).
export function parsePnpmLock(text: string): SbomComponent[] {
  const out = new Map<string, SbomComponent>();
  let inPackages = false;
  for (const line of text.split("\n")) {
    if (/^packages:\s*$/.test(line)) {
      inPackages = true;
      continue;
    }
    // Any other column-0 key ends the section.
    if (inPackages && /^\S/.test(line)) break;
    if (!inPackages) continue;

    const key = /^\s{2}'?\/?(@?[^'@\s]+(?:\/[^'@\s]+)?)[@/]([0-9][^'\s:(]*)'?(?:\([^)]*\))*'?:\s*$/.exec(line);
    if (key?.[1] && key[2]) out.set(`${key[1]}@${key[2]}`, { name: key[1], version: key[2] });
  }
  return [...out.values()];
}

// yarn.lock — both the v1 format (`braces@^2.3.1:` / `  version "2.3.2"`) and Berry's
// (`"braces@npm:^2.3.1":` / `  version: 2.3.2`).
export function parseYarnLock(text: string): SbomComponent[] {
  const out = new Map<string, SbomComponent>();
  let name: string | undefined;
  for (const line of text.split("\n")) {
    const header = /^"?(@?[^@"\s][^@"]*)@/.exec(line);
    if (/^\S/.test(line) && header?.[1] && line.trimEnd().endsWith(":")) {
      name = header[1];
      continue;
    }
    const version = /^\s+version:?\s+"?([^"\s]+)"?\s*$/.exec(line);
    if (name && version?.[1]) {
      out.set(`${name}@${version[1]}`, { name, version: version[1] });
      name = undefined;
    }
  }
  return [...out.values()];
}

const PARSERS: { file: string; parse: (text: string) => SbomComponent[] }[] = [
  { file: "package-lock.json", parse: parsePackageLock },
  { file: "pnpm-lock.yaml", parse: parsePnpmLock },
  { file: "yarn.lock", parse: parseYarnLock },
];

// The manifest fallback. Direct dependencies only and the declared RANGE rather than a resolved
// version — a real but plainly-labelled degradation, never presented as the resolved tree.
function manifestComponents(dir: string): SbomComponent[] {
  const path = join(dir, "package.json");
  if (!existsSync(path)) return [];
  const pkg = JSON.parse(readFileSync(path, "utf8")) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
  return [
    ...Object.entries(pkg.dependencies ?? {}).map(([name, version]) => ({ name, version })),
    ...Object.entries(pkg.devDependencies ?? {}).map(([name, version]) => ({ name, version, dev: true })),
  ];
}

export function collectDependencies(dir: string): DependencySource {
  for (const { file, parse } of PARSERS) {
    const path = join(dir, file);
    if (!existsSync(path)) continue;
    let components: SbomComponent[] = [];
    let parseError: string | undefined;
    try {
      components = parse(readFileSync(path, "utf8"));
    } catch (err) {
      parseError = (err as Error).message;
    }
    if (components.length > 0) {
      return { components, source: file, completeness: "complete", note: `Resolved dependency tree parsed from ${file}.` };
    }
    // A lockfile that is present but yields nothing is the dangerous case: it looks like a clean
    // parse. Degrade to the manifest and say the lockfile was not understood.
    const fallback = manifestComponents(dir);
    return {
      components: fallback,
      source: "package.json",
      completeness: "incomplete",
      note:
        `${file} is present but Harvey could not extract components from it${parseError ? ` (${parseError})` : ""}. ` +
        "This BOM lists the manifest's DIRECT dependencies at their declared version RANGES only — the transitive tree is NOT included and the versions are not resolved. Do not treat it as a complete inventory.",
    };
  }

  const fallback = manifestComponents(dir);
  if (fallback.length === 0) {
    return { components: [], source: "(none)", completeness: "unknown", note: "No lockfile and no package.json were found, so no dependency inventory could be built. This is an empty BOM, not a dependency-free project." };
  }
  return {
    components: fallback,
    source: "package.json",
    completeness: "incomplete",
    note: "No lockfile was found. This BOM lists the manifest's DIRECT dependencies at their declared version RANGES only — the transitive tree is NOT included and the versions are not resolved.",
  };
}

// purl (package-URL) for an npm component. The scope's leading "@" is percent-encoded; the "/"
// separating namespace from name is not. Every other character valid in an npm name is URL-safe.
function purl(c: SbomComponent): string {
  return `pkg:npm/${c.name.replace(/^@/, "%40")}@${encodeURIComponent(c.version)}`;
}

export function buildSbom(dir: string, opts: { targetName?: string; timestamp?: string } = {}): { bom: object; warning?: string } {
  const deps = collectDependencies(dir);
  const ref = (c: SbomComponent): string => `${c.name}@${c.version}`;

  const bom = {
    bomFormat: "CycloneDX",
    specVersion: SPEC_VERSION,
    version: 1,
    metadata: {
      timestamp: opts.timestamp ?? new Date().toISOString(),
      tools: { components: [{ type: "application", name: "Harvey", publisher: "Harvey" }] },
      component: { type: "application", "bom-ref": "root", name: opts.targetName ?? "target" },
      properties: [
        { name: "harvey:completeness", value: deps.completeness },
        { name: "harvey:source", value: deps.source },
        { name: "harvey:note", value: deps.note },
      ],
    },
    components: deps.components.map((c) => ({
      type: "library",
      "bom-ref": ref(c),
      name: c.name,
      version: c.version,
      purl: purl(c),
      // CycloneDX scope: dev-only dependencies are not part of the shipped artifact.
      ...(c.dev ? { scope: "optional" as const } : {}),
    })),
    // CycloneDX's own completeness statement. Kept alongside the properties above because a
    // consumer that ignores compositions must still be told, and vice versa.
    compositions: [{ aggregate: deps.completeness, dependencies: ["root"] }],
  };

  return { bom, ...(deps.completeness === "complete" ? {} : { warning: deps.note }) };
}
