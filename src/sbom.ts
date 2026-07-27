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
// direct dependencies and says that is what happened. #1079 closed the remaining hole: completeness
// used to be `components.length > 0`, so a parser recovering 1 of 900 entries still said "complete".
// Each parser now COUNTS the entries it could not resolve and completeness is derived from that.
//
// ── What the BOM carries per component ───────────────────────────────────────────────────────────
// name, version, purl, dev scope, plus (#1079) CycloneDX `licenses[]` and `hashes[]` — the two
// fields an enterprise buyer's checklist actually looks for. Both come from the lockfile Harvey
// already parses (MEASURED 2026-07-27 on targets/calibration/package-lock.json: 395 resolved
// components, 390 with `license`, 395 with `integrity`), so they cost nothing and require no network.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const SPEC_VERSION = "1.5";

type SbomCompleteness = "complete" | "incomplete" | "unknown";

interface SbomComponent {
  name: string;
  version: string;
  dev?: boolean;
  // #1079: both sit in the lockfile Harvey already parses, and both are on the checklist an
  // enterprise buyer runs against a delivered SBOM. `license` is npm's SPDX string (id or
  // expression); `integrity` is the Subresource-Integrity string (`sha512-<base64>`) that lets a
  // consumer verify the artifact they have is the one this BOM describes.
  license?: string;
  integrity?: string;
}

// #1079: `unmatched` is the whole point of this shape. Completeness used to be derived from
// `components.length > 0`, so a parser that recovered 1 of 900 entries still reported "complete"
// — the partial-presented-as-whole failure the module header calls THE risk with an SBOM. Every
// parser now counts the lockfile entries it saw and could not resolve, and completeness is
// derived from that count.
interface ParsedLock {
  components: SbomComponent[];
  unmatched: number;
}

interface DependencySource {
  components: SbomComponent[];
  source: string; // the file the components came from
  completeness: SbomCompleteness;
  note: string;
}

// package-lock.json v2/v3 keys every installed package by its node_modules path; v1 nests them
// under `dependencies`. Both carry the RESOLVED version, which is what an SBOM needs.
export function parsePackageLock(text: string): ParsedLock {
  interface LockEntry {
    version?: string;
    dev?: boolean;
    license?: string;
    integrity?: string;
    link?: boolean;
    dependencies?: Record<string, unknown>;
  }
  const lock = JSON.parse(text) as { packages?: Record<string, LockEntry>; dependencies?: Record<string, LockEntry> };
  const out = new Map<string, SbomComponent>();
  let unmatched = 0;
  const add = (name: string, meta: LockEntry): void => {
    out.set(`${name}@${meta.version ?? ""}`, {
      name,
      version: meta.version ?? "",
      ...(meta.dev ? { dev: true } : {}),
      ...(meta.license ? { license: meta.license } : {}),
      ...(meta.integrity ? { integrity: meta.integrity } : {}),
    });
  };

  for (const [path, meta] of Object.entries(lock.packages ?? {})) {
    // "" is the root project itself, not a dependency; it is the BOM's subject, not a component.
    // A `link: true` entry is a workspace symlink, not a published artifact — also not a component.
    if (path === "" || meta.link) continue;
    const name = path.replace(/^(?:.*\/)?node_modules\//, "");
    if (!name || !meta.version) {
      unmatched++;
      continue;
    }
    add(name, meta);
  }

  const walkV1 = (deps: Record<string, LockEntry>): void => {
    for (const [name, meta] of Object.entries(deps)) {
      if (meta.version) add(name, meta);
      else unmatched++;
      if (meta.dependencies) walkV1(meta.dependencies as Record<string, LockEntry>);
    }
  };
  if (!lock.packages && lock.dependencies) walkV1(lock.dependencies);

  return { components: [...out.values()], unmatched };
}

// pnpm-lock.yaml, `packages:` section only. Three key shapes across lockfile versions:
//   v5: /braces/2.3.2:      v6: /braces@2.3.2:      v9: 'braces@2.3.2':
// Parsed by line rather than with a YAML dependency (adding one is an operator decision, and the
// section's grammar is this narrow). pnpm carries no license field, but every entry's
// `resolution: {integrity: …}` is the same SRI hash package-lock records (#1079).
export function parsePnpmLock(text: string): ParsedLock {
  const out = new Map<string, SbomComponent>();
  let inPackages = false;
  let unmatched = 0;
  let current: SbomComponent | undefined;
  for (const line of text.split("\n")) {
    if (/^packages:\s*$/.test(line)) {
      inPackages = true;
      continue;
    }
    // Any other column-0 key ends the section.
    if (inPackages && /^\S/.test(line)) break;
    if (!inPackages) continue;

    const integrity = /^\s{4}resolution:\s*\{\s*integrity:\s*([^,}\s]+)/.exec(line);
    if (current && integrity?.[1]) {
      current.integrity = integrity[1];
      continue;
    }

    // A key line is at exactly two spaces of indent and ends with a colon. One that the version
    // regex cannot resolve is a package this parser did not recover — counted, not ignored.
    if (!/^\s{2}\S.*:\s*$/.test(line)) continue;
    const key = /^\s{2}'?\/?(@?[^'@\s]+(?:\/[^'@\s]+)?)[@/]([0-9][^'\s:(]*)'?(?:\([^)]*\))*'?:\s*$/.exec(line);
    if (key?.[1] && key[2]) {
      current = { name: key[1], version: key[2] };
      out.set(`${key[1]}@${key[2]}`, current);
    } else {
      current = undefined;
      unmatched++;
    }
  }
  return { components: [...out.values()], unmatched };
}

// yarn.lock — both the v1 format (`braces@^2.3.1:` / `  version "2.3.2"`) and Berry's
// (`"braces@npm:^2.3.1":` / `  version: 2.3.2`). v1 records `integrity`, Berry records `checksum`.
export function parseYarnLock(text: string): ParsedLock {
  const out = new Map<string, SbomComponent>();
  let name: string | undefined;
  let current: SbomComponent | undefined;
  let unmatched = 0;
  for (const line of text.split("\n")) {
    const header = /^"?(@?[^@"\s][^@"]*)@/.exec(line);
    if (/^\S/.test(line) && line.trimEnd().endsWith(":")) {
      // A header that never reaches a `version` line yielded no component — count it when the
      // next header arrives, so a truncated or unfamiliar entry cannot pass as a clean parse.
      if (name) unmatched++;
      name = header?.[1];
      current = undefined;
      if (!name) unmatched++;
      continue;
    }
    const integrity = /^\s+(?:integrity|checksum):?\s+"?([^"\s]+)"?\s*$/.exec(line);
    if (current && integrity?.[1]) {
      current.integrity = integrity[1];
      continue;
    }
    const version = /^\s+version:?\s+"?([^"\s]+)"?\s*$/.exec(line);
    if (name && version?.[1]) {
      current = { name, version: version[1] };
      out.set(`${name}@${version[1]}`, current);
      name = undefined;
    }
  }
  if (name) unmatched++;
  return { components: [...out.values()], unmatched };
}

const PARSERS: { file: string; parse: (text: string) => ParsedLock }[] = [
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
    let unmatched = 0;
    let parseError: string | undefined;
    try {
      ({ components, unmatched } = parse(readFileSync(path, "utf8")));
    } catch (err) {
      parseError = (err as Error).message;
    }
    if (components.length > 0) {
      // #1079: a parser that resolved SOME entries and skipped others is exactly the
      // partial-presented-as-whole case. Say how many were missed rather than calling it complete
      // because the array was non-empty.
      if (unmatched > 0) {
        return {
          components,
          source: file,
          completeness: "incomplete",
          note:
            `${file} was parsed, but ${unmatched} of ${components.length + unmatched} entries could not be resolved to a name and version and are MISSING from this BOM. ` +
            "Treat the component list as partial: an absent component here means unlisted, not absent from the project.",
        };
      }
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

export interface LicenseCandidate {
  name: string;
  version?: string;
  // The license the lockfile records, when its format has the field. package-lock.json does;
  // pnpm-lock.yaml and yarn.lock do not, so for those every candidate needs a registry lookup.
  license?: string;
  // Declared in a manifest (any of dependencies/devDependencies/optionalDependencies/
  // peerDependencies) rather than reached only through the resolved tree. Ordering, not
  // filtering: the registry-lookup budget is spent on declared packages first.
  direct: boolean;
}

export interface LicenseScope {
  candidates: LicenseCandidate[];
  source: string;
  completeness: SbomCompleteness;
  note: string;
  direct: number;
  transitive: number;
}

// #1213: the candidate set for checkLicenseCompliance, from the same parse the SBOM uses — so the
// BOM a client receives and the license findings can never disagree. It is the RESOLVED TREE, not
// the manifest: before #1213 the check read `{...dependencies, ...devDependencies}`, so a copyleft
// package reached only transitively (measured on ATC 2026-07-27: `sharp` is declared by no manifest
// in the workspace, yet `@img/sharp-*` appears 82 times in pnpm-lock.yaml, three of them
// LGPL-3.0-or-later) was never submitted to the check at all.
//
// Keyed by name@version, so a tree holding two versions of one package under different licenses
// yields both — the name-keyed map this replaced silently kept whichever entry parsed last.
// A manifest-declared name the tree never resolved is still a candidate (no lockfile at all, or an
// optionalDependency the lockfile skipped); it carries no version and no license, so it falls
// through to the registry lookup exactly as it did before.
export function licenseScope(dir: string, directNames: readonly string[]): LicenseScope {
  const deps = collectDependencies(dir);
  const declared = new Set(directNames);
  const candidates: LicenseCandidate[] = [];
  const resolved = new Set<string>();
  for (const c of deps.components) {
    resolved.add(c.name);
    candidates.push({
      name: c.name,
      ...(c.version ? { version: c.version } : {}),
      ...(c.license ? { license: c.license } : {}),
      direct: declared.has(c.name),
    });
  }
  for (const name of declared) {
    if (!resolved.has(name)) candidates.push({ name, direct: true });
  }
  return {
    candidates,
    source: deps.source,
    completeness: deps.completeness,
    note: deps.note,
    direct: candidates.filter((c) => c.direct).length,
    transitive: candidates.filter((c) => !c.direct).length,
  };
}

// purl (package-URL) for an npm component. The scope's leading "@" is percent-encoded; the "/"
// separating namespace from name is not. Every other character valid in an npm name is URL-safe.
function purl(c: SbomComponent): string {
  return `pkg:npm/${c.name.replace(/^@/, "%40")}@${encodeURIComponent(c.version)}`;
}

// CycloneDX splits a single SPDX id (`licenses[].license.id`) from a compound expression
// (`licenses[].expression`) — "(MIT OR Apache-2.0)" in the id field fails schema validation, which
// is the one thing a procurement pipeline will actually notice.
function licenses(c: SbomComponent): object[] | undefined {
  if (!c.license) return undefined;
  return /[\s()]/.test(c.license) ? [{ expression: c.license }] : [{ license: { id: c.license } }];
}

// npm records Subresource Integrity (`sha512-<base64>`); CycloneDX wants an algorithm name and a
// hex digest. A hash Harvey cannot convert is omitted rather than emitted in the wrong encoding —
// a consumer verifying against a malformed digest gets a mismatch, which is worse than no hash.
const SRI_ALG: Record<string, string> = { sha1: "SHA-1", sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" };

function hashes(c: SbomComponent): object[] | undefined {
  const [, alg, b64] = /^(sha1|sha256|sha384|sha512)-(.+)$/.exec(c.integrity ?? "") ?? [];
  if (!alg || !b64) return undefined;
  return [{ alg: SRI_ALG[alg], content: Buffer.from(b64, "base64").toString("hex") }];
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
        // #1079: licenses and hashes are the two fields a buyer checks, and how many components
        // actually carry them depends on the lockfile format (package-lock records both; pnpm and
        // yarn record only the integrity hash). State the coverage rather than letting a
        // half-populated field read as the whole picture.
        { name: "harvey:license-coverage", value: `${deps.components.filter((c) => c.license).length}/${deps.components.length} components carry a license from ${deps.source}` },
        { name: "harvey:hash-coverage", value: `${deps.components.filter((c) => c.integrity).length}/${deps.components.length} components carry an integrity hash from ${deps.source}` },
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
      ...(licenses(c) ? { licenses: licenses(c) } : {}),
      ...(hashes(c) ? { hashes: hashes(c) } : {}),
    })),
    // CycloneDX's own completeness statement. Kept alongside the properties above because a
    // consumer that ignores compositions must still be told, and vice versa.
    compositions: [{ aggregate: deps.completeness, dependencies: ["root"] }],
  };

  return { bom, ...(deps.completeness === "complete" ? {} : { warning: deps.note }) };
}
