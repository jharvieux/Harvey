// #664 (M1 #611 Gap A hardening): the service-role-literal class, moved from a semgrep
// base64-alignment SIGNATURE match to an actual JWT decode. Replaces the old `harvey-
// service-role-literal` semgrep rule (base.yml) so the two engines don't double-fire on the
// same construct. Two gaps closed:
//   - Gap A (exact decode): the payload segment is base64url-decoded and JSON-parsed, then
//     `role === "service_role"` is checked directly — exact regardless of claim spacing/key
//     order, instead of matching three alignment-shifted base64 encodings of the substring
//     `role":"service_role`.
//   - Gap B (demo-key correlation): the local-dev exclusion decodes `iss` and compares it to
//     "supabase-demo" directly (the same claim the gitleaks `supabase-demo-key-marker`
//     correlation targets in secrets.ts), instead of a base64 substring signature.
//   - Gap C (cross-file): `const KEY = "eyJ…"` exported from one module and imported into the
//     module that calls createClient(url, KEY) is resolved via the same import-resolution
//     helpers app-router.ts uses for its server->client cross-file leak check (relative imports
//     + tsconfig/jsconfig `paths` aliases) — one implementation, not a reimplementation.
// A malformed/non-3-segment literal decodes to undefined and is silently NOT a match (fail
// safe: most string literals reaching createClient's second argument in practice, e.g. a
// hardcoded local anon key with unusual formatting, are simply not JWTs).

import ts from "typescript";
import type { Finding } from "../findings.js";
import { resolveImport, type PathAlias } from "../detectors/app-router.js";
import { loc, parse, type SourceInput } from "../detectors/common.js";
import { mechanicalFinding } from "./common.js";

const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
const DEMO_ISS = "supabase-demo";

interface DecodedJwtPayload {
  role?: unknown;
  iss?: unknown;
}

function decodeJwtPayload(literal: string): DecodedJwtPayload | undefined {
  const parts = literal.split(".");
  const payloadPart = parts.length === 3 ? parts[1] : undefined;
  if (!payloadPart) return undefined;
  try {
    return JSON.parse(Buffer.from(payloadPart, "base64url").toString("utf8")) as DecodedJwtPayload;
  } catch {
    return undefined;
  }
}

function isLeakedServiceRoleLiteral(literal: string): boolean {
  const payload = decodeJwtPayload(literal);
  return payload?.role === "service_role" && payload.iss !== DEMO_ISS;
}

// Every top-level `const $NAME = "$LITERAL"` in the file — the same-file const-propagation case
// semgrep's constant propagation used to resolve.
function collectStringConsts(sf: ts.SourceFile): Map<string, string> {
  const consts = new Map<string, string>();
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer && ts.isStringLiteralLike(node.initializer)) {
      consts.set(node.name.text, node.initializer.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return consts;
}

interface NamedImport {
  local: string;
  imported: string;
  modulePath: string;
}

function collectNamedImports(sf: ts.SourceFile, path: string, importGraph: ReadonlyMap<string, readonly string[]>, aliases: PathAlias[]): NamedImport[] {
  const imports: NamedImport[] = [];
  const reachable = new Set(importGraph.get(path) ?? []);
  const allPaths = new Set(importGraph.keys());
  for (const stmt of sf.statements) {
    if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier) || !stmt.importClause?.namedBindings) continue;
    if (!ts.isNamedImports(stmt.importClause.namedBindings)) continue;
    const resolved = resolveImport(path, stmt.moduleSpecifier.text, allPaths, aliases);
    if (!resolved || !reachable.has(resolved)) continue;
    for (const el of stmt.importClause.namedBindings.elements) {
      imports.push({ local: el.name.text, imported: (el.propertyName ?? el.name).text, modulePath: resolved });
    }
  }
  return imports;
}

interface CreateClientSite {
  node: ts.CallExpression;
  keyArg: ts.Expression;
}

function findCreateClientSites(sf: ts.SourceFile): CreateClientSite[] {
  const sites: CreateClientSite[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === "createClient" && node.arguments.length >= 2) {
      const keyArg = node.arguments[1];
      if (keyArg && (ts.isStringLiteralLike(keyArg) || ts.isIdentifier(keyArg))) sites.push({ node, keyArg });
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return sites;
}

interface ResolvedKey {
  literal: string;
  crossFileFrom?: string;
}

function resolveKeyLiteral(keyArg: ts.Expression, sameFileConsts: Map<string, string>, namedImports: NamedImport[], exportsByPath: ReadonlyMap<string, Map<string, string>>): ResolvedKey | undefined {
  if (ts.isStringLiteralLike(keyArg)) return { literal: keyArg.text };
  if (!ts.isIdentifier(keyArg)) return undefined;
  const name = keyArg.text;
  const same = sameFileConsts.get(name);
  if (same !== undefined) return { literal: same };
  const imp = namedImports.find((i) => i.local === name);
  if (!imp) return undefined;
  const remote = exportsByPath.get(imp.modulePath)?.get(imp.imported);
  return remote !== undefined ? { literal: remote, crossFileFrom: imp.modulePath } : undefined;
}

function detectFile(path: string, sf: ts.SourceFile, importGraph: ReadonlyMap<string, readonly string[]>, aliases: PathAlias[], exportsByPath: ReadonlyMap<string, Map<string, string>>): Finding[] {
  const sites = findCreateClientSites(sf);
  if (sites.length === 0) return [];
  const sameFileConsts = collectStringConsts(sf);
  const namedImports = collectNamedImports(sf, path, importGraph, aliases);

  const findings: Finding[] = [];
  for (const site of sites) {
    const resolved = resolveKeyLiteral(site.keyArg, sameFileConsts, namedImports, exportsByPath);
    if (!resolved || !isLeakedServiceRoleLiteral(resolved.literal)) continue;
    const crossFileNote = resolved.crossFileFrom ? ` The key is imported from ${resolved.crossFileFrom}.` : "";
    findings.push(
      mechanicalFinding({
        id: `SEC-SRL-${path.replace(/[^a-zA-Z0-9]+/g, "-")}-${site.node.getStart(sf)}`,
        title: `${path} — service_role key hardcoded as a JWT literal and passed to createClient`,
        severity: "Critical",
        category: "Secret exposure",
        taxonomy: "Supabase service_role key hardcoded as a JWT literal (service-role-literal)",
        location: loc(path, sf, site.node),
        evidence: `Heuristic "service-role-literal": the decoded JWT payload carries role:"service_role" (iss !== "${DEMO_ISS}").${crossFileNote}`,
        impact: "Anyone with the source (or the shipped bundle, in a Vite/no-code SPA) gets full RLS bypass.",
        fix: "Never inline a service_role key; keep it server-side and read it from a secret store/env var.",
        precisionTier: "high",
      }),
    );
  }
  return findings;
}

export function detectServiceRoleLiteralFindings(files: SourceInput[], importGraph: ReadonlyMap<string, readonly string[]>, aliases: PathAlias[]): Finding[] {
  const sourceFiles = files.filter((f) => SOURCE_EXT.test(f.path));
  const parsed = sourceFiles.map((f) => ({ path: f.path, sf: parse(f.path, f.text) }));
  const exportsByPath = new Map(parsed.map((p) => [p.path, collectStringConsts(p.sf)]));
  return parsed.flatMap(({ path, sf }) => detectFile(path, sf, importGraph, aliases, exportsByPath));
}
