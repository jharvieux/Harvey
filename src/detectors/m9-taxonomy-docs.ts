import { posix } from "node:path";
import ts from "typescript";
import { parse } from "./common.js";

export interface SourceText {
  readonly path: string;
  readonly text: string;
}

interface TaxonomySite {
  readonly path: string;
  readonly line: number;
  readonly expression: string;
}

interface TaxonomyExclusion extends TaxonomySite {
  readonly kind: "scope" | "not-assessed" | "not-applicable";
}

interface TaxonomyAlias {
  readonly emitted: string;
  readonly documentedAs: string;
}

interface M9TaxonomyRegistry {
  readonly sourcePaths: readonly string[];
  readonly emittedM9Taxonomies: readonly string[];
  readonly canonicalM9Families: readonly string[];
  readonly emittedRoutedTaxonomies: readonly string[];
  readonly aliases: readonly TaxonomyAlias[];
  readonly exclusions: readonly TaxonomyExclusion[];
  readonly unreadTaxonomySites: readonly TaxonomySite[];
}

interface DocumentedCheckHeader {
  readonly line: number;
  readonly heading: string;
  readonly taxonomies: readonly string[];
}

interface M9TaxonomyParityReport {
  readonly registry: M9TaxonomyRegistry;
  readonly headers: readonly DocumentedCheckHeader[];
  readonly violations: readonly string[];
}

const ENTRY = "src/detectors/app-router.ts";
const TAXONOMY_PREFIX = /^M(?:1|9) — /;
const TAXONOMY_CODE = /`(M(?:1|9) — [^`]+)`/g;

/**
 * Adapter-specific nouns are one emitted check family, not three documentation families. The
 * operator-facing doc names the original Next spelling; Remix/RR7 and TanStack reuse that check.
 */
function canonicalDocumentedTaxonomy(taxonomy: string): string {
  if (/^M9 — .+ missing input validation$/.test(taxonomy)) return "M9 — Server Action missing input validation";
  if (/^M1 — .+ missing authorization check$/.test(taxonomy)) return "M1 — Server Action missing authorization check";
  return taxonomy;
}

function propertyName(node: ts.PropertyName): string | undefined {
  return ts.isIdentifier(node) || ts.isStringLiteral(node) ? node.text : undefined;
}

function site(path: string, sf: ts.SourceFile, node: ts.Node): TaxonomySite {
  return {
    path,
    line: sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1,
    expression: node.getText(sf),
  };
}

function sourceCandidates(importer: string, specifier: string): string[] {
  const base = posix.normalize(posix.join(posix.dirname(importer), specifier));
  const withoutJs = base.replace(/\.(?:mjs|cjs|js|jsx)$/, "");
  return [base, withoutJs, `${withoutJs}.ts`, `${withoutJs}.tsx`, `${withoutJs}.mts`, `${withoutJs}.cts`, `${withoutJs}/index.ts`, `${withoutJs}/index.tsx`];
}

/** The relative-import dependency closure is the production ownership boundary for this detector. */
function detectorClosure(all: ReadonlyMap<string, SourceText>, entry = ENTRY): string[] {
  if (!all.has(entry)) return [];
  const reached = new Set<string>();
  const pending = [entry];
  while (pending.length > 0) {
    const path = pending.pop();
    if (path === undefined || reached.has(path)) continue;
    reached.add(path);
    const source = all.get(path);
    if (!source) continue;
    const sf = parse(path, source.text);
    for (const statement of sf.statements) {
      if (ts.isImportDeclaration(statement) && statement.importClause?.isTypeOnly) continue;
      if (ts.isExportDeclaration(statement) && statement.isTypeOnly) continue;
      const moduleSpecifier =
        ts.isImportDeclaration(statement) || ts.isExportDeclaration(statement) ? statement.moduleSpecifier : undefined;
      if (!moduleSpecifier || !ts.isStringLiteral(moduleSpecifier) || !moduleSpecifier.text.startsWith(".")) continue;
      const target = sourceCandidates(path, moduleSpecifier.text).find((candidate) => all.has(candidate));
      if (target && !reached.has(target)) pending.push(target);
    }
  }
  return [...reached].sort();
}

function exclusionKind(taxonomy: string): TaxonomyExclusion["kind"] | undefined {
  if (taxonomy.endsWith(" — scope")) return "scope";
  if (taxonomy.includes(" — not assessed")) return "not-assessed";
  if (taxonomy.startsWith("M9 — Not assessed")) return "not-assessed";
  if (taxonomy.startsWith("M9 — Not applicable")) return "not-applicable";
  return undefined;
}

function addLiteral(
  taxonomy: string,
  at: TaxonomySite,
  emittedM9: Set<string>,
  routed: Set<string>,
  exclusions: TaxonomyExclusion[],
): void {
  if (!TAXONOMY_PREFIX.test(taxonomy)) return;
  const kind = exclusionKind(taxonomy);
  if (kind) {
    exclusions.push({ ...at, kind, expression: JSON.stringify(taxonomy) });
  } else if (taxonomy.startsWith("M9 — ")) {
    emittedM9.add(taxonomy);
  } else {
    routed.add(taxonomy);
  }
}

function literalValues(node: ts.Expression): string[] | undefined {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return [node.text];
  if (ts.isConditionalExpression(node)) {
    const yes = literalValues(node.whenTrue);
    const no = literalValues(node.whenFalse);
    return yes && no ? [...yes, ...no] : undefined;
  }
  return undefined;
}

function dynamicTaxonomy(
  path: string,
  sf: ts.SourceFile,
  node: ts.TemplateExpression,
  mutationNouns: readonly string[],
  emittedM9: Set<string>,
  routed: Set<string>,
  exclusions: TaxonomyExclusion[],
): boolean {
  const at = site(path, sf, node);
  const first = node.templateSpans[0];
  const second = node.templateSpans[1];
  if (
    first !== undefined &&
    second === undefined &&
    ts.isIdentifier(first.expression) &&
    first.expression.text === "noun"
  ) {
    const suffix = first.literal.text;
    if (node.head.text === "M9 — " && suffix === " missing input validation") {
      for (const noun of mutationNouns) emittedM9.add(`M9 — ${noun}${suffix}`);
      return mutationNouns.length > 0;
    }
    if (node.head.text === "M1 — " && suffix === " missing authorization check") {
      for (const noun of mutationNouns) routed.add(`M1 — ${noun}${suffix}`);
      return mutationNouns.length > 0;
    }
  }

  // The base taxonomies are literal rows in DATA_LAYER_CHECKS and are counted above. This
  // expression emits only their disclosed not-assessed variants.
  if (
    node.head.text === "" &&
    first !== undefined &&
    second === undefined &&
    ts.isIdentifier(first.expression) &&
    first.expression.text === "taxonomy" &&
    first.literal.text === " — not assessed"
  ) {
    exclusions.push({ ...at, kind: "not-assessed" });
    return true;
  }

  // Boundary adapters emit one such row per unsupported check/framework pair. It is an explicit
  // disclosure population, not a finding family that needs its own Checks header.
  if (
    node.head.text === "M9 — " &&
    first !== undefined &&
    second !== undefined &&
    node.templateSpans[2] === undefined &&
    ts.isIdentifier(first.expression) &&
    first.expression.text === "checkLabel" &&
    first.literal.text === " — not assessed (" &&
    ts.isIdentifier(second.expression) &&
    second.expression.text === "label" &&
    second.literal.text === ")"
  ) {
    exclusions.push({ ...at, kind: "not-assessed" });
    return true;
  }
  return false;
}

/** Build the emitted registry from the detector's current production dependency closure. */
function buildM9TaxonomyRegistry(sources: readonly SourceText[]): M9TaxonomyRegistry {
  const all = new Map(sources.map((source) => [source.path, source]));
  const sourcePaths = detectorClosure(all);
  const mutationNouns = new Set<string>();
  const unreadTaxonomySites: TaxonomySite[] = [];

  for (const path of sourcePaths) {
    const source = all.get(path);
    if (!source) continue;
    const sf = parse(path, source.text);
    const walk = (node: ts.Node): void => {
      if (ts.isPropertyAssignment(node) && propertyName(node.name) === "mutationNoun") {
        if (ts.isStringLiteral(node.initializer)) mutationNouns.add(node.initializer.text);
        else unreadTaxonomySites.push({ ...site(path, sf, node.initializer), expression: `mutationNoun: ${node.initializer.getText(sf)}` });
      }
      ts.forEachChild(node, walk);
    };
    walk(sf);
  }

  const emittedM9 = new Set<string>();
  const routed = new Set<string>();
  const exclusions: TaxonomyExclusion[] = [];
  for (const path of sourcePaths) {
    const source = all.get(path);
    if (!source) continue;
    const sf = parse(path, source.text);
    const walk = (node: ts.Node): void => {
      if (ts.isPropertyAssignment(node) && propertyName(node.name) === "taxonomy") {
        const at = site(path, sf, node.initializer);
        const literals = literalValues(node.initializer);
        if (literals) {
          for (const value of literals) addLiteral(value, at, emittedM9, routed, exclusions);
        } else if (!ts.isTemplateExpression(node.initializer) || !dynamicTaxonomy(path, sf, node.initializer, [...mutationNouns], emittedM9, routed, exclusions)) {
          unreadTaxonomySites.push(at);
        }
      } else if (ts.isShorthandPropertyAssignment(node) && node.name.text === "taxonomy") {
        unreadTaxonomySites.push(site(path, sf, node));
      }
      ts.forEachChild(node, walk);
    };
    walk(sf);
  }

  const emittedM9Taxonomies = [...emittedM9].sort();
  const emittedRoutedTaxonomies = [...routed].sort();
  const aliases = [...emittedM9Taxonomies, ...emittedRoutedTaxonomies]
    .map((emitted): TaxonomyAlias => ({ emitted, documentedAs: canonicalDocumentedTaxonomy(emitted) }))
    .filter((row) => row.emitted !== row.documentedAs)
    .sort((a, b) => a.emitted.localeCompare(b.emitted));
  return {
    sourcePaths,
    emittedM9Taxonomies,
    canonicalM9Families: [...new Set(emittedM9Taxonomies.map(canonicalDocumentedTaxonomy))].sort(),
    emittedRoutedTaxonomies,
    aliases,
    exclusions: exclusions.sort((a, b) => a.path.localeCompare(b.path) || a.line - b.line),
    unreadTaxonomySites: unreadTaxonomySites.sort((a, b) => a.path.localeCompare(b.path) || a.line - b.line),
  };
}

/** Read only the operator-facing Checks section; later calibration prose is not a check header. */
function documentedCheckHeaders(markdown: string): DocumentedCheckHeader[] {
  const lines = markdown.split(/\r?\n/);
  const checks = lines.findIndex((line) => line.trim() === "## Checks");
  if (checks < 0) return [];
  const headers: DocumentedCheckHeader[] = [];
  for (let index = checks + 1; index < lines.length; index++) {
    const line = lines[index] ?? "";
    if (/^## /.test(line)) break;
    if (!/^### /.test(line)) continue;
    headers.push({
      line: index + 1,
      heading: line.slice("### ".length),
      taxonomies: [...line.matchAll(TAXONOMY_CODE)].map((match) => match[1] as string),
    });
  }
  return headers;
}

/** Bidirectional source↔doc parity, with disclosure rows enumerated rather than silently dropped. */
export function compareM9TaxonomyDocs(sources: readonly SourceText[], markdown: string): M9TaxonomyParityReport {
  const registry = buildM9TaxonomyRegistry(sources);
  const headers = documentedCheckHeaders(markdown);
  const violations: string[] = [];
  if (registry.sourcePaths.length === 0) violations.push(`${ENTRY} is absent, so no production taxonomy population was read`);
  for (const row of registry.unreadTaxonomySites) {
    violations.push(`${row.path}:${row.line} taxonomy emission expression is not classified: ${row.expression}`);
  }
  if (headers.length === 0) violations.push("docs/m9-app-router.md has no readable ## Checks / ### header population");
  for (const header of headers) {
    if (header.taxonomies.length === 0) violations.push(`docs/m9-app-router.md:${header.line} check header names no M1/M9 taxonomy: ${header.heading}`);
  }

  const documentedM9 = new Set(
    headers.flatMap((header) => header.taxonomies).filter((taxonomy) => taxonomy.startsWith("M9 — ")).map(canonicalDocumentedTaxonomy),
  );
  const documentedRouted = new Set(
    headers.flatMap((header) => header.taxonomies).filter((taxonomy) => taxonomy.startsWith("M1 — ")).map(canonicalDocumentedTaxonomy),
  );
  const sourceM9 = new Set(registry.canonicalM9Families);
  const sourceRouted = new Set(registry.emittedRoutedTaxonomies.map(canonicalDocumentedTaxonomy));

  for (const taxonomy of sourceM9) {
    if (!documentedM9.has(taxonomy)) violations.push(`shipped M9 taxonomy has no Checks header: ${taxonomy}`);
  }
  for (const taxonomy of documentedM9) {
    if (!sourceM9.has(taxonomy)) violations.push(`Checks header names an M9 taxonomy that no longer ships: ${taxonomy}`);
  }
  for (const taxonomy of documentedRouted) {
    if (!sourceRouted.has(taxonomy)) violations.push(`Checks header names a routed M1 taxonomy that no longer ships: ${taxonomy}`);
  }

  return { registry, headers, violations };
}
