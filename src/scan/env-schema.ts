// #679 ENV-SCHEMA — env-var completeness. Diffs the set of env-var reads across the target's product
// source (`process.env.X`, plus `import.meta.env.X` on the Vite family, #902) against the set of keys
// DECLARED in its env schema module(s), and classifies a client-exposed read by the framework's own
// public prefix (NEXT_PUBLIC_ / VITE_ / PUBLIC_ …, #902). A read of
// an UNDECLARED key is a finding (config drift: an undocumented required var that a fresh deploy
// can silently miss, or a typo'd read that reads `undefined`); a declared key that is NEVER read is
// Info (a dead declaration). Reads inside the schema module itself and in test/fixture files don't
// count — the schema module's job IS to touch `process.env`. If no env schema module is found,
// emits nothing: no schema, no diff.
//
// This is a COMPLETENESS check (a two-set diff), not the code-SHAPE detection that
// src/detectors/handrolled.ts does over `process.env` — that class is new here.
//
// Review tier, never free-count: locating the schema module and extracting its declared key set is
// heuristic across several real-world shapes (@t3-oss `createEnv`, a `z.object` over `process.env`,
// or a plain exported map wiring `process.env.X` into named fields), so it is a signal to review,
// not a ground-truth verdict.

import ts from "typescript";
import type { Finding } from "../findings.js";
import { loc, parse, type SourceInput } from "../detectors/common.js";
import { NON_PRODUCT } from "../detectors/load-sources.js";
import { mechanicalFinding } from "./common.js";
import { envConvention, type EnvConvention, type TargetFramework } from "./framework-detect.js";
import type { PathScopedClass } from "./path-scope.js";

const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs|mts|cts)$/;

// A file that DECLARES the env surface — recognized by SHAPE, not just a name, so neither a
// `lib/env.js` that merely does `process.env.NODE_ENV = "..."` nor a helper that validates one
// config value with zod is mistaken for the app's env schema:
//   - the @t3-oss `createEnv(...)` builder anywhere;
//   - a schema that validates the WHOLE process.env object (`schema.parse(process.env)` /
//     `.safeParse(process.env)`) — the canonical zod/valibot env-schema shape;
//   - a module NAMED `env.<ext>` that actually enumerates at least one env key.
const SCHEMA_PATH = /(^|\/)env\.(ts|tsx|js|jsx|mjs|cjs|mts|cts)$/;
const CREATE_ENV = /\bcreateEnv\s*\(/;
// #902: the Vite-family env schema validates `import.meta.env`, not `process.env`.
const PARSE_ENV = /\.(parse|safeParse)\s*\(\s*(process\.env|import\.meta\.env)\b/;

/** The production preselector for modules that can declare the target's environment schema. */
export function envSchemaModuleCandidates(files: readonly SourceInput[]): SourceInput[] {
  return files.filter(
    (file) =>
      SOURCE_EXT.test(file.path) &&
      !NON_PRODUCT.test(file.path) &&
      (SCHEMA_PATH.test(file.path) || CREATE_ENV.test(file.text) || PARSE_ENV.test(file.text)),
  );
}

export const ENV_SCHEMA_PATH_SCOPE_CLASSES: readonly PathScopedClass[] = [
  {
    rowId: "M1-PATHSCOPE-ENV-SCHEMA-00",
    detector: "env-schema",
    classId: "Environment schema completeness diff",
    ownerFile: "src/scan/env-schema.ts",
    inventory: "env-source-files",
    selectorSymbol: "envSchemaModuleCandidates",
    convention: "product schema modules named `env.*`, calling `createEnv(...)`, or parsing the whole runtime env object",
    select: envSchemaModuleCandidates,
    classes: "the declared-versus-read environment-variable completeness diff",
  },
];

// #902: the framework-native env accesses the process.env/import.meta.env read-diff below cannot
// see. When present on a target whose framework has one (SvelteKit / Nuxt), the pass discloses that
// its completeness check is partial rather than letting the unseen surface read as fully assessed.
const UNMODELED_ENV_ACCESS: Partial<Record<TargetFramework, RegExp>> = {
  sveltekit: /\$env\/(static|dynamic)\/(public|private)/,
  nuxt: /\bruntimeConfig\b|\buseRuntimeConfig\s*\(/,
};

// Shape of an environment-variable key: UPPER_SNAKE (covers NEXT_PUBLIC_*/VITE_* too).
const ENV_KEY = /^[A-Z][A-Z0-9_]*$/;

// Runtime/framework-provided vars that legitimately go undeclared in an app's own schema — reads
// of these are not config-drift findings even when the schema doesn't list them.
const BUILTIN_ENV = new Set([
  "NODE_ENV", "CI", "PORT", "HOST", "HOSTNAME", "PWD", "HOME", "PATH", "TZ", "TMPDIR", "LANG",
  "NEXT_RUNTIME", "ANALYZE",
  "VERCEL", "VERCEL_ENV", "VERCEL_URL", "VERCEL_REGION", "VERCEL_BRANCH_URL",
]);

// `process.env` recognized as a `process.env` property/element base.
function isProcessEnv(node: ts.Expression): boolean {
  return ts.isPropertyAccessExpression(node) && node.name.text === "env" && ts.isIdentifier(node.expression) && node.expression.text === "process";
}

// #902: `import.meta.env` — the Vite-family client-env base (`import.meta` is a MetaProperty node).
function isImportMetaEnv(node: ts.Expression): boolean {
  return (
    ts.isPropertyAccessExpression(node) &&
    node.name.text === "env" &&
    ts.isMetaProperty(node.expression) &&
    node.expression.keywordToken === ts.SyntaxKind.ImportKeyword
  );
}

// The env base(s) this target reads: always `process.env`; `import.meta.env` too on the Vite family.
function isEnvBase(node: ts.Expression, importMeta: boolean): boolean {
  return isProcessEnv(node) || (importMeta && isImportMetaEnv(node));
}

// The LHS of `process.env.X = …` is a WRITE (e.g. the P-NODE-ENV-NOT-PROD footgun), not a read of
// X and not a declaration of it — a different class owns that.
function isAssignmentTarget(node: ts.Node): boolean {
  const p = node.parent;
  return !!p && ts.isBinaryExpression(p) && p.left === node && p.operatorToken.kind === ts.SyntaxKind.EqualsToken;
}

// The env key READ by a `process.env.X` / `process.env["X"]` access (or the import.meta.env
// equivalent on the Vite family), if this node is one (writes excluded).
function envKeyOf(node: ts.Node, importMeta: boolean): string | undefined {
  if (isAssignmentTarget(node)) return undefined;
  if (ts.isPropertyAccessExpression(node) && isEnvBase(node.expression, importMeta)) return node.name.text;
  if (ts.isElementAccessExpression(node) && isEnvBase(node.expression, importMeta) && ts.isStringLiteralLike(node.argumentExpression)) {
    return node.argumentExpression.text;
  }
  return undefined;
}

function isSchemaModule(file: SourceInput, sf: ts.SourceFile, importMeta: boolean): boolean {
  if (CREATE_ENV.test(file.text)) return true;
  if (PARSE_ENV.test(file.text)) return true;
  // Named `env.*` counts only if it genuinely declares an env key — not just any file so named.
  return SCHEMA_PATH.test(file.path) && declaredKeys(sf, importMeta).size > 0;
}

// Keys DECLARED by a schema module: UPPER_SNAKE object-literal property names (createEnv
// server/client blocks, a z.object shape) UNION the `process.env.X` keys it wires up (runtimeEnv
// maps, `export const env = { url: process.env.DATABASE_URL }`).
function declaredKeys(sf: ts.SourceFile, importMeta: boolean): Set<string> {
  const keys = new Set<string>();
  const visit = (n: ts.Node): void => {
    if (ts.isPropertyAssignment(n) || ts.isShorthandPropertyAssignment(n)) {
      const name = n.name;
      const text = ts.isIdentifier(name) ? name.text : ts.isStringLiteralLike(name) ? name.text : undefined;
      if (text && ENV_KEY.test(text)) keys.add(text);
    }
    const read = envKeyOf(n, importMeta);
    if (read) keys.add(read);
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return keys;
}

interface ParsedSource {
  path: string;
  sf: ts.SourceFile;
}

// First read site (path:line) of every `process.env.X` key across product code, excluding the
// schema modules themselves.
function collectReads(sources: ParsedSource[], schemaPaths: Set<string>, importMeta: boolean): Map<string, string> {
  const reads = new Map<string, string>();
  for (const { path, sf } of sources) {
    if (schemaPaths.has(path)) continue;
    const visit = (n: ts.Node): void => {
      const key = envKeyOf(n, importMeta);
      if (key && !reads.has(key)) reads.set(key, loc(path, sf, n));
      ts.forEachChild(n, visit);
    };
    visit(sf);
  }
  return reads;
}

// #902: a not-assessed disclosure (same contract as SEC-TH-GH-00) for a framework whose native env
// access (SvelteKit $env modules, Nuxt runtimeConfig) the process.env/import.meta.env read-diff
// cannot see. Emitted only when the target actually uses that convention, so it fails loud on a real
// gap without adding noise to a framework target that reads env the modelled way.
function unmodeledEnvConventionFinding(framework: TargetFramework, conv: EnvConvention): Finding {
  return {
    id: "ENV-SCHEMA-CONVENTION-00",
    title: `Env-schema completeness not assessed for ${conv.unmodeled}`,
    severity: "Info",
    confidence: "N/A",
    category: "Configuration",
    taxonomy: "Env var completeness — framework convention not modelled",
    location: "(repo-wide)",
    status: "Open",
    evidence: `Target detected as ${framework}, which reads config through ${conv.unmodeled}. The env-schema completeness pass diffs \`process.env\`/\`import.meta.env\` reads against the declared schema and does not model this access shape, so vars read through it are not covered here.`,
    impact: `Env-var completeness coverage for this target is PARTIAL: a required or client-exposed var accessed via ${conv.unmodeled} would not be flagged by this pass — a disclosed gap, not a finding of zero env-config issues.`,
    fix: `Review the ${conv.unmodeled} usage by hand: every declared key should be read, every read should be declared, and no server-only secret should sit behind the framework's public/client channel.`,
    value: 1,
    ease: 3,
    safety: 5,
  };
}

export function detectEnvSchemaFindings(files: SourceInput[], framework: TargetFramework = "next"): Finding[] {
  const conv = envConvention(framework);
  const sources: ParsedSource[] = files
    .filter((f) => SOURCE_EXT.test(f.path) && !NON_PRODUCT.test(f.path))
    .map((f) => ({ path: f.path, sf: parse(f.path, f.text) }));

  // Fail loud on an unmodelled native convention the target actually uses — computed before the
  // no-schema-module early return, since the schema itself may live in the shape we can't read.
  const disclosure: Finding[] = [];
  const unmodeledPattern = UNMODELED_ENV_ACCESS[framework];
  if (conv.unmodeled && unmodeledPattern && files.some((f) => unmodeledPattern.test(f.text))) {
    disclosure.push(unmodeledEnvConventionFinding(framework, conv));
  }

  const schemaCandidatePaths = new Set(envSchemaModuleCandidates(files).map((file) => file.path));
  const schemaFiles = sources.filter(
    ({ path, sf }) => schemaCandidatePaths.has(path) && isSchemaModule({ path, text: sf.getFullText() }, sf, conv.importMetaEnv),
  );
  if (schemaFiles.length === 0) return disclosure;

  const schemaPaths = new Set(schemaFiles.map((f) => f.path));
  const declared = new Set<string>();
  for (const { sf } of schemaFiles) for (const k of declaredKeys(sf, conv.importMetaEnv)) declared.add(k);
  // A schema module we can't extract any keys from can't ground a diff — stay silent rather than
  // flag every read in the app as "undeclared".
  if (declared.size === 0) return disclosure;

  const reads = collectReads(sources, schemaPaths, conv.importMetaEnv);
  const schemaLoc = `${schemaFiles[0]!.path}:1`;
  const findings: Finding[] = [...disclosure];

  for (const [key, location] of reads) {
    if (declared.has(key) || BUILTIN_ENV.has(key)) continue;
    const matchedPrefix = conv.publicPrefixes.find((p) => key.startsWith(p));
    findings.push(
      mechanicalFinding({
        id: `ENV-undeclared-read-${key}`,
        title: `\`${key}\` is read but not declared in the env schema`,
        severity: "Low",
        category: "Configuration",
        taxonomy: "Env var read but not declared in env schema",
        location,
        evidence: `\`${key}\` is read in ${location} but is not among the keys declared in the env schema module (${schemaFiles[0]!.path}).`,
        impact: matchedPrefix
          ? `${key} is a client-exposed (${matchedPrefix}) variable read without a schema declaration: it is bundled to the browser and, being undeclared, is neither validated nor documented — a missing value ships \`undefined\` to clients with no build-time error.`
          : `An undeclared required var is not validated at startup and is missing from the schema's single source of truth: a fresh environment can omit it and the app reads \`undefined\` at runtime instead of failing fast at boot. It can also be a typo'd key that will always read \`undefined\`.`,
        fix: `Add ${key} to the env schema module (${schemaFiles[0]!.path}) so it is validated and documented, or remove the read if the variable is obsolete.`,
        precisionTier: "review",
      }),
    );
  }

  for (const key of declared) {
    if (reads.has(key) || BUILTIN_ENV.has(key)) continue;
    findings.push(
      mechanicalFinding({
        id: `ENV-unused-declaration-${key}`,
        title: `\`${key}\` is declared in the env schema but never read`,
        severity: "Info",
        category: "Configuration",
        taxonomy: "Env var declared in env schema but never read",
        location: schemaLoc,
        evidence: `${key} is declared in the env schema module (${schemaFiles[0]!.path}) but no \`process.env.${key}\` read appears anywhere in product source.`,
        impact: "A declared-but-unread variable is dead configuration: it forces operators to provision a value the app never uses, and can hide a rename where the read was updated but the declaration was not.",
        fix: `Remove ${key} from the env schema if it is obsolete, or wire up the read it was added for.`,
        precisionTier: "review",
      }),
    );
  }

  return findings;
}
