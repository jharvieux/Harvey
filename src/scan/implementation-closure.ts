import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import ts from "typescript";
import { statSafe } from "../fs-walk.js";

export type ImplementationClosureUncertaintyKind = "dynamic" | "unresolved" | "unreadable" | "discovery-error";

export interface ImplementationClosureEdge {
  from: string;
  to: string;
  specifier: string;
  kind: "static" | "dynamic";
}

export interface ImplementationClosureUncertainty {
  kind: ImplementationClosureUncertaintyKind;
  path: string;
  detail: string;
}

interface ImplementationClosureReceipt {
  roots: string[];
  files: string[];
  edges: ImplementationClosureEdge[];
  uncertainties: ImplementationClosureUncertainty[];
}

function resolveRelativeImplementation(from: string, specifier: string): string | undefined {
  if (!specifier.startsWith(".")) return undefined;
  const unresolved = resolve(dirname(from), specifier);
  const withoutJs = unresolved.replace(/\.(?:mjs|cjs|js)$/, "");
  const candidates = [
    unresolved,
    `${withoutJs}.ts`,
    `${withoutJs}.tsx`,
    `${withoutJs}.mts`,
    `${withoutJs}.cts`,
    `${withoutJs}.js`,
    `${withoutJs}.mjs`,
    `${withoutJs}.cjs`,
    join(withoutJs, "index.ts"),
    join(withoutJs, "index.tsx"),
    join(withoutJs, "index.js"),
  ];
  return candidates.find((candidate) => statSafe(candidate)?.isFile());
}

function sourceFile(path: string): ts.SourceFile {
  const kind = path.endsWith(".tsx")
    ? ts.ScriptKind.TSX
    : path.endsWith(".jsx")
      ? ts.ScriptKind.JSX
      : path.endsWith(".js") || path.endsWith(".mjs") || path.endsWith(".cjs")
        ? ts.ScriptKind.JS
        : ts.ScriptKind.TS;
  return ts.createSourceFile(path, readFileSync(path, "utf8"), ts.ScriptTarget.Latest, true, kind);
}

function isTypeOnlyDependency(statement: ts.ImportDeclaration | ts.ExportDeclaration): boolean {
  if (ts.isImportDeclaration(statement)) {
    const clause = statement.importClause;
    if (!clause) return false;
    if (clause.isTypeOnly) return true;
    return !clause.name
      && clause.namedBindings !== undefined
      && ts.isNamedImports(clause.namedBindings)
      && clause.namedBindings.elements.length > 0
      && clause.namedBindings.elements.every((element) => element.isTypeOnly);
  }
  if (statement.isTypeOnly) return true;
  return statement.exportClause !== undefined
    && ts.isNamedExports(statement.exportClause)
    && statement.exportClause.elements.length > 0
    && statement.exportClause.elements.every((element) => element.isTypeOnly);
}

/** One fail-open graph shared by cache identities and corpus relevance. */
export function discoverImplementationClosure(roots: readonly string[]): ImplementationClosureReceipt {
  const closure = new Set<string>();
  const edges: ImplementationClosureEdge[] = [];
  const uncertainties: ImplementationClosureUncertainty[] = [];

  const visit = (path: string): void => {
    if (closure.has(path)) return;
    closure.add(path);
    let parsed: ts.SourceFile;
    try {
      parsed = sourceFile(path);
    } catch (error) {
      uncertainties.push({ kind: "unreadable", path, detail: error instanceof Error ? error.message : String(error) });
      return;
    }

    const follow = (specifier: string, kind: ImplementationClosureEdge["kind"]): void => {
      if (!specifier.startsWith(".")) return;
      const imported = resolveRelativeImplementation(path, specifier);
      if (!imported) {
        uncertainties.push({ kind: "unresolved", path, detail: `${kind} dependency ${JSON.stringify(specifier)} cannot be resolved` });
        return;
      }
      edges.push({ from: path, to: imported, specifier, kind });
      visit(imported);
    };

    for (const statement of parsed.statements) {
      if ((!ts.isImportDeclaration(statement) && !ts.isExportDeclaration(statement))
        || !statement.moduleSpecifier
        || !ts.isStringLiteral(statement.moduleSpecifier)
        || isTypeOnlyDependency(statement)) continue;
      follow(statement.moduleSpecifier.text, "static");
    }

    const inspectDynamic = (node: ts.Node): void => {
      if (ts.isCallExpression(node)
        && (node.expression.kind === ts.SyntaxKind.ImportKeyword
          || (ts.isIdentifier(node.expression) && node.expression.text === "require"))) {
        const argument = node.arguments[0];
        if (!argument || !ts.isStringLiteralLike(argument)) {
          uncertainties.push({ kind: "dynamic", path, detail: "dynamic import/require has a non-literal implementation identity" });
        } else {
          follow(argument.text, "dynamic");
        }
      }
      ts.forEachChild(node, inspectDynamic);
    };
    inspectDynamic(parsed);
  };

  try {
    for (const root of roots) {
      if (!statSafe(root)?.isFile()) {
        uncertainties.push({ kind: "unresolved", path: root, detail: "implementation root is missing or not a file" });
        continue;
      }
      visit(root);
    }
  } catch (error) {
    uncertainties.push({ kind: "discovery-error", path: roots.join(", "), detail: error instanceof Error ? error.message : String(error) });
  }

  return {
    roots: [...roots].sort(),
    files: [...closure].sort(),
    edges: edges.sort((a, b) => `${a.from}\0${a.to}\0${a.kind}`.localeCompare(`${b.from}\0${b.to}\0${b.kind}`)),
    uncertainties: uncertainties.sort((a, b) => `${a.path}\0${a.kind}\0${a.detail}`.localeCompare(`${b.path}\0${b.kind}\0${b.detail}`)),
  };
}

export function discoverTransitiveImplementationFiles(roots: readonly string[]): string[] {
  const receipt = discoverImplementationClosure(roots);
  if (receipt.uncertainties.length > 0) {
    const first = receipt.uncertainties[0]!;
    throw new Error(`implementation closure ${first.kind}: implementation identity cannot be proven: ${first.path}: ${first.detail}`);
  }
  return receipt.files;
}
