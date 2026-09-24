import "./sync-stdio.js";
import { readFileSync, readdirSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import ts from "typescript";

export const SYNC_STDIO_IMPORT = "./sync-stdio.js";

function isProcessProperty(node: ts.Expression, property: string): boolean {
  return ts.isPropertyAccessExpression(node)
    && ts.isIdentifier(node.expression)
    && node.expression.text === "process"
    && node.name.text === property;
}

function isLiteralZero(node: ts.Expression | undefined): boolean {
  return node !== undefined && ts.isNumericLiteral(node) && Number(node.text) === 0;
}

// Dynamic exit arguments are treated as risky. Guessing a dynamic value is zero would leave a
// droppable verdict path outside the ratchet.
export function hasNonzeroExit(source: string, file = "cli.ts"): boolean {
  const parsed = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
  let exits = false;
  const visit = (node: ts.Node): void => {
    if (exits) return;
    if (ts.isCallExpression(node) && isProcessProperty(node.expression, "exit")) {
      exits = node.arguments.length > 0 && !isLiteralZero(node.arguments[0]);
    } else if (
      ts.isBinaryExpression(node)
      && node.operatorToken.kind === ts.SyntaxKind.EqualsToken
      && isProcessProperty(node.left, "exitCode")
    ) {
      exits = !isLiteralZero(node.right);
    }
    ts.forEachChild(node, visit);
  };
  visit(parsed);
  return exits;
}

// The guard must be the first syntax statement; comments and substring matches never count.
export function hasFirstSyncStdioImport(source: string, file = "cli.ts"): boolean {
  const parsed = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
  const first = parsed.statements[0];
  return first !== undefined
    && ts.isImportDeclaration(first)
    && ts.isStringLiteral(first.moduleSpecifier)
    && first.moduleSpecifier.text === SYNC_STDIO_IMPORT;
}

export function discoverExitingCliFiles(files: readonly string[], libraries: ReadonlySet<string>, readSource: (file: string) => string): string[] {
  return files.filter((file) => !libraries.has(file) && hasNonzeroExit(readSource(file), file));
}

export function unguardedExitingCliFiles(files: readonly string[], libraries: ReadonlySet<string>, readSource: (file: string) => string): string[] {
  return discoverExitingCliFiles(files, libraries, readSource)
    .filter((file) => !hasFirstSyncStdioImport(readSource(file), file));
}

export function cliTypeScriptFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts"))
    .map((entry) => join(directory, entry.name))
    .sort();
}

export function main(argv = process.argv.slice(2)): void {
  const directory = argv[0] ?? join(process.cwd(), "src", "cli");
  const libraries = new Set(argv.slice(1));
  const files = cliTypeScriptFiles(directory);
  const unguarded = unguardedExitingCliFiles(files, libraries, (file) => readFileSync(file, "utf8"));
  if (unguarded.length > 0) {
    console.error("sync-stdio missing or late in: " + unguarded.map((file) => relative(process.cwd(), file)).join(", "));
    process.exitCode = 1;
  }
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : null;
if (invokedPath === import.meta.url) main();
