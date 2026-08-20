import ts from "typescript";
import type { Finding } from "../findings.js";
import { loc, parse, type SourceInput } from "./common.js";
import { isGeneratedSource, SOURCE_FILE } from "./load-sources.js";

type EscapeKind = "as-any" | "double-assertion" | "unexplained-ts-ignore";

interface EscapeRow {
  kind: EscapeKind;
  node: ts.Node;
  position?: number;
  expression: string;
  detail: string;
}

const EXCLUDED_PATH = /(^|\/)(?:__generated__|__tests__|build|coverage|dist|fixtures?|generated|node_modules|test|tests|vendor)(\/|$)|(^|\/)targets\/calibration(\/|$)|\.(?:d|generated|test|spec)\.[cm]?[jt]sx?$/i;
const INTEROP_RATIONALE = /\b(interop|third[- ]party|upstream (?:api|sdk|library)|legacy (?:api|sdk|library))\b/i;
const VALIDATION_RATIONALE = /\b(runtime[- ]validated|validated boundary|schema[- ]validated|narrowed by|checked by)\b/i;
const VALIDATOR_CALL = /^(assert|check|decode|guard|is|narrow|parse|safeParse|validate)/i;

function sourceLine(sf: ts.SourceFile, line: number): string {
  return sf.text.split(/\r?\n/)[line] ?? "";
}

function lineOf(sf: ts.SourceFile, node: ts.Node): number {
  return sf.getLineAndCharacterOfPosition(node.getStart(sf)).line;
}

function nearbyRationale(sf: ts.SourceFile, node: ts.Node): string {
  const line = lineOf(sf, node);
  return [sourceLine(sf, line - 2), sourceLine(sf, line - 1), sourceLine(sf, line)].join("\n");
}

function baseExpression(node: ts.AsExpression): ts.Expression {
  let expression: ts.Expression = node.expression;
  while (ts.isAsExpression(expression) || ts.isTypeAssertionExpression(expression) || ts.isParenthesizedExpression(expression)) {
    expression = expression.expression;
  }
  return expression;
}

function callLeaf(expression: ts.Expression): string | undefined {
  if (!ts.isCallExpression(expression)) return undefined;
  if (ts.isIdentifier(expression.expression)) return expression.expression.text;
  if (ts.isPropertyAccessExpression(expression.expression)) return expression.expression.name.text;
  return undefined;
}

function hasPriorValidation(node: ts.AsExpression, sf: ts.SourceFile, base: ts.Expression): boolean {
  const leaf = callLeaf(base);
  if (leaf && VALIDATOR_CALL.test(leaf)) return true;
  if (!ts.isIdentifier(base)) return false;

  let statement: ts.Node = node;
  while (statement.parent && !ts.isBlock(statement.parent) && !ts.isSourceFile(statement.parent)) statement = statement.parent;
  const container = statement.parent;
  if (!container || (!ts.isBlock(container) && !ts.isSourceFile(container))) return false;
  const statements = container.statements;
  const index = statements.findIndex((candidate) => candidate === statement);
  if (index < 0) return false;
  const preceding = statements.slice(Math.max(0, index - 3), index).map((candidate) => candidate.getText(sf)).join("\n");
  const escaped = base.text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(?:assert|check|guard|narrow|validate|is)[A-Za-z0-9_]*\\s*\\(\\s*${escaped}\\b`, "i").test(preceding)
    || new RegExp(`if\\s*\\([^)]*(?:is|valid|safe|guard)[^)]*${escaped}[\\s\\S]*throw\\b`, "i").test(preceding);
}

function justifiedAssertion(node: ts.AsExpression, sf: ts.SourceFile): boolean {
  const rationale = nearbyRationale(sf, node);
  if (INTEROP_RATIONALE.test(rationale)) return true;
  return VALIDATION_RATIONALE.test(rationale) && hasPriorValidation(node, sf, baseExpression(node));
}

function assertionKind(node: ts.AsExpression): EscapeKind | undefined {
  const types: ts.TypeNode[] = [];
  let current: ts.Expression = node;
  while (true) {
    if (ts.isAsExpression(current)) {
      types.push(current.type);
      current = current.expression;
      continue;
    }
    if (ts.isParenthesizedExpression(current)) {
      current = current.expression;
      continue;
    }
    break;
  }
  if (types.some((type) => type.kind === ts.SyntaxKind.AnyKeyword)) return "as-any";
  const unknownIndex = types.findIndex((type) => type.kind === ts.SyntaxKind.UnknownKeyword);
  if (unknownIndex > 0 && types.slice(0, unknownIndex).some((type) => type.kind !== ts.SyntaxKind.UnknownKeyword && type.kind !== ts.SyntaxKind.AnyKeyword)) {
    return "double-assertion";
  }
  return undefined;
}

function assertionRows(sf: ts.SourceFile): EscapeRow[] {
  const rows: EscapeRow[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isAsExpression(node) && !ts.isAsExpression(node.parent)) {
      const kind = assertionKind(node);
      if (kind && !justifiedAssertion(node, sf)) {
        const base = baseExpression(node).getText(sf).replace(/\s+/g, " ").slice(0, 120);
        rows.push({
          kind,
          node,
          expression: base,
          detail: kind === "as-any"
            ? "the assertion introduces `any`, disabling static checks for this expression"
            : "the assertion tunnels through `unknown` into an unrelated target type",
        });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return rows;
}

function ignoredDirectiveRows(sf: ts.SourceFile): EscapeRow[] {
  const rows: EscapeRow[] = [];
  const scanner = ts.createScanner(ts.ScriptTarget.Latest, false, ts.LanguageVariant.Standard, sf.text);
  let token = scanner.scan();
  while (token !== ts.SyntaxKind.EndOfFileToken) {
    if (token === ts.SyntaxKind.SingleLineCommentTrivia || token === ts.SyntaxKind.MultiLineCommentTrivia) {
      const comment = scanner.getTokenText();
      const directive = /@ts-ignore\b([^\r\n]*)/.exec(comment);
      if (directive) {
        const suffix = directive[1]?.trim() ?? "";
        const explained = /^(?:--|—|:)\s*\S.{7,}$/.test(suffix);
        if (!explained) {
          const start = scanner.getTokenStart();
          const line = sf.getLineAndCharacterOfPosition(start).line;
          const suppressed = sourceLine(sf, line + 1).trim().slice(0, 120);
          rows.push({
            kind: "unexplained-ts-ignore",
            node: sf,
            position: start,
            expression: suppressed || "the following line",
            detail: "the directive has no `-- reason`, `: reason`, or em-dash rationale",
          });
        }
      }
    }
    token = scanner.scan();
  }
  return rows;
}

function rowLocation(path: string, sf: ts.SourceFile, row: EscapeRow): string {
  if (row.position !== undefined) return `${path}:${sf.getLineAndCharacterOfPosition(row.position).line + 1}`;
  return loc(path, sf, row.node);
}

function finding(id: string, path: string, sf: ts.SourceFile, row: EscapeRow): Finding {
  const names: Record<EscapeKind, { title: string; taxonomy: string }> = {
    "as-any": { title: "Unjustified `as any` bypasses TypeScript", taxonomy: "M5 — Type escape (`as any`)" },
    "double-assertion": { title: "Double assertion bypasses TypeScript narrowing", taxonomy: "M5 — Type escape (double assertion)" },
    "unexplained-ts-ignore": { title: "Unexplained `@ts-ignore` suppresses type checking", taxonomy: "M5 — Unexplained @ts-ignore" },
  };
  return {
    id,
    title: names[row.kind].title,
    severity: "Low",
    confidence: "Review",
    category: "Maintainability",
    taxonomy: names[row.kind].taxonomy,
    location: rowLocation(path, sf, row),
    status: "Open",
    evidence: `Escaped expression: \`${row.expression}\`; ${row.detail}, and no runtime validation/narrowing boundary is visible.`,
    impact: "The compiler can no longer prove the value matches the promised type, moving failures to production and obscuring the actual boundary contract.",
    fix: "Validate or narrow at the boundary and keep the resulting type, or document the concrete interop constraint beside the narrowest possible assertion.",
    value: 3,
    ease: 4,
    safety: 4,
    okWhen: "A runtime validator or narrowing guard proves the value, or a concrete interop rationale explains the smallest necessary assertion.",
    notOkWhen: "The assertion or suppression merely makes an unchecked production value compile.",
    mechanical: true,
    precisionTier: "review",
  };
}

export function m5TypeEscapeSources(files: readonly SourceInput[]): SourceInput[] {
  return files.filter((file) => SOURCE_FILE.test(file.path) && !EXCLUDED_PATH.test(file.path) && !isGeneratedSource(file.path, file.text));
}

export function detectM5TypeEscapeFindings(
  files: SourceInput[],
  classifiers: { assertions?: boolean; tsIgnore?: boolean } = {},
): Finding[] {
  let id = 0;
  const findings: Finding[] = [];
  for (const file of m5TypeEscapeSources(files)) {
    const sf = parse(file.path, file.text);
    const rows = [
      ...(classifiers.assertions === false ? [] : assertionRows(sf)),
      ...(classifiers.tsIgnore === false ? [] : ignoredDirectiveRows(sf)),
    ].sort((a, b) => {
      const aPos = a.position ?? a.node.getStart(sf);
      const bPos = b.position ?? b.node.getStart(sf);
      return aPos - bPos;
    });
    for (const row of rows) findings.push(finding(`M5TYPE-${String(++id).padStart(2, "0")}`, file.path, sf, row));
  }
  return findings;
}
