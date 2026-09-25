import ts from "typescript";

// Bind the supplied source only. No ambient libraries, filesystem imports, or target
// code execute: an unresolved name is a platform candidate, never a local helper.
// The compiler owns lexical scope, hoisting, declaration merging and every TS binding
// form; enumerating selected declaration kinds here would make proof fail open.
export class SourceBindings {
  private readonly checker: ts.TypeChecker;

  constructor(private readonly source: ts.SourceFile) {
    const host: ts.CompilerHost = {
      getSourceFile: (name) => name === source.fileName ? source : undefined,
      getDefaultLibFileName: () => "",
      writeFile: () => {},
      getCurrentDirectory: () => "",
      getDirectories: () => [],
      fileExists: (name) => name === source.fileName,
      readFile: (name) => name === source.fileName ? source.text : undefined,
      getCanonicalFileName: (name) => name,
      useCaseSensitiveFileNames: () => true,
      getNewLine: () => "\n",
    };
    this.checker = ts.createProgram([source.fileName], {
      noLib: true, noResolve: true, target: ts.ScriptTarget.Latest,
      module: ts.ModuleKind.ESNext, allowJs: true,
    }, host).getTypeChecker();
  }

  private symbol(reference: ts.Identifier): ts.Symbol | undefined {
    return ts.isShorthandPropertyAssignment(reference.parent) && reference.parent.name === reference
      ? this.checker.getShorthandAssignmentValueSymbol(reference.parent)
      : this.checker.getSymbolAtLocation(reference);
  }

  declaration(reference: ts.Identifier): ts.Declaration | undefined {
    const declarations = this.symbol(reference)?.declarations;
    // Merged/duplicate declarations cannot certify one specific runtime implementation.
    return declarations?.length === 1 ? declarations[0] : undefined;
  }

  unboundWithin(scope: ts.Node, names: ReadonlySet<string>): boolean {
    const visit = (node: ts.Node): boolean => {
      // The checker synthesizes intrinsic globals such as undefined without a
      // declaration. Any source declaration (including ambient/merged ones) is unknown.
      if (ts.isIdentifier(node) && names.has(node.text) && this.symbol(node)?.declarations?.length) return false;
      return !ts.forEachChild(node, (child) => !visit(child) || undefined);
    };
    return visit(scope);
  }

  hasWrite(names: ReadonlySet<string>): boolean {
    const mentions = (node: ts.Node): boolean => (ts.isIdentifier(node) && names.has(node.text))
      || (ts.forEachChild(node, (child) => mentions(child) || undefined) ?? false);
    const visit = (node: ts.Node): boolean => {
      if (ts.isBinaryExpression(node) && node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
        && node.operatorToken.kind <= ts.SyntaxKind.LastAssignment && mentions(node.left)) return true;
      if ((ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node))
        && (node.operator === ts.SyntaxKind.PlusPlusToken || node.operator === ts.SyntaxKind.MinusMinusToken)
        && mentions(node.operand)) return true;
      if (ts.isDeleteExpression(node) && mentions(node.expression)) return true;
      if ((ts.isForInStatement(node) || ts.isForOfStatement(node))
        && !ts.isVariableDeclarationList(node.initializer) && mentions(node.initializer)) return true;
      return ts.forEachChild(node, (child) => visit(child) || undefined) ?? false;
    };
    return visit(this.source);
  }
}
