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
    if (ts.isExportSpecifier(reference.parent)) return this.checker.getExportSpecifierLocalTargetSymbol(reference.parent);
    return ts.isShorthandPropertyAssignment(reference.parent) && reference.parent.name === reference
      ? this.checker.getShorthandAssignmentValueSymbol(reference.parent)
      : this.checker.getSymbolAtLocation(reference);
  }

  declaration(reference: ts.Identifier): ts.Declaration | undefined {
    const declarations = this.symbol(reference)?.declarations;
    // Require one declaration when certifying a specific runtime implementation.
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

  inertValue(node: ts.Expression): boolean {
    if (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isNonNullExpression(node)
      || ts.isSatisfiesExpression(node)) return this.inertValue(node.expression);
    if (ts.isLiteralExpression(node) || ts.isArrowFunction(node) || ts.isFunctionExpression(node)
      || [ts.SyntaxKind.TrueKeyword, ts.SyntaxKind.FalseKeyword, ts.SyntaxKind.NullKeyword].includes(node.kind)) return true;
    if (ts.isPrefixUnaryExpression(node) && [ts.SyntaxKind.PlusToken, ts.SyntaxKind.MinusToken].includes(node.operator)
      && ts.isNumericLiteral(node.operand)) return true;
    if (ts.isArrayLiteralExpression(node)) return node.elements.every((element) => this.inertValue(element));
    if (ts.isObjectLiteralExpression(node)) return node.properties.every((property) => ts.isPropertyAssignment(property)
      && !ts.isComputedPropertyName(property.name) && this.inertValue(property.initializer));
    return false;
  }

  inertStatement(statement: ts.Statement, dependency: (specifier: string) => boolean = () => false): boolean {
    if (ts.canHaveModifiers(statement) && ts.getModifiers(statement)?.some((modifier) => modifier.kind === ts.SyntaxKind.DeclareKeyword)) return true;
    if (ts.isFunctionDeclaration(statement) || ts.isInterfaceDeclaration(statement)
      || ts.isTypeAliasDeclaration(statement) || ts.isEmptyStatement(statement)) return true;
    if (ts.isVariableStatement(statement)) return Boolean(statement.declarationList.flags & ts.NodeFlags.Const)
      && statement.declarationList.declarations.every((declaration) => ts.isIdentifier(declaration.name)
        && declaration.initializer && this.inertValue(declaration.initializer));
    if (ts.isImportDeclaration(statement)) {
      const clause = statement.importClause;
      if (clause?.isTypeOnly || (clause && !clause.name && clause.namedBindings && ts.isNamedImports(clause.namedBindings)
        && clause.namedBindings.elements.length > 0 && clause.namedBindings.elements.every((item) => item.isTypeOnly))) return true;
      return ts.isStringLiteral(statement.moduleSpecifier) && dependency(statement.moduleSpecifier.text);
    }
    if (ts.isExportDeclaration(statement)) {
      if (statement.isTypeOnly || (statement.exportClause && ts.isNamedExports(statement.exportClause)
        && statement.exportClause.elements.length > 0 && statement.exportClause.elements.every((item) => item.isTypeOnly))) return true;
      return !statement.moduleSpecifier || (ts.isStringLiteral(statement.moduleSpecifier) && dependency(statement.moduleSpecifier.text));
    }
    if (ts.isExportAssignment(statement)) return this.inertValue(statement.expression);
    // Calls, property reads, computed keys, class/static initialization, namespaces,
    // writes and unknown statement forms require review, irrespective of spelling.
    return false;
  }

  inertModule(dependency: (specifier: string) => boolean, entry?: ts.Statement): boolean {
    return this.source.statements.every((statement) => statement === entry || this.inertStatement(statement, dependency));
  }
}
