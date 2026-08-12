// #1252 P-OWASP-REACT-PROP-OVERSHARE — a whole object handed to a component as one prop when its
// declared type carries fields the component has no business receiving. OWASP React Security CS
// (draft), Sensitive Data Exposure: "Minimize Sensitive Data in Component State and Props". Props
// live in React's Fiber tree, which session-recording scripts and browser extensions read, and a
// field never rendered is still there.
//
// This gap was RECORDED rather than filed on 2026-07-27 with the reason "scoring it needs to know
// which fields of an app's own types are sensitive, which is a per-app judgment rather than a
// syntactic shape". Half of that is right and it is not the half that blocks a rule: WHICH names
// are sensitive is a naming heuristic (which is why this ships at review tier, never in the free
// count), but WHETHER the whole object was passed is purely syntactic, and it is the conjunct that
// makes the heuristic usable — `<Avatar user={account} />` next to `<Avatar name={n} />` is a
// difference a parser can see.
//
// BOUNDS, stated here and in the finding's own message:
//   - the type must be declared in the SAME FILE. An imported type is not resolved, so a repo that
//     keeps its interfaces in a types module is not assessed by this rule.
//   - only a declared TYPE is read, never an inferred one — an untyped object literal passed whole
//     is not assessed.
//   - the sensitive-name vocabulary is a fixed list; a field named in an app's own vocabulary
//     (`nino`, `rut`, `pesel`) is not recognised.
// A module that is provably server-only ('use server', or a server-only import) is skipped: props
// there never reach a browser, and the Server->Client boundary is detectServerClientLeak's (M9).

import ts from "typescript";
import type { Finding } from "../findings.js";
import { leadingDirective, loc, parse, type SourceInput } from "../detectors/common.js";
import { mechanicalFinding } from "./common.js";

// Names that carry a field a UI component should never be handed wholesale. Deliberately narrow —
// `email`, `phone` and `address` are absent, because a profile component legitimately renders them
// and their presence would make every user object a finding.
const SENSITIVE_FIELD =
  /^(ssn|socialsecurity(number)?|taxid|nationalid|passport(number)?|password|passwordhash|passwordsalt|salt|secret|clientsecret|mfasecret|totpsecret|privatekey|apikey|apisecret|accesstoken|refreshtoken|sessiontoken|idtoken|bearertoken|creditcard(number)?|cardnumber|cvv|cvc|bankaccount(number)?|routingnumber|iban|dateofbirth|dob|birthdate)$/;

function sensitiveMembers(members: ts.NodeArray<ts.TypeElement>): string[] {
  return members
    .filter((m): m is ts.PropertySignature => ts.isPropertySignature(m) && !!m.name && ts.isIdentifier(m.name))
    .map((m) => (m.name as ts.Identifier).text)
    .filter((name) => SENSITIVE_FIELD.test(name.replace(/[_-]/g, "").toLowerCase()));
}

// Same-file `interface X {}` / `type X = {}` only. Following an import would need a module graph
// pass this rule deliberately does not open; the bound is disclosed in the message.
function localTypeMembers(sf: ts.SourceFile): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const st of sf.statements) {
    if (ts.isInterfaceDeclaration(st)) out.set(st.name.text, sensitiveMembers(st.members));
    else if (ts.isTypeAliasDeclaration(st) && ts.isTypeLiteralNode(st.type)) out.set(st.name.text, sensitiveMembers(st.type.members));
  }
  return out;
}

function typeReferenceName(type: ts.TypeNode | undefined): string | undefined {
  if (type && ts.isTypeReferenceNode(type) && ts.isIdentifier(type.typeName)) return type.typeName.text;
  return undefined;
}

// The declared type of `account` where the component is written `({ account }: { account: Account })`
// — the shape every React component in a typed codebase uses — plus the plain annotated parameter
// and the annotated local. An inferred type is deliberately not resolved (bound, disclosed).
function declaredTypeNames(sf: ts.SourceFile): Map<string, string> {
  const out = new Map<string, string>();
  const bind = (name: string, type: ts.TypeNode | undefined) => {
    const ref = typeReferenceName(type);
    if (ref) out.set(name, ref);
  };
  const visit = (node: ts.Node) => {
    if (ts.isParameter(node) || ts.isVariableDeclaration(node)) {
      if (ts.isIdentifier(node.name)) bind(node.name.text, node.type);
      else if (ts.isObjectBindingPattern(node.name) && node.type && ts.isTypeLiteralNode(node.type)) {
        for (const el of node.name.elements) {
          if (!ts.isIdentifier(el.name)) continue;
          const key = (el.propertyName ?? el.name).getText(sf);
          const member = node.type.members.find(
            (m): m is ts.PropertySignature => ts.isPropertySignature(m) && !!m.name && m.name.getText(sf) === key,
          );
          bind(el.name.text, member?.type);
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

interface Overshare {
  node: ts.Node;
  component: string;
  prop: string;
  object: string;
  fields: string[];
}

function tagName(el: ts.JsxOpeningLikeElement): string {
  return el.tagName.getText();
}

function collect(sf: ts.SourceFile, types: Map<string, string[]>, declared: Map<string, string>): Overshare[] {
  const hits: Overshare[] = [];
  const consider = (el: ts.JsxOpeningLikeElement) => {
    const component = tagName(el);
    // An intrinsic element (<div>) takes no component props; only a composed component can be
    // handed a whole domain object.
    if (!/^[A-Z]/.test(component)) return;
    for (const attr of el.attributes.properties) {
      let object: string | undefined;
      let prop: string;
      if (ts.isJsxSpreadAttribute(attr) && ts.isIdentifier(attr.expression)) {
        object = attr.expression.text;
        prop = "…spread";
      } else if (
        ts.isJsxAttribute(attr) &&
        attr.initializer &&
        ts.isJsxExpression(attr.initializer) &&
        attr.initializer.expression &&
        ts.isIdentifier(attr.initializer.expression)
      ) {
        object = attr.initializer.expression.text;
        prop = attr.name.getText(sf);
      } else continue;

      const typeName = declared.get(object);
      const fields = typeName ? types.get(typeName) : undefined;
      if (fields && fields.length > 0) hits.push({ node: attr, component, prop, object, fields });
    }
  };
  const visit = (node: ts.Node) => {
    if (ts.isJsxSelfClosingElement(node) || ts.isJsxOpeningElement(node)) consider(node);
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return hits;
}

function detectFile(path: string, sf: ts.SourceFile): Finding[] {
  if (leadingDirective(sf) === "use server") return [];
  if (sf.statements.some((s) => ts.isImportDeclaration(s) && ts.isStringLiteral(s.moduleSpecifier) && s.moduleSpecifier.text === "server-only")) return [];

  const types = localTypeMembers(sf);
  if (types.size === 0) return [];

  return collect(sf, types, declaredTypeNames(sf)).map((hit) => {
    const location = loc(path, sf, hit.node);
    const named = hit.fields.map((f) => `\`${f}\``).join(", ");
    return mechanicalFinding({
      id: `REACT-prop-overshare-${location.replace(/[^a-zA-Z0-9]+/g, "-")}`,
      title: `${path} — whole object passed as a prop carries sensitive fields`,
      severity: "Medium",
      category: "Next.js/web footgun",
      taxonomy: "Sensitive fields in props",
      location,
      evidence: `\`<${hit.component} ${hit.prop === "…spread" ? `{...${hit.object}}` : `${hit.prop}={${hit.object}}`} />\` hands \`${hit.component}\` the whole \`${hit.object}\`, whose declared type carries ${named}.`,
      impact:
        "Every field of the object reaches React's Fiber tree and the serialized props of any SSR payload, whether or not the component renders it — readable by browser extensions, React DevTools and session-recording scripts. SCOPE: the type must be declared in the same file (an imported one is not resolved), only declared types are read, and the sensitive-name list is fixed, so an app's own vocabulary for a sensitive field is not recognised.",
      fix: `Pass only the fields \`${hit.component}\` renders (\`const { … } = ${hit.object}\`), or project the object into a view model before it crosses the component boundary.`,
      precisionTier: "review",
      cwe: ["CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"],
      owasp: ["A01:2021 - Broken Access Control"],
    });
  });
}

export function detectPropOvershareFindings(files: SourceInput[]): Finding[] {
  return files.flatMap((f) => detectFile(f.path, parse(f.path, f.text)));
}
