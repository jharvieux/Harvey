import xpath from "xpath";
import { DOMParser } from "@xmldom/xmldom";

const DIRECTORY = new DOMParser().parseFromString("<users><user name='ada' role='admin'/></users>");

// PLANTED BUG (P-XPATH-INJECTION, #1273): the request's `name` is concatenated into an XPath
// predicate. `' or '1'='1` rewrites the predicate to match every node, so a lookup meant to return
// one user returns the whole directory — and against an XML-backed credential store the same
// rewrite is an authentication bypass. Review tier: taint-gated, the AST proves the concatenation.
export default function handler(req, res) {
  const nodes = xpath.select(`//user[@name='${req.query.name}']`, DIRECTORY);
  res.status(200).json({ count: nodes.length });
}
