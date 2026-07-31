import xpath from "xpath";
import { DOMParser } from "@xmldom/xmldom";

const DIRECTORY = new DOMParser().parseFromString("<users><user name='ada' role='admin'/></users>");

// N-XPATH-CONSTANT (NEGATIVE — must NOT be flagged, #1273): the XPath expression is a server-owned
// constant; the request value only filters the RESULT, in JavaScript, after the query has run. No
// request taint reaches the expression, so harvey-xpath-injection stays dark. Boundary guard: a
// rule that matched `xpath.select` on presence rather than on taint would fire here.
export default function handler(req, res) {
  const nodes = xpath.select("//user[@role='admin']", DIRECTORY);
  const wanted = nodes.filter((n) => n.getAttribute("name") === req.query.name);
  res.status(200).json({ count: wanted.length });
}
