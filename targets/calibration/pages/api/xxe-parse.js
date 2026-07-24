import libxmljs from "libxmljs";

// PLANTED BUG (P-XXE-LIBXMLJS, #985): the request body is parsed as XML via libxmljs.parseXml —
// an XXE-capable parser. harvey-xxe only matched the noent/resolveEntities parser OPTION; the
// parse-CALL sink (libxmljs/DOMParser fed tainted input) was added in #985. Review tier.
export default function handler(req, res) {
  const doc = libxmljs.parseXml(req.body.xml);
  res.status(200).json({ root: doc.root().name() });
}
