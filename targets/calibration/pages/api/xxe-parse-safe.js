import libxmljs from "libxmljs";

// N-XXE-PARSE-FIXED (NEGATIVE — must NOT be flagged, #985): libxmljs.parseXml is called on a fixed
// constant XML string, not request input — no taint reaches the parse sink. Regression guard for
// the new parse-call XXE sink.
export default function handler(req, res) {
  const doc = libxmljs.parseXml("<root><ok/></root>");
  res.status(200).json({ root: doc.root().name() });
}
