import { parseStringPromise } from "xml2js";

// N-XXE-SAFE (NEGATIVE — must NOT be flagged): the XML parser is configured with noent: false —
// external entities are NOT resolved, which is the hardened setting. The XXE rule must fire only
// when entity resolution is enabled (noent: true / resolveEntities: true).
export function parseFeed(xml) {
  return parseStringPromise(xml, { explicitArray: false, noent: false });
}
