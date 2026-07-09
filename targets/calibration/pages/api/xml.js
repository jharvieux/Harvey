import { parseStringPromise } from "xml2js";

// PLANTED BUG (P-XXE): the XML parser is configured with noent: true, resolving external
// entities in the request body — XXE (local file read / SSRF via a DOCTYPE entity). Review tier.
export default async function handler(req, res) {
  const doc = await parseStringPromise(req.body, { explicitArray: false, noent: true });
  res.status(200).json(doc);
}
