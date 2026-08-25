export function parseServerXml(req: { body: { xml: string } }) {
  return new DOMParser().parseFromString(req.body.xml, "application/xml");
}
