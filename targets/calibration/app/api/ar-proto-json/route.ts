import merge from "lodash.merge";

const DEFAULTS = { theme: "light", pageSize: 25 };

// PLANTED BUG (P-PROTO-JSON-BODY, #1224): the App Router JSON body is recursively merged into a
// settings object, so a `__proto__` key mutates Object.prototype. A JSON body is exactly what
// carries that key — this rule's single most important missing source, and it had one of the two
// narrowest source lists in the directory.
export async function POST(req: Request) {
  const body = await req.json();
  const settings = merge({ ...DEFAULTS }, body);
  return Response.json(settings);
}
