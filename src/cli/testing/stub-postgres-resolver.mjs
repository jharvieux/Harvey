// The resolve hook itself — runs on the loader thread, so it is a separate file
// from the registrar (#1407).

import { pathToFileURL } from "node:url";
import { join } from "node:path";

const STUB = pathToFileURL(join(import.meta.dirname, "stub-postgres.mjs")).href;

export function resolve(specifier, context, nextResolve) {
  if (specifier === "postgres") return { url: STUB, shortCircuit: true, format: "module" };
  return nextResolve(specifier, context);
}
