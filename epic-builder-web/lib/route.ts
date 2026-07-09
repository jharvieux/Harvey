// Route-handler helper: enforce the auth gate (design §6), run the handler, and turn a thrown error
// into a JSON 400 whose message carries no secret (the tracker layer already guarantees tokens never
// reach an error message; this only surfaces the message text). Keeps every route to parse -> call
// wrap -> return JSON.

import { NextResponse } from "next/server";
import { isAuthenticated } from "./auth.js";
import { productionDeps } from "./deps.js";
import type { CoreDeps } from "./core.js";

export async function handle(fn: (deps: CoreDeps) => Promise<unknown>): Promise<NextResponse> {
  if (!(await isAuthenticated())) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  try {
    return NextResponse.json(await fn(productionDeps()));
  } catch (err) {
    return NextResponse.json({ error: err instanceof Error ? err.message : String(err) }, { status: 400 });
  }
}
