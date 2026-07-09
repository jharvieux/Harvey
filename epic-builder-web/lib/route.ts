// Route-handler helper: enforce the auth gate (design §6), run the handler, and turn a thrown error
// into a JSON 400 whose message carries no secret (the tracker layer already guarantees tokens never
// reach an error message; this only surfaces the message text). Keeps every route to parse -> call
// wrap -> return JSON.

import { NextResponse } from "next/server";
import { resolveUserId } from "./auth.js";
import { productionDeps } from "./deps.js";
import type { CoreDeps } from "./core.js";

export async function handle(fn: (deps: CoreDeps) => Promise<unknown>): Promise<NextResponse> {
  const userId = await resolveUserId();
  if (!userId) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  const { deps, commit } = await productionDeps(userId);
  try {
    const result = await fn(deps);
    // Persist only on success: with the Supabase store this makes each request's writes atomic (a failed
    // request flushes nothing); with the filesystem store commit is a no-op and the core has already
    // written to disk.
    await commit();
    return NextResponse.json(result);
  } catch (err) {
    return NextResponse.json({ error: err instanceof Error ? err.message : String(err) }, { status: 400 });
  }
}
