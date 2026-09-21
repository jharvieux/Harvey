// Authenticate before parsing or invoking core, flush only a successful result, and release
// request-owned resources on every exit.

import { NextResponse } from "next/server";
import { resolveUserId } from "./auth.js";
import { productionDeps } from "./deps.js";
import type { CoreDeps } from "./core.js";

export async function handle(fn: (deps: CoreDeps) => Promise<unknown>): Promise<NextResponse> {
  let acquired: Awaited<ReturnType<typeof productionDeps>> | undefined;
  let response: NextResponse | undefined;
  let failure: unknown;
  try {
    const userId = await resolveUserId();
    if (!userId) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
    acquired = await productionDeps(userId);
    const result = await fn(acquired.deps);
    await acquired.commit();
    response = NextResponse.json(result);
  } catch (err) {
    failure = err;
  }
  try {
    await acquired?.release();
  } catch (err) {
    if (failure === undefined) failure = err;
  }
  if (failure !== undefined) {
    return NextResponse.json({ error: failure instanceof Error ? failure.message : String(failure) }, { status: 400 });
  }
  return response!;
}
