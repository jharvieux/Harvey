import { NextResponse } from "next/server";
import { handle } from "../../../lib/route.js";
import { runPublish } from "../../../lib/core.js";

export const runtime = "nodejs";

export async function POST(req: Request): Promise<NextResponse> {
  const { slug, dryRun } = (await req.json()) as { slug?: string; dryRun?: boolean };
  return handle(async (deps) => {
    if (!slug) throw new Error("slug is required");
    return runPublish(deps, slug, dryRun ?? true);
  });
}
