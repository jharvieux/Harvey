import { NextResponse } from "next/server";
import { handle } from "../../../lib/route.js";
import { submitClarify } from "../../../lib/core.js";

export const runtime = "nodejs";

export async function POST(req: Request): Promise<NextResponse> {
  const { slug, answers } = (await req.json()) as { slug?: string; answers?: string };
  return handle(async (deps) => {
    if (!slug) throw new Error("slug is required");
    return submitClarify(deps, slug, answers ?? "defaults");
  });
}
