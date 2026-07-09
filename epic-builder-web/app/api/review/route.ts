import { NextResponse } from "next/server";
import { handle } from "../../../lib/route.js";
import { reviewAction, type ReviewInput } from "../../../lib/core.js";

export const runtime = "nodejs";

export async function POST(req: Request): Promise<NextResponse> {
  const { slug, ...input } = (await req.json()) as { slug?: string } & ReviewInput;
  return handle(async (deps) => {
    if (!slug) throw new Error("slug is required");
    return reviewAction(deps, slug, input);
  });
}
