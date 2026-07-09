import { NextResponse } from "next/server";
import { handle } from "../../../lib/route.js";
import { fanOut, previewManifest } from "../../../lib/core.js";

export const runtime = "nodejs";

// GET ?slug=: preview the proposed story manifest before committing to drafting.
export async function GET(req: Request): Promise<NextResponse> {
  const slug = new URL(req.url).searchParams.get("slug");
  return handle(async (deps) => {
    if (!slug) throw new Error("slug is required");
    return { entries: await previewManifest(deps, slug) };
  });
}

// POST: draft the kept subset (or all if `keep` is omitted) and enter per-story review.
export async function POST(req: Request): Promise<NextResponse> {
  const { slug, keep } = (await req.json()) as { slug?: string; keep?: number[] };
  return handle(async (deps) => {
    if (!slug) throw new Error("slug is required");
    return fanOut(deps, slug, keep);
  });
}
