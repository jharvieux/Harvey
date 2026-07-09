import { NextResponse } from "next/server";
import { handle } from "../../../lib/route.js";
import { getState, startSession } from "../../../lib/core.js";

export const runtime = "nodejs";

// POST: start a new epic from a prompt (returns slug + round-1 clarifying questions).
export async function POST(req: Request): Promise<NextResponse> {
  const { prompt } = (await req.json()) as { prompt?: string };
  return handle(async (deps) => {
    if (!prompt || !prompt.trim()) throw new Error("a prompt is required");
    return startSession(deps, prompt.trim());
  });
}

// GET ?slug=: load the current view (resume / refresh).
export async function GET(req: Request): Promise<NextResponse> {
  const slug = new URL(req.url).searchParams.get("slug");
  return handle(async (deps) => {
    if (!slug) throw new Error("slug is required");
    return getState(deps, slug);
  });
}
