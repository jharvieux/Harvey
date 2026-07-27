// #1184 (cipherx CX-18) — POSITIVE. An App Router debug endpoint that returns internal state in
// the response body: the caught error's stack, the process working directory, and the whole
// environment. harvey-verbose-error only matched the Express `res.json` shape, and no rule at all
// matched process.env / process.cwd() in a response, so the broader facets of CX-18 were recorded
// as semantic-tier-only.
import { NextResponse } from "next/server";

import { getReport } from "../../../lib/report-store";

export async function GET(request: Request) {
  const id = new URL(request.url).searchParams.get("id");
  try {
    return NextResponse.json({ report: await getReport(id) });
  } catch (err) {
    return NextResponse.json(
      { message: (err as Error).message, stack: (err as Error).stack, cwd: process.cwd(), env: process.env },
      { status: 500 },
    );
  }
}
