// #1184 — NEGATIVE. The same handler doing the correct thing: the stack and the working directory
// go to the server log, and the client gets a generic message. Logging err.stack is normal and must
// not fire; RETURNING it is the defect. Pins the rule to the response position rather than to the
// mere presence of `.stack` / `process.env` / `process.cwd()` in the file.
import { NextResponse } from "next/server";

import { getReport } from "../../../lib/report-store";

export async function GET(request: Request) {
  const id = new URL(request.url).searchParams.get("id");
  try {
    return NextResponse.json({ report: await getReport(id) });
  } catch (err) {
    console.error("report load failed", (err as Error).stack, process.cwd(), process.env.NODE_ENV);
    return NextResponse.json({ message: "Unable to load that report" }, { status: 500 });
  }
}
