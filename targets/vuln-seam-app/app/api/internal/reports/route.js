// NEGATIVE CONTROL (DIRECT-SERVICE-CALL must stay not-vulnerable): another /internal route, but it
// requires the fronting app's shared internal secret header. A direct anon call lacks it and gets a
// 401 with no data -> unproven.
import { timingSafeEqual } from "node:crypto";

export const dynamic = "force-dynamic";

export async function GET(request) {
  const presented = request.headers.get("x-internal-secret") ?? "";
  const expected = process.env.WEBHOOK_SIGNING_SECRET ?? "";
  const ok =
    presented.length === expected.length &&
    presented.length > 0 &&
    timingSafeEqual(Buffer.from(presented), Buffer.from(expected));
  if (!ok) return new Response("forbidden", { status: 401 });

  return Response.json([{ id: 1, kind: "internal-report" }]);
}
