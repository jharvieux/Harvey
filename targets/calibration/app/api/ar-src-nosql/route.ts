import { db } from "../../../lib/mongo";

// PLANTED BUG (P-NOSQL-JSON-BODY, #1221): the JSON body value lands under a Mongo $regex operator.
// harvey-nosql-injection was one of the 17 of 21 server-side taint rules blind to `await req.json()`.
export async function POST(req: Request) {
  const { name } = await req.json();
  const user = await db.collection("users").findOne({ name: { $regex: name } });
  return Response.json(user);
}
