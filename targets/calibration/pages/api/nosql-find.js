import { db } from "../../lib/mongo";

// PLANTED BUG (P-NOSQL-REGEX, #985): the request-controlled name is placed directly under a Mongo
// $regex operator — NoSQL injection (an attacker supplies a catastrophic or filter-bypassing
// regex, or crafts operator objects). harvey-nosql-injection taint (req -> $where/$regex/$ne/...).
export default async function handler(req, res) {
  const data = req.query.name;
  const user = await db.collection("users").findOne({ name: { $regex: data } });
  res.status(200).json(user);
}
