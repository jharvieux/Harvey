import { db } from "../../lib/mongo";

// N-NOSQL-EQ-LOOKUP (NEGATIVE — must NOT be flagged, #985): a plain equality lookup by id. The
// request value is the VALUE of an ordinary field, not fed into a $-operator, so it is a normal
// scoped query, not injection. harvey-nosql-injection requires the tainted value to reach a Mongo
// operator ($where/$regex/$ne/...) — cleared. Keeps the rule off ordinary id lookups.
export default async function handler(req, res) {
  const id = req.params.id;
  const user = await db.collection("users").findOne({ _id: id });
  res.status(200).json(user);
}
