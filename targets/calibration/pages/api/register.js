import { admin } from "../../lib/supabaseAdmin";

// PLANTED BUG (P-PLAINTEXT-PASSWORD): the request body's raw password is written straight to
// the `password` column with no hashing step (bcrypt/argon2) — a DB compromise (or a stray
// SELECT *) leaks every user's password in plaintext.
export default async function handler(req, res) {
  const { data, error } = await admin.from("users").insert({ email: req.body.email, password: req.body.pw });
  res.status(error ? 500 : 200).json({ data, error });
}
