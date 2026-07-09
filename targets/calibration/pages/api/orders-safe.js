// TRUE NEGATIVE (N-ERROR-GENERIC): a generic error message with no stack trace and no raw error
// object — covers both harvey-verbose-error (no .stack/.message access) and
// harvey-db-error-disclosure (the literal `error` identifier is never passed to res.json here).
export default async function handler(req, res) {
  const { data, error } = await supabase.from("orders").select("*");
  if (error) {
    return res.status(500).json({ error: "Server error" });
  }
  res.status(200).json(data);
}
