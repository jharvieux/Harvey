// PLANTED BUG (P-DB-ERROR-DISCLOSURE): the raw Postgres/PostgREST error object is echoed
// straight into the JSON response — leaks constraint names, column names, and query internals.
export default async function handler(req, res) {
  const { data, error } = await supabase.from("orders").select("*");
  if (error) {
    return res.status(500).json(error);
  }
  res.status(200).json(data);
}
