import { Pool } from "pg";

// NEGATIVE (N-PG-SSL-OK): the same Supabase pooler connection with TLS verification ON. The rule
// matches only `ssl: false`, so a verifying ssl object is cleared.
export const pool = new Pool({
  connectionString: "postgres://appuser:pw@aws-0-us-east-1.pooler.supabase.com:6543/postgres",
  ssl: { rejectUnauthorized: true },
});
