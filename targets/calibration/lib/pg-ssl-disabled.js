import { Pool } from "pg";

// PLANTED BUG (P-PG-SSL-DISABLED): a direct pg Pool to the Supabase pooler host with TLS turned
// OFF (ssl: false). Traffic to the pooler crosses the public internet, so disabling TLS exposes
// the connection (and the credentials in it) to a network attacker. harvey-pg-ssl-disabled.
export const pool = new Pool({
  connectionString: "postgres://appuser:pw@aws-0-us-east-1.pooler.supabase.com:6543/postgres",
  ssl: false,
});
