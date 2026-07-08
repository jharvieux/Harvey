import { Pool } from "pg";

// Direct Postgres pool using the service connection string. Runs as the DB owner,
// so RLS does not apply here — query construction must be parameterised. One route
// deliberately concatenates user input instead.
export const pool = new Pool({ connectionString: process.env.DATABASE_URL });
