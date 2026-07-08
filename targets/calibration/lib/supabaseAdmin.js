import { createClient } from "@supabase/supabase-js";

// Service-role client: bypasses RLS entirely. Anything reached with this must do
// its own tenant scoping in code. Several routes here deliberately fail to.
export const admin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false, autoRefreshToken: false } }
);
