import { createClient } from "@supabase/supabase-js";

// Shared service-role client used by the server-only admin/cron fixtures. Server-only by intent;
// the P-AUTH-ADMIN-CLIENT positive is the Client Component that imports it into the browser bundle.
export const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false } },
);
