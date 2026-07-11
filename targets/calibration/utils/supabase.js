import { createClient } from "@supabase/supabase-js";

// The plain anon (publishable-key) client — safe to ship to the browser. Contrast
// lib/supabaseAdmin.js, which holds the service-role key and must never load in a Client
// Component. Used by the N-AUTH-ADMIN-ANON-CLIENT negative (#164).
export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
);
