import { createClient } from "@supabase/supabase-js";

// PLANTED BUG (P-VITE-SERVICE-ROLE-CLIENT, #565): a Vite/no-code SPA has no "use client" boundary —
// all of its code is client code — and reads env via import.meta.env.VITE_*. Vite statically INLINES
// every VITE_-prefixed var into the browser bundle, so a service-role key named with the VITE_ prefix
// ships full RLS-bypass credentials to every visitor. harvey-vite-service-role-in-client → high
// (Critical). This is nocode-rescue #1 (service_role shipped to the browser bundle).
export const admin = createClient(
  import.meta.env.VITE_SUPABASE_URL,
  import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY,
);
