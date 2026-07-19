import { createClient } from "@supabase/supabase-js";

// TRUE NEGATIVE (N-VITE-ANON-CLIENT, #565): the anon/publishable key is DESIGNED to ship to the
// browser (it is RLS-protected), so reading it from import.meta.env.VITE_SUPABASE_ANON_KEY is the
// correct, intended shape. harvey-vite-service-role-in-client is scoped to a SERVICE_ROLE/SERVICE_KEY
// name via metavariable-regex — the anon key name does not match, so this must clear.
export const supabase = createClient(
  import.meta.env.VITE_SUPABASE_URL,
  import.meta.env.VITE_SUPABASE_ANON_KEY,
);
