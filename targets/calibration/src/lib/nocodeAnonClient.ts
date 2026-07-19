import { createClient } from "@supabase/supabase-js";

// NEGATIVE (N-ANON-LITERAL-CLIENT, #611 Gap A): the SAME inline-literal shape, but the key is the
// anon/publishable key (role:anon) — which is meant to be public and shipped to the browser.
// harvey-service-role-literal requires a service_role token signature, so the anon literal is
// correctly NOT flagged. Regression guard that the rule keys on the role, not on "a JWT literal".
const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZpeHR1cmVyZWYwMSIsInJvbGUiOiJhbm9uIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjIwMDAwMDAwMDB9.FAKEsig_notreal_000000000000000000000";
export const supabase = createClient(import.meta.env.VITE_SUPABASE_URL, SUPABASE_ANON_KEY);
