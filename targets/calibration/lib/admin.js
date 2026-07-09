import { createClient } from "@supabase/supabase-js";

// PLANTED BUG (P-SRV-ROLE-JWT-SRC): a Supabase service_role JWT hardcoded in source. The token
// is FAKE (fake signature, ref "calibrationref01"), but its base64 body decodes to
// "role":"service_role" — the only reliable signal (anon and service_role JWTs are otherwise
// structurally identical). gitleaks decodes it (--max-decode-depth 2) and the custom
// supabase-service-role-jwt rule fires on the decoded claim → high (full RLS bypass).
const SERVICE_ROLE_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImNhbGlicmF0aW9ucmVmMDEiLCJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjIwMDAwMDAwMDB9.Rm3kL9pQ2vXcW8rNpKdLhGfYsAe4Uo1Bx6Vt0Zi7Ny";

export const admin = createClient("https://calibrationref01.supabase.co", SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});
