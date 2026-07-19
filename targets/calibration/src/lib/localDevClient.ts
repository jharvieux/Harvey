import { createClient } from "@supabase/supabase-js";

// NEGATIVE (N-SRV-ROLE-DEMO-CLIENT, #611 Gap A): the well-known public supabase-start local-dev
// demo service_role key (decoded iss:"supabase-demo"), inlined against a localhost URL. It is a
// service_role token, but it is public by design and ships with every `supabase start`.
// harvey-service-role-literal excludes the supabase-demo signature, so a committed local key does
// not free-count. (gitleaks decodes it too, but the supabase-demo-key-marker correlation clears it.)
export const local = createClient("http://127.0.0.1:54321", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UtZGVtbyIsImlhdCI6MTY0MTc2OTIwMCwiZXhwIjoxNzk5NTM1NjAwfQ.FAKEsig_notreal_000000000000000000000");
