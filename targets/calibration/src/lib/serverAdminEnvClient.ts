import "server-only";
import { createClient } from "@supabase/supabase-js";

// NEGATIVE (N-SRV-ROLE-ENV-CLIENT, #611 Gap A): the correct server-side admin client — the
// service_role key is read from process.env, NOT hardcoded as a literal. harvey-service-role-literal
// only matches a string-literal key, so this legitimate usage stays dark. The discriminator is
// literal-vs-env, which is exactly what separates a leaked key from a correct one.
export const admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
