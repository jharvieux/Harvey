import { createClient } from "@supabase/supabase-js";
import { SUPABASE_ANON_KEY } from "./crossFileAnonKeyStore";

// NEGATIVE (N-SRV-ROLE-CROSSFILE-ANON, #664 Gap C): imports the anon literal cross-file. The
// decoded role claim is "anon", so this stays dark even though the import resolves correctly.
export const supabase = createClient(import.meta.env.VITE_SUPABASE_URL, SUPABASE_ANON_KEY);
