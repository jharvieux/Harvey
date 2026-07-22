import { createClient } from "@supabase/supabase-js";
import { SUPABASE_SERVICE_ROLE_KEY } from "./serviceRoleKeyStore";

// PLANTED BUG (P-SRV-ROLE-LITERAL-CROSSFILE, #664 Gap C): the service_role literal is defined in
// ANOTHER module (serviceRoleKeyStore.ts) and imported here before reaching createClient —
// out of single-file semgrep const-propagation's reach. The AST detector
// (src/scan/service-role-literal.ts) resolves the import (same resolveImport helper app-router.ts
// uses for its cross-file server->client leak check) and decodes the remote literal.
export const admin = createClient(import.meta.env.VITE_SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
