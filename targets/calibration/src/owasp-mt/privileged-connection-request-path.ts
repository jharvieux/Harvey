import { createClient } from "@supabase/supabase-js";

// OWASP Multi-Tenant CS section 2 + our proposed addition (CheatSheetSeries#2309 item 1):
// FORCE ROW LEVEL SECURITY binds the table OWNER only. A role holding BYPASSRLS -- which is what a
// service-role key is -- bypasses row security unconditionally, so every policy on every table is
// void for this client. Here it serves an ordinary user request, which means the app has no tenant
// isolation at all despite correct-looking policies in the migrations.

const admin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!,
);

export async function getProjectForUser(projectId: string) {
  const { data } = await admin.from("projects").select("*").eq("id", projectId).single();
  return data;
}
