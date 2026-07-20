import { admin } from "../../lib/supabaseAdmin";

// PLANTED BUG (P-JOB-TENANT-SCOPE, #681): a background-job (Inngest) function reads a
// per-tenant table on the RLS-bypassing service-role client with NO tenant predicate. A job
// has no request and no session, so nothing scopes this read — it returns every tenant's
// inbound messages. This is the shape of ATC finding #2003 (import-pipeline service-role read
// of gmail_inbound_messages). The safe form filters by the job payload's tenant id (see
// import-inbound-safe.ts, N-JOB-TENANT-SCOPED).
export const importInbound = inngest.createFunction(
  { id: "import-inbound" },
  { event: "gmail/received" },
  async ({ event }) => {
    const { data } = await admin.from("gmail_inbound_messages").select("*");
    return data;
  },
);
