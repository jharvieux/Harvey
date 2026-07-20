import { admin } from "../../lib/supabaseAdmin";

// TRUE NEGATIVE (N-JOB-TENANT-SCOPED, #681): the same background-job service-role read, but
// scoped by the job payload's tenant id via `.eq("tenant_id", …)`. The service-role client
// still bypasses RLS, but the explicit tenant predicate confines the read to one tenant, so
// there is no cross-tenant exposure for the detector to flag. Contrast import-inbound.ts
// (P-JOB-TENANT-SCOPE), which has no tenant predicate at all.
export const importInbound = inngest.createFunction(
  { id: "import-inbound" },
  { event: "gmail/received" },
  async ({ event }) => {
    const { data } = await admin
      .from("gmail_inbound_messages")
      .select("*")
      .eq("tenant_id", event.data.tenantId);
    return data;
  },
);
