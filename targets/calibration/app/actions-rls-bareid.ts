"use server";

import { createClient } from "../lib/supabase";

// TRUE NEGATIVE (N-RLS-CLIENT-BARE-ID, #465): the SAME no-auth + bare `.eq("id", …)` syntax as
// actions-svc-bareid.ts, but on the PLAIN (RLS-enforced) client — row policies still gate the
// write, so the widened owner-id shape must stay silent. Modelled on proposit's
// updateOrganisationLogo, the measured near-miss. The generic missing-auth finding is the one
// that fires here (and is NOT subsumed) — the defect this file does carry is "no visible auth
// check", not "client picks the row on an RLS-bypassing client".
export async function updateOrganisationLogo(organisationId: string, logoPath: string) {
  const supabase = await createClient();

  await supabase.from("organisations").update({ logo: logoPath }).eq("id", organisationId);
}
