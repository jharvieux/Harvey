import { supabase } from "../lib/supabaseAnonClient";
import { sendReminder } from "./mailer";

// The correct form of D-091 item 22 (#1230): CAS-claim the row FIRST, skip the send when zero rows
// were claimed. A concurrent run loses the race on the claim and sends nothing.

export async function fireTaskRemindersClaimed() {
  const { data: due } = await supabase.from("d091_reminders").select("id, recipient").is("sent_at", null);
  for (const row of due ?? []) {
    const { data: claimed } = await supabase
      .from("d091_reminders")
      .update({ sent_at: new Date().toISOString() })
      .eq("id", row.id)
      .is("sent_at", null)
      .select("id");
    if (!claimed || claimed.length === 0) continue;
    await sendReminder(row.recipient);
  }
}
