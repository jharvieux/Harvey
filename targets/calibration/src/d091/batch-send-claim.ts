import { supabase } from "../lib/supabaseAnonClient";
import { sendReminder } from "./mailer";

// D-091 item 22 (#1230) -- claim-before-send. The row is stamped AFTER the send, so a retry (or a
// second overlapping run of the same cron) re-sends every row whose stamp has not landed yet. A
// single-run test never sees it.

export async function fireTaskReminders() {
  const { data: due } = await supabase.from("d091_reminders").select("id, recipient").is("sent_at", null);
  for (const row of due ?? []) {
    await sendReminder(row.recipient);
    await supabase.from("d091_reminders").update({ sent_at: new Date().toISOString() }).eq("id", row.id);
  }
}
