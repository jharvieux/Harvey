import { supabase } from "../lib/supabaseAnonClient";
import { handleSubscriptionEvent } from "./handlers";

// The correct form of D-091 item 10 (#1230): the row's existence means "fully processed", so it is
// written after the dispatched handler returns. A crash mid-handler leaves no row and the
// provider's retry does the work.

export async function processProviderEventOrdered(event: { id: string; type: string }) {
  await handleSubscriptionEvent(event);
  await supabase.from("d091_webhook_events").insert({ event_id: event.id, kind: event.type });
}

// The other shape the rule must clear: a dedup row written on its own, with nothing dispatched
// after it. Recording receipt is not this bug.
export async function recordProviderEvent(event: { id: string; type: string }) {
  await supabase.from("d091_webhook_events").insert({ event_id: event.id, kind: event.type });
}
