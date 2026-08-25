import { supabase } from "../lib/supabaseAnonClient";
import { handleSubscriptionEvent } from "./handlers";

// D-091 item 10 (#1230) -- the idempotency row is written BEFORE the work it guards. A crash
// between the insert and the dispatch makes the provider's retry look like a duplicate, so the
// work never completes and nothing reports it: the row says "processed" when it means "received".

export async function processProviderEvent(event: { id: string; type: string; created: number }) {
  await supabase.from("d091_webhook_events").insert({ event_id: event.id, kind: event.type, received_at: event.created });
  await handleSubscriptionEvent(event);
}
