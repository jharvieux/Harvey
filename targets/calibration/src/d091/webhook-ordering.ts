import { supabase } from "../lib/supabaseAnonClient";

// D-091 item 27 (#1230) -- webhook state-application without ordering protection. Replay dedup
// (signature + delivery-id row) stops the SAME event firing twice; it does nothing about a stale
// event arriving after a fresher one under at-least-once, unordered delivery. This handler writes
// the event's status with no comparison against the last-applied event time or version, so an
// out-of-order older delivery overwrites newer state.
//
// Planted as a NO-MECHANICAL-RULE class by decision (see briefs/anti-patterns.md, item 27), for the
// same reason item 20 (WEBHOOK-REPLAY) already is: a rule would have to prove the ABSENCE of an
// ordering guard anywhere reachable from the handler, including through an imported wrapper.

export async function applySubscriptionEvent(event: { id: string; created: number; status: string; customerRef: string }) {
  const { error } = await supabase
    .from("d091_subscriptions")
    .update({ status: event.status })
    .eq("customer_ref", event.customerRef);
  if (error) throw error;
}
