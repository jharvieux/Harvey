import { supabase } from "../lib/supabaseAnonClient";

// D-091 item 27 (#1230) -- webhook state-application without ordering protection. Replay dedup
// (signature + delivery-id row) stops the SAME event firing twice; it does nothing about a stale
// event arriving after a fresher one under at-least-once, unordered delivery. This handler writes
// the event's status with no comparison against the last-applied event time or version, so an
// out-of-order older delivery overwrites newer state.
//
// DETECTED since #1352 by src/scan/idempotency.ts's `webhookOrdering`, at review tier. It was
// planted as a no-mechanical-rule class on the argument that a rule "would have to prove the
// ABSENCE of an ordering guard anywhere reachable from the handler, including through an imported
// wrapper" — the same absence-at-reach problem four shipped detectors answer by scoping to the
// function body and stating that bound in the finding.

export async function applySubscriptionEvent(event: { id: string; created: number; status: string; customerRef: string }) {
  const { error } = await supabase
    .from("d091_subscriptions")
    .update({ status: event.status })
    .eq("customer_ref", event.customerRef);
  if (error) throw error;
}
