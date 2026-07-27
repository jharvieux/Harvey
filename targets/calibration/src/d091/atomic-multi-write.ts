import { supabase } from "../lib/supabaseAnonClient";

// D-091 item 23 (#1230) -- collectively-atomic multi-writes. The group row and its owner-membership
// row are one invariant, written as two statements. Both writes check their error, so nothing here
// is silently swallowed: the defect is that a crash BETWEEN them leaves a group with no owner, and
// the retry re-creates the group.
//
// Planted as a NO-MECHANICAL-RULE class by decision (see briefs/anti-patterns.md, item 23). Two
// writes in one function is not a defect -- whether they form a single invariant is a judgement
// about what the rows MEAN, which is why this sits in the M1 semantic pass and not in an AST rule.

export async function createGroupWithOwner(groupName: string, ownerId: string) {
  const { data: group, error: groupError } = await supabase
    .from("d091_groups")
    .insert({ name: groupName })
    .select("id")
    .single();
  if (groupError) throw groupError;

  const { error: memberError } = await supabase
    .from("d091_group_members")
    .insert({ group_id: group.id, member_id: ownerId, role: "owner" });
  if (memberError) throw memberError;
}
