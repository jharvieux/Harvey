// Batch B16 (#123) — semantic-tier Supabase policy-body/function-body fixtures (roadmap
// `docs/design/corpus-roadmap-to-100.md` §4a). Three classes were carved out of #123's broader
// semantic backlog for fixture-only sweep scope: #137 (storage read policy checks auth, not
// ownership), #138 (storage upload policy WITH CHECK(true)), #139 (SECURITY DEFINER privileged
// write with no auth.uid() check). All three were originally judged to need policy/function-BODY
// reasoning a structural grep can't do reliably, so — per #123 option (b) — detection was left to
// the existing LLM high-recall pass rather than a new mechanical scanner.
//
// That call has since been revisited for all three, and each proved mechanically reachable once
// the reviewer that ALREADY existed was fed from parsed migration SQL instead of a live DB:
// #220/#256 for the two storage policies, #264 for the SECURITY DEFINER write. What looked
// semantic was the CLASSIFIER's question (is this exposure intended?), not the reviewers' narrower
// one (does the body bind any row to the caller?) — which is textual, and discriminates each
// positive from its planted benign twin exactly. All three remain `review` tier and remain covered
// by the LLM pass; the mechanical hit is an ADDITIONAL feed, never free-count. What the gate
// enforces is that the negatives raise zero free-count false positives.
//
// See GROUND-TRUTH.md §B16.

import type { CorpusEntry } from "./types.js";

export const b16StorageSecdefEntries: CorpusEntry[] = [
  // --- POSITIVES (semantic-tier — not caught by the static gate; see note above) ---
  { id: "P-STORAGE-AUTH-NOT-OWNER", kind: "positive", cls: "storage.objects read policy checks auth, not ownership", location: "20260710000001_b15_storage_secdef_semantic.sql", match: ["user_files_select_authenticated"], expectedTier: "review", note: "create policy user_files_select_authenticated on storage.objects for select using (bucket_id = 'user-files' and auth.role() = 'authenticated') — any signed-in user reaches every other user's files in the bucket, not just their own folder. Policy-body semantics; no mechanical rule reads storage.objects USING clauses, so this is a documented static miss (#123 option (b), LLM/vuln-scan high-recall pass covers it)." },
  { id: "P-STORAGE-UPLOAD-CHECK-TRUE", kind: "positive", cls: "storage.objects upload policy WITH CHECK(true)", location: "20260710000001_b15_storage_secdef_semantic.sql", match: ["user_files_insert_open"], expectedTier: "review", note: "create policy user_files_insert_open on storage.objects for insert with check (true) — unrestricted; any authenticated caller can write to any path in any bucket. Code-side upload-limit absence is already covered by P-UPLOAD-NO-LIMIT (b14-applogic.entries.ts); this is the policy-body shape. No longer a static miss: #256 added the WITH CHECK (true) rule to the shared reviewer, so P-STORAGE-UPLOAD-CHECK-TRUE-STATIC (rls-static-semantics.entries.ts) also catches this mechanically at review tier — both may fire, neither is free-count. Same arrangement as P-STORAGE-AUTH-NOT-OWNER." },
  { id: "P-SECDEF-PRIV-WRITE-NOAUTH", kind: "positive", cls: "SECURITY DEFINER function does a privileged write with no auth.uid() check", location: "20260710000001_b15_storage_secdef_semantic.sql", match: ["promote_to_admin(target_user_id"], expectedTier: "review", note: "public.promote_to_admin(target_user_id uuid), security definer, granted to authenticated, updates public.profiles.role with no check on who is calling — any authenticated caller can promote any user (including themselves) to admin. No longer a static miss: #264 wired checkMigrationDefinerAuthz (supabase-static.ts) to feed the EXISTING definer-review.ts reviewer from parsed migration SQL, the same 'one rule set, two feeds' arrangement #220/#256 used for the storage policies above. The #123 option-(b) call that this needed function-body SEMANTICS held for the classifier's question (is this exposure intended?) but not for this one: 'a privileged write with no auth.uid() anywhere in the body' is a textual fact, and it discriminates promote_to_admin from promote_to_admin_checked exactly. Review tier, never free-count — the body-read can't see a caller-side gate. The LLM/vuln-scan pass still covers it too; both may fire." },

  // --- NEGATIVES (must NOT be flagged in the free count) ---
  { id: "N-STORAGE-OWNERSHIP-SCOPED", kind: "negative", cls: "storage.objects read policy scoped to the caller's own folder", location: "20260710000001_b15_storage_secdef_semantic.sql", match: ["user_files_select_own"], note: "create policy user_files_select_own on storage.objects for select using (bucket_id = 'user-files' and (storage.foldername(name))[1] = auth.uid()::text) — the standard one-folder-per-user ownership pattern. No mechanical rule reads storage.objects bodies at all, so this is trivially silent; the entry exists to keep the fixture pair symmetric with P-STORAGE-AUTH-NOT-OWNER." },
  { id: "N-STORAGE-UPLOAD-OWNERSHIP-MIME", kind: "negative", cls: "storage.objects upload policy scoped to ownership + allowed mime types", location: "20260710000001_b15_storage_secdef_semantic.sql", match: ["user_files_insert_own"], note: "create policy user_files_insert_own on storage.objects for insert with check (bucket_id = 'user-files' and (storage.foldername(name))[1] = auth.uid()::text and (metadata ->> 'mimetype') = any (array[...])) — ownership-scoped and mime-restricted, mirroring the bucket's allowed_mime_types (config.toml). No mechanical rule reads storage.objects bodies — trivially silent." },
  { id: "N-SECDEF-PRIV-WRITE-AUTHCHECK", kind: "negative", cls: "SECURITY DEFINER function gates its privileged write on an explicit caller check", location: "20260710000001_b15_storage_secdef_semantic.sql", match: ["promote_to_admin_checked(target_user_id"], note: "public.promote_to_admin_checked(target_user_id uuid), security definer, raises an exception unless a lookup on the CALLER's own row (`where id = auth.uid() and role = 'admin'`) succeeds before the target row is promoted — the caller must already be an admin. No mechanical rule reads SECURITY DEFINER function bodies — trivially silent; contrasts P-SECDEF-PRIV-WRITE-NOAUTH." },
];
