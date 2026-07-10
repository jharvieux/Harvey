// Batch B15 (#123) — semantic-tier Supabase policy-body/function-body fixtures (roadmap
// `docs/design/corpus-roadmap-to-100.md` §4a). Three classes were carved out of #123's broader
// semantic backlog for fixture-only sweep scope: #137 (storage read policy checks auth, not
// ownership), #138 (storage upload policy WITH CHECK(true)), #139 (SECURITY DEFINER privileged
// write with no auth.uid() check). All three need policy/function-BODY reasoning a structural
// grep can't do reliably, so — per #123 option (b) — detection is left to the existing LLM
// high-recall pass, not a new mechanical scanner. Every positive here is `review` tier and
// EXPECTED to miss the static gate (see cli/validate-calibration.ts's reviewMisses, non-fatal);
// what the gate enforces is that the negatives raise zero free-count false positives.
//
// See GROUND-TRUTH.md §B15.

import type { CorpusEntry } from "./types.js";

export const b15StorageSecdefEntries: CorpusEntry[] = [
  // --- POSITIVES (semantic-tier — not caught by the static gate; see note above) ---
  { id: "P-STORAGE-AUTH-NOT-OWNER", kind: "positive", cls: "storage.objects read policy checks auth, not ownership", location: "20260710000001_b15_storage_secdef_semantic.sql", match: ["user_files_select_authenticated"], expectedTier: "review", note: "create policy user_files_select_authenticated on storage.objects for select using (bucket_id = 'user-files' and auth.role() = 'authenticated') — any signed-in user reaches every other user's files in the bucket, not just their own folder. Policy-body semantics; no mechanical rule reads storage.objects USING clauses, so this is a documented static miss (#123 option (b), LLM/vuln-scan high-recall pass covers it)." },

  // --- NEGATIVES (must NOT be flagged in the free count) ---
  { id: "N-STORAGE-OWNERSHIP-SCOPED", kind: "negative", cls: "storage.objects read policy scoped to the caller's own folder", location: "20260710000001_b15_storage_secdef_semantic.sql", match: ["user_files_select_own"], note: "create policy user_files_select_own on storage.objects for select using (bucket_id = 'user-files' and (storage.foldername(name))[1] = auth.uid()::text) — the standard one-folder-per-user ownership pattern. No mechanical rule reads storage.objects bodies at all, so this is trivially silent; the entry exists to keep the fixture pair symmetric with P-STORAGE-AUTH-NOT-OWNER." },
];
