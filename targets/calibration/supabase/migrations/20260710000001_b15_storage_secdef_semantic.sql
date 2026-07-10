-- B15 (#123) — semantic-tier Supabase policy-body / function-body fixtures. These three classes
-- (roadmap `docs/design/corpus-roadmap-to-100.md` §4a) need policy/function-BODY reasoning, not a
-- structural grep, so they are deliberately NOT wired to a mechanical scanner — detection is the
-- existing LLM/vuln-scan high-recall pass (parent tracker #123, option (b)). Fixtures exist purely
-- so the free-count gate proves these plants raise zero false positives; a review-tier miss on the
-- positives in `pnpm validate:calibration` is expected and non-fatal (see cli/validate-calibration.ts).

-- #137 — P-STORAGE-AUTH-NOT-OWNER: a storage.objects SELECT policy gated only on
-- "is the caller logged in", not on which caller. Every signed-in user reaches every tenant's
-- file in the "user-files" bucket (config.toml), not just their own folder.
create policy user_files_select_authenticated on storage.objects
  for select
  using (bucket_id = 'user-files' and auth.role() = 'authenticated');

-- N-STORAGE-OWNERSHIP-SCOPED — benign lookalike: the same read policy, but scoped to the
-- caller's own folder via storage.foldername(name)[1] = auth.uid() (the standard Supabase
-- "one folder per user" ownership pattern). Contrast P-STORAGE-AUTH-NOT-OWNER above.
create policy user_files_select_own on storage.objects
  for select
  using (bucket_id = 'user-files' and (storage.foldername(name))[1] = auth.uid()::text);
