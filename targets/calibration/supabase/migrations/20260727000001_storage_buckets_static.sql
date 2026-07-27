-- #1182 (cipherx CX-10) — storage buckets declared in MIGRATION SQL rather than through the
-- dashboard or a seed script. The connected-tier checkPublicBucketsWithNoPolicies reads
-- storage.buckets from a live database and the #560 semgrep rule reads createBucket() in app/seed
-- code; a bucket committed as an INSERT into storage.buckets was visible to neither.

-- POSITIVE (1): public = true, positional column list. Every object in this bucket is served
-- unauthenticated from /storage/v1/object/public/<bucket>/<path>, regardless of storage.objects RLS.
insert into storage.buckets (id, name, public, file_size_limit)
values ('kyc-documents', 'kyc-documents', true, 52428800);

-- POSITIVE (2): the same shape written with the boolean in a different position and a second row
-- in the same statement, so the value is read from the tuple by column index rather than by
-- assuming a fixed layout.
insert into storage.buckets (id, public, name)
values
  ('scan-reports', true, 'scan-reports'),
  ('internal-archive', false, 'internal-archive');

-- POSITIVE (3): a storage.objects SELECT policy granted to the anon/public role with no owner
-- predicate — a PRIVATE bucket whose read policy nonetheless opens every object in it to an
-- unauthenticated caller. Distinct from the public flag above: the bucket is not public, the
-- policy is.
create policy exports_read_anon on storage.objects
  for select
  to anon
  using (bucket_id = 'exports');

-- NEGATIVE (1): public = false — a private bucket, storage RLS applies. Must stay clear.
insert into storage.buckets (id, name, public)
values ('patient-files', 'patient-files', false);

-- NEGATIVE (2): a bucket insert with no `public` column at all — Postgres defaults it to false.
insert into storage.buckets (id, name)
values ('build-cache', 'build-cache');

-- NEGATIVE (3): a storage.objects SELECT policy granted to anon but scoped to the caller's own
-- folder — the standard one-folder-per-user ownership pattern, correct even for a signed-URL flow.
-- The auth.uid() call is (select …)-wrapped so the auth_rls_initplan perf lint stays quiet too:
-- this fixture must be silent, so the corpus row cannot read as a hit from an unrelated rule.
create policy exports_read_own on storage.objects
  for select
  to anon
  using (bucket_id = 'exports' and (storage.foldername(name))[1] = (select auth.uid())::text);
