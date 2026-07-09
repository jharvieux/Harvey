-- Epic Builder web — durable, per-user storage for the workspace seam (design epic-builder-web.md §4).
--
-- Two tables partition every session and draft by the authenticated Supabase user id:
--   epic_sessions(user_id, slug, state, json)  — one row per workspace; json is the whole DraftSession,
--                                                state is denormalized from json for cheap listing.
--   epic_drafts(user_id, slug, path, body)      — one row per file in the workspace tree (epic.md,
--                                                intake.md, stories/*.md, briefs/*.md, .revisions/*, …).
--
-- RLS scopes every row to its owner, so a client using the anon/publishable key can never read or write
-- across users. The server-side adapter uses the service-role key (which bypasses RLS) and additionally
-- filters every query by user_id itself — RLS is the defense-in-depth for the anon-key path.

create table if not exists public.epic_sessions (
  user_id    uuid        not null references auth.users (id) on delete cascade,
  slug       text        not null,
  state      text        not null,
  json       jsonb       not null,
  updated_at timestamptz not null default now(),
  primary key (user_id, slug)
);

create table if not exists public.epic_drafts (
  user_id    uuid        not null references auth.users (id) on delete cascade,
  slug       text        not null,
  path       text        not null,
  body       text        not null,
  updated_at timestamptz not null default now(),
  primary key (user_id, slug, path)
);

create index if not exists epic_drafts_user_slug_idx on public.epic_drafts (user_id, slug);

alter table public.epic_sessions enable row level security;
alter table public.epic_drafts   enable row level security;

-- Owner-only access. auth.uid() is the caller's Supabase user id: a client using the anon key only ever
-- sees its own rows. USING gates read/update/delete; WITH CHECK gates the target of insert/update, so a
-- row can never be written with someone else's user_id.
create policy epic_sessions_owner on public.epic_sessions
  for all
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy epic_drafts_owner on public.epic_drafts
  for all
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);
