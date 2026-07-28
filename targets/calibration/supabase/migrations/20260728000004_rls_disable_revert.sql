-- #1425 — the revert the billing_exports hotfix never got. This is the second half of
-- N-RLS-DISABLE-REVERTED: public.import_staging goes back to protected, in a LATER file than the
-- disable, so clearing it requires resolving row-security state in apply order across the whole
-- file set rather than asking whether a disable statement exists anywhere.
--
-- This file is also its own readership proof, which is why the negative needs no separate scope
-- control: if it were skipped, import_staging would resolve to disabled, SB-RLS-DISABLED-STATIC
-- would fire on a benign fixture, and N-RLS-DISABLE-REVERTED would FAIL the gate as a free-count
-- false positive. An unread file here goes red, not quiet.
alter table public.import_staging enable row level security;
