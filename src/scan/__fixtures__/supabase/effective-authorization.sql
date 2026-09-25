CREATE ROLE anon;
CREATE ROLE authenticated;
CREATE ROLE service_role BYPASSRLS;
CREATE ROLE app_owner;
CREATE ROLE readers;
CREATE ROLE bounded_definer;
GRANT readers TO authenticated;
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role, app_owner, bounded_definer;
CREATE SCHEMA hidden;
CREATE SCHEMA future;
CREATE SCHEMA pgtenant;
GRANT USAGE ON SCHEMA pgtenant TO anon;
GRANT USAGE ON SCHEMA future TO anon;
GRANT USAGE, CREATE ON SCHEMA future TO app_owner;

CREATE TABLE public.deny_all (id int, tenant text, secret text);
INSERT INTO public.deny_all VALUES (1, 'a', 'alpha'), (2, 'b', 'beta');
ALTER TABLE public.deny_all OWNER TO app_owner;
ALTER TABLE public.deny_all ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.deny_all TO anon, authenticated, service_role, bounded_definer;

CREATE TABLE public.restrictive (LIKE public.deny_all);
INSERT INTO public.restrictive SELECT * FROM public.deny_all;
ALTER TABLE public.restrictive ENABLE ROW LEVEL SECURITY;
GRANT ALL ON public.restrictive TO anon, authenticated;
CREATE POLICY permissive_all ON public.restrictive USING (true) WITH CHECK (true);
CREATE POLICY restrictive_none ON public.restrictive AS RESTRICTIVE USING (false) WITH CHECK (false);
CREATE TABLE public.restrictive_only (LIKE public.deny_all);
INSERT INTO public.restrictive_only SELECT * FROM public.deny_all;
ALTER TABLE public.restrictive_only ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON public.restrictive_only TO anon;
CREATE POLICY restriction_without_permission ON public.restrictive_only AS RESTRICTIVE USING (true);
CREATE TABLE public.policy_other_role (LIKE public.deny_all);
INSERT INTO public.policy_other_role SELECT * FROM public.deny_all;
ALTER TABLE public.policy_other_role ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON public.policy_other_role TO anon, authenticated;
CREATE POLICY authenticated_only ON public.policy_other_role TO authenticated USING (true);

CREATE TABLE public.tenant_rows (LIKE public.deny_all);
INSERT INTO public.tenant_rows SELECT * FROM public.deny_all;
ALTER TABLE public.tenant_rows ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON public.tenant_rows TO anon, authenticated;
CREATE POLICY scoped_rows ON public.tenant_rows USING (tenant = current_setting('fixture.tenant', true));

CREATE TABLE public.disabled (LIKE public.deny_all);
INSERT INTO public.disabled SELECT * FROM public.deny_all;
GRANT SELECT ON public.disabled TO anon;
CREATE TABLE public.no_grant (LIKE public.deny_all);
INSERT INTO public.no_grant SELECT * FROM public.deny_all;
CREATE TABLE hidden.no_schema (LIKE public.deny_all);
INSERT INTO hidden.no_schema SELECT * FROM public.deny_all;
GRANT SELECT ON hidden.no_schema TO anon;
CREATE TABLE pgtenant.visible (LIKE public.deny_all);
INSERT INTO pgtenant.visible SELECT * FROM public.deny_all;
GRANT SELECT ON pgtenant.visible TO anon;

CREATE TABLE public.column_rls (LIKE public.deny_all);
INSERT INTO public.column_rls SELECT * FROM public.deny_all;
ALTER TABLE public.column_rls ENABLE ROW LEVEL SECURITY;
GRANT SELECT (secret) ON public.column_rls TO anon;
GRANT UPDATE (secret) ON public.column_rls TO anon;
CREATE POLICY column_scope ON public.column_rls USING (tenant = current_setting('fixture.tenant', true));
CREATE TABLE public.column_open (LIKE public.deny_all);
INSERT INTO public.column_open SELECT * FROM public.deny_all;
GRANT SELECT (secret) ON public.column_open TO anon;

CREATE TABLE public.owner_unforced (LIKE public.deny_all);
INSERT INTO public.owner_unforced SELECT * FROM public.deny_all;
ALTER TABLE public.owner_unforced OWNER TO authenticated;
ALTER TABLE public.owner_unforced ENABLE ROW LEVEL SECURITY;
CREATE TABLE public.owner_forced (LIKE public.deny_all);
INSERT INTO public.owner_forced SELECT * FROM public.deny_all;
ALTER TABLE public.owner_forced OWNER TO authenticated;
ALTER TABLE public.owner_forced ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.owner_forced FORCE ROW LEVEL SECURITY;

CREATE TABLE public.inherited (LIKE public.deny_all);
INSERT INTO public.inherited SELECT * FROM public.deny_all;
ALTER TABLE public.inherited ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON public.inherited TO readers;
CREATE POLICY inherited_reader ON public.inherited TO readers USING (true);
CREATE TABLE public.public_grant (LIKE public.deny_all);
INSERT INTO public.public_grant SELECT * FROM public.deny_all;
GRANT SELECT ON public.public_grant TO PUBLIC;

ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA future GRANT SELECT ON TABLES TO anon;
CREATE TABLE future.current_denied (LIKE public.deny_all);
ALTER TABLE future.current_denied OWNER TO app_owner;
GRANT SELECT ON future.current_denied TO anon;
ALTER TABLE future.current_denied ENABLE ROW LEVEL SECURITY;
SET ROLE app_owner;
CREATE TABLE future.default_open (id int, secret text);
INSERT INTO future.default_open VALUES (1, 'alpha'), (2, 'beta');
CREATE TABLE future.default_denied (id int, secret text);
INSERT INTO future.default_denied VALUES (1, 'alpha'), (2, 'beta');
ALTER TABLE future.default_denied ENABLE ROW LEVEL SECURITY;
RESET ROLE;

CREATE FUNCTION public.definer_read() RETURNS SETOF public.deny_all
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog
BEGIN ATOMIC SELECT * FROM public.deny_all; END;
ALTER FUNCTION public.definer_read() OWNER TO app_owner;
CREATE FUNCTION public.definer_denied() RETURNS SETOF public.deny_all
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog
BEGIN ATOMIC SELECT * FROM public.deny_all; END;
ALTER FUNCTION public.definer_denied() OWNER TO bounded_definer;
CREATE FUNCTION public.definer_forced() RETURNS SETOF public.owner_forced
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog
BEGIN ATOMIC SELECT * FROM public.owner_forced; END;
ALTER FUNCTION public.definer_forced() OWNER TO authenticated;
CREATE FUNCTION public.definer_scoped() RETURNS SETOF public.deny_all
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog
BEGIN ATOMIC SELECT * FROM public.deny_all WHERE tenant = current_setting('fixture.tenant', true); END;
ALTER FUNCTION public.definer_scoped() OWNER TO app_owner;
CREATE FUNCTION public.definer_private() RETURNS SETOF public.deny_all
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog
BEGIN ATOMIC SELECT * FROM public.deny_all; END;
ALTER FUNCTION public.definer_private() OWNER TO app_owner;
REVOKE ALL ON FUNCTION public.definer_private() FROM PUBLIC;

CREATE SCHEMA storage;
CREATE TABLE storage.buckets (id text, name text, public boolean);
CREATE TABLE storage.objects (id int);
