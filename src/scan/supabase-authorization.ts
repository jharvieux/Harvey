import type { Finding } from "../findings.js";
import { mechanicalFinding } from "./common.js";

const COMMANDS = ["SELECT", "INSERT", "UPDATE", "DELETE"] as const;
const identity = (value: string) => encodeURIComponent(value).replaceAll("-", "%2D");
const identifier = (value: string) => /^[a-z_][a-z0-9_$]*$/.test(value) ? value : `"${value.replaceAll('"', '""')}"`;
type Command = typeof COMMANDS[number];
interface Policy { name: string; command: string; permissive: boolean; using: string | null; check: string | null }
interface Access {
  schema: string; name: string; role: string; owner: string;
  rls: boolean; forced: boolean; ownerAccess: boolean; bypass: boolean; superuser: boolean; schemaUsage: boolean;
  grants: Record<Command, boolean>; columns: { name: string; select: boolean; insert: boolean; update: boolean }[];
  policies: Policy[]; truncate: boolean; references: boolean;
}
interface Definer {
  schema: string; name: string; arguments: string; owner: string; bypass: boolean; superuser: boolean;
  callers: string[]; relations: { schema: string; name: string; rls: boolean; forced: boolean; ownerAccess: boolean }[];
}
export interface TableAuthorization {
  schema: string; name: string; detail: string; exposure: boolean;
  columns: { name: string; principals: { role: string; read: "all" | "none" | "conditional"; reason: string }[] }[];
}

// Read one catalog snapshot. PostgreSQL resolves PUBLIC and inherited ACL/policy roles;
// role attributes are read on the effective role rather than inherited from memberships.
const AUTHORIZATION_SQL = `/* harvey-effective-authorization-v1 */
with principals as (
  select oid, rolname, rolsuper, rolbypassrls from pg_roles where rolname in ('anon','authenticated','service_role')
    or oid in (select p.proowner from pg_proc p join pg_namespace n on n.oid=p.pronamespace
      where p.prosecdef and p.prokind='f' and n.nspname !~ '^pg_' and n.nspname<>'information_schema')
), relations as (
  select c.*, n.nspname as schema from pg_class c join pg_namespace n on n.oid=c.relnamespace
  where c.relkind in ('r','p') and n.nspname !~ '^pg_' and n.nspname <> 'information_schema'
)
select jsonb_build_object('version',1,'tableCount',(select count(*) from relations),
 'definerCount',(select count(*) from pg_proc p join pg_namespace n on n.oid=p.pronamespace
   where p.prosecdef and p.prokind='f' and n.nspname !~ '^pg_' and n.nspname<>'information_schema'),
 'roles',coalesce((select jsonb_agg(rolname order by rolname) from principals),'[]'::jsonb),
 'tables',coalesce((select jsonb_agg(jsonb_build_object(
   'schema',t.schema,'name',t.relname,'role',r.rolname,'owner',pg_get_userbyid(t.relowner),
   'rls',t.relrowsecurity,'forced',t.relforcerowsecurity,'ownerAccess',pg_has_role(r.oid,t.relowner,'USAGE'),
   'bypass',r.rolbypassrls,'superuser',r.rolsuper,'schemaUsage',has_schema_privilege(r.oid,t.relnamespace,'USAGE'),
   'grants',jsonb_build_object('SELECT',has_table_privilege(r.oid,t.oid,'SELECT'),'INSERT',has_table_privilege(r.oid,t.oid,'INSERT'),
     'UPDATE',has_table_privilege(r.oid,t.oid,'UPDATE'),'DELETE',has_table_privilege(r.oid,t.oid,'DELETE')),
   'truncate',has_table_privilege(r.oid,t.oid,'TRUNCATE'),'references',has_table_privilege(r.oid,t.oid,'REFERENCES'),
   'columns',coalesce((select jsonb_agg(jsonb_build_object('name',a.attname,
     'select',has_column_privilege(r.oid,t.oid,a.attnum,'SELECT'),
     'insert',has_column_privilege(r.oid,t.oid,a.attnum,'INSERT'),
     'update',has_column_privilege(r.oid,t.oid,a.attnum,'UPDATE')) order by a.attnum)
     from pg_attribute a where a.attrelid=t.oid and a.attnum>0 and not a.attisdropped),'[]'::jsonb),
   'policies',coalesce((select jsonb_agg(jsonb_build_object('name',p.polname,'command',p.polcmd,
     'permissive',p.polpermissive,'using',pg_get_expr(p.polqual,p.polrelid),'check',pg_get_expr(p.polwithcheck,p.polrelid)) order by p.polname)
     from pg_policy p where p.polrelid=t.oid and (0=any(p.polroles) or exists
       (select 1 from unnest(p.polroles) pr where pr<>0 and pg_has_role(r.oid,pr,'USAGE')))),'[]'::jsonb)
 ) order by t.schema,t.relname,r.rolname) from relations t cross join principals r),'[]'::jsonb),
 'definers',coalesce((select jsonb_agg(jsonb_build_object(
   'schema',n.nspname,'name',p.proname,'arguments',pg_get_function_identity_arguments(p.oid),
   'owner',o.rolname,'bypass',o.rolbypassrls,'superuser',o.rolsuper,
   'callers',coalesce((select jsonb_agg(r.rolname order by r.rolname) from principals r
     where r.rolname in ('anon','authenticated','service_role') and has_schema_privilege(r.oid,n.oid,'USAGE') and has_function_privilege(r.oid,p.oid,'EXECUTE')),'[]'::jsonb),
   'relations',coalesce((select jsonb_agg(jsonb_build_object('schema',t.schema,'name',t.relname,
     'rls',t.relrowsecurity,'forced',t.relforcerowsecurity,'ownerAccess',pg_has_role(o.oid,t.relowner,'USAGE')) order by t.schema,t.relname)
     from relations t where exists (select 1 from pg_depend d where d.classid='pg_proc'::regclass
       and d.objid=p.oid and d.refclassid='pg_class'::regclass and d.refobjid=t.oid)),'[]'::jsonb)
 ) order by n.nspname,p.proname,p.oid) from pg_proc p join pg_namespace n on n.oid=p.pronamespace join pg_roles o on o.oid=p.proowner
 where p.prosecdef and p.prokind='f' and n.nspname !~ '^pg_' and n.nspname<>'information_schema'),'[]'::jsonb)
) as authorization;`;

function record(value: unknown): value is Record<string, unknown> { return Boolean(value) && typeof value === "object" && !Array.isArray(value); }
const strings = (value: unknown): value is string[] => Array.isArray(value) && value.every((v) => typeof v === "string");
function fields(value: unknown, text: string[], flags: string[]): value is Record<string, unknown> {
  return record(value) && text.every((k) => typeof value[k] === "string") && flags.every((k) => typeof value[k] === "boolean");
}
function validAccess(row: unknown): row is Access {
  return fields(row, ["schema", "name", "role", "owner"], ["rls", "forced", "ownerAccess", "bypass", "superuser", "schemaUsage", "truncate", "references"])
    && fields(row.grants, [], [...COMMANDS])
    && Array.isArray(row.columns) && row.columns.every((c) => fields(c, ["name"], ["select", "insert", "update"]))
    && Array.isArray(row.policies) && row.policies.every((p) => fields(p, ["name", "command"], ["permissive"])
      && ["r", "a", "w", "d", "*"].includes(p.command as string)
      && (p.using === null || typeof p.using === "string") && (p.check === null || typeof p.check === "string"));
}
function validDefiner(row: unknown): row is Definer {
  return fields(row, ["schema", "name", "arguments", "owner"], ["bypass", "superuser"])
    && strings(row.callers) && Array.isArray(row.relations)
    && row.relations.every((t) => fields(t, ["schema", "name"], ["rls", "forced", "ownerAccess"]));
}

type Truth = "all" | "none" | "conditional";
function literal(expression: string | null): Truth {
  if (expression === null) return "all";
  const text = expression.trim();
  return text === "true" ? "all" : text === "false" ? "none" : "conditional";
}
function policyGate(policies: Policy[], check: boolean): Truth {
  const permitted = policies.filter((p) => p.permissive).map((p) => literal(check ? p.check ?? p.using : p.using));
  const restricted = policies.filter((p) => !p.permissive).map((p) => literal(check ? p.check ?? p.using : p.using));
  if (!permitted.length || permitted.every((v) => v === "none") || restricted.includes("none")) return "none";
  return permitted.includes("all") && restricted.every((v) => v === "all") ? "all" : "conditional";
}
function commandAccess(row: Access, command: Command): { state: Truth; reason: string } {
  const columns = command === "DELETE" ? [] : row.columns.filter((c) => c[command.toLowerCase() as "select" | "insert" | "update"]).map((c) => c.name);
  if (!row.schemaUsage) return { state: "none", reason: "no schema USAGE" };
  if (!row.grants[command] && !columns.length) return { state: "none", reason: "no effective table or column grant" };
  const grant = row.grants[command] ? "table grant" : `column grant (${columns.join(", ")})`;
  if (!row.rls || row.superuser || row.bypass || (row.ownerAccess && !row.forced)) {
    const reason = !row.rls ? "RLS disabled" : row.superuser ? "effective role is superuser" : row.bypass ? "effective role has BYPASSRLS" : "effective owner; FORCE RLS disabled";
    return { state: "all", reason: `${grant}; ${reason}` };
  }
  const code = { SELECT: "r", INSERT: "a", UPDATE: "w", DELETE: "d" }[command];
  const policies = row.policies.filter((p) => p.command === "*" || p.command === code);
  const using = policyGate(policies, false);
  const check = policyGate(policies, true);
  const state = command === "INSERT" ? check : command !== "UPDATE" ? using
    : using === "none" || check === "none" ? "none" : using === "all" && check === "all" ? "all" : "conditional";
  const reason = !policies.some((p) => p.permissive) ? "RLS deny-by-default: no applicable permissive policy"
    : state === "none" ? "RLS policy composition denies rows" : state === "all" ? "applicable permissive/restrictive policy composition is unconditional"
      : "applicable row predicates require review; no caller-isolation proof inferred";
  return { state, reason: `${grant}; ${reason}; policies=${policies.map((p) => p.name).join(",") || "none"}` };
}

function tableAssessment(rows: Access[], exposedSchemas?: readonly string[]): { table: TableAuthorization; finding: Finding } {
  const { schema, name, owner, rls, forced } = rows[0]!;
  const qualified = `${identifier(schema)}.${identifier(name)}`;
  const explanations: string[] = [];
  let exposure = false;
  let uncertain = false;
  for (const row of rows) {
    const results = COMMANDS.map((command) => {
      const access = commandAccess(row, command);
      return command !== "SELECT" && access.state === "all"
        ? { command, state: "conditional" as const, reason: `${access.reason}; write feasibility, additional SELECT requirements, constraints and triggers require review` }
        : { command, ...access };
    });
    // SELECT establishes a direct row-read path. Write commands may additionally need
    // SELECT policies, constraints or trigger context; keep those as review evidence.
    const read = results[0]!;
    const client = row.role === "anon" || row.role === "authenticated";
    if (client && read.state === "all" && exposedSchemas?.includes(schema)) exposure = true;
    if (results.some((r) => r.state === "conditional") || (client && read.state === "all" && exposedSchemas === undefined)) uncertain = true;
    explanations.push(`${row.role}: ${results.map((r) => `${r.command}=${r.state} (${r.reason})`).join("; ")}.`
      + (row.truncate || row.references ? ` Whole-table privileges: ${[row.truncate ? "TRUNCATE" : "", row.references ? "REFERENCES" : ""].filter(Boolean).join(", ")}; not row-policy-governed, but no API/SQL invocation path is inferred.` : ""));
  }
  const detail = `owner=${owner}; RLS=${rls}; FORCE=${forced}. ${explanations.join(" ")} `
    + (exposedSchemas === undefined ? "API schema reachability was not established." : `API-exposed schema=${exposedSchemas.includes(schema)}.`)
    + " service_role is a separate privileged server principal; these facts do not show its credential is available to a client.";
  const columns = rows[0]!.columns.map((column) => ({ name: column.name, principals: rows
    .filter((row) => row.role === "anon" || row.role === "authenticated")
    .map((row) => {
      const read = commandAccess(row, "SELECT");
      const granted = row.grants.SELECT || row.columns.some((entry) => entry.name === column.name && entry.select);
      return { role: row.role, read: granted ? read.state : "none" as const,
        reason: granted ? read.reason : "no effective SELECT grant on this column" };
    }) }));
  const table = { schema, name, detail, exposure, columns };
  return { table, finding: mechanicalFinding({
    id: `SB-AUTHZ-${identity(schema)}-${identity(name)}`, location: qualified,
    title: exposure ? `Client role can read ${qualified} without a row restriction` : `Effective authorization inventory for ${qualified}`,
    severity: exposure ? "High" : "Info", category: "Supabase config", taxonomy: "Effective database authorization",
    evidence: detail, precisionTier: exposure ? "high" : "review",
    impact: exposure ? "A current client principal has schema usage, a current SELECT grant and an unrestricted row path in an exposed API schema. Whether the data is intended to be public still requires review."
      : uncertain ? "Conditional policies or missing API context retain review. No exposure or tenant-isolation clearance is inferred from grants alone."
        : "This records current direct-role authorization. Deny-by-default is not exposure; definer calls and privileged server connections are separate contexts.",
    fix: exposure ? "Confirm that unrestricted reads are intended; otherwise narrow grants or applicable RLS policies."
      : "Review conditional predicates and privileged call paths against the intended authorization model; retain intentional deny-by-default configurations.",
  }) };
}

export async function loadEffectiveAuthorization(query: (sql: string) => Promise<unknown>, exposedSchemas?: readonly string[]): Promise<{ findings: Finding[]; tables: TableAuthorization[] }> {
  try {
    const result = await query(AUTHORIZATION_SQL);
    const data = Array.isArray(result) && result.length === 1 && record(result[0]) ? result[0].authorization : undefined;
    if (!record(data) || data.version !== 1 || !strings(data.roles) || !data.roles.length
      || new Set(data.roles).size !== data.roles.length
      || !Number.isSafeInteger(data.tableCount) || !Number.isSafeInteger(data.definerCount)
      || !Array.isArray(data.tables) || !data.tables.every(validAccess)
      || !Array.isArray(data.definers) || !data.definers.every(validDefiner)) throw new Error("incomplete catalog");
    const roles = data.roles;
    const groups = new Map<string, Access[]>();
    for (const row of data.tables) {
      const key = JSON.stringify([row.schema, row.name]);
      groups.set(key, [...groups.get(key) ?? [], row]);
    }
    if (groups.size !== data.tableCount || data.definers.length !== data.definerCount
      || [...groups.values()].some((rows) => rows.length !== roles.length || new Set(rows.map((r) => r.role)).size !== rows.length
        || rows.some((r) => !roles.includes(r.role) || r.owner !== rows[0]!.owner || r.rls !== rows[0]!.rls || r.forced !== rows[0]!.forced
          || new Set(r.columns.map((c) => c.name)).size !== r.columns.length
          || JSON.stringify(r.columns.map((c) => c.name).sort()) !== JSON.stringify(rows[0]!.columns.map((c) => c.name).sort())))) throw new Error("incomplete principal matrix");
    const assessed = [...groups.values()].map((rows) => tableAssessment(rows, exposedSchemas));
    const findings = assessed.map((entry) => entry.finding);
    for (const fn of data.definers) {
      if (!fn.callers.length) continue;
      const ownerContext = fn.relations.map((t) => {
        const row = groups.get(JSON.stringify([t.schema, t.name]))?.find((r) => r.role === fn.owner);
        const access = row ? commandAccess(row, "SELECT") : undefined;
        return `${t.schema}.${t.name}: SELECT=${access?.state ?? "unproved"} (${access?.reason ?? "owner grant/policy metadata absent"}; RLS=${t.rls}, FORCE=${t.forced}, ownerAccess=${t.ownerAccess})`;
      });
      findings.push(mechanicalFinding({
        id: `SB-AUTHZ-DEFINER-${identity(fn.schema)}-${identity(fn.name)}-${identity(fn.arguments)}`, location: `${identifier(fn.schema)}.${identifier(fn.name)}(${fn.arguments})`,
        title: `Review effective owner context of ${fn.schema}.${fn.name}`, severity: "Info", category: "Supabase config",
        taxonomy: "SECURITY DEFINER effective authorization context", precisionTier: "review",
        evidence: `EXECUTE plus schema USAGE: ${fn.callers.join(", ")}; effective owner=${fn.owner}; superuser=${fn.superuser}; BYPASSRLS=${fn.bypass}. `
          + `Catalog-recorded owner read context: ${ownerContext.join("; ") || "none"}. `
          + "Catalog dependencies are not a complete call graph: string bodies and dynamic SQL may add other objects. Caller restrictions and the function's actual statement behavior remain unproved.",
        impact: "A definer runs in its owner's authorization context. Neither the caller's RLS denial nor EXECUTE alone establishes the function's data exposure or safety.",
        fix: "Review the function body, caller constraints, owner grants and each referenced relation under the effective owner. Test allowed and disallowed callers separately.",
      }));
    }
    findings.push(mechanicalFinding({ id: "SB-AUTHZ-00", title: "Effective authorization catalog assessed", severity: "Info", category: "Coverage",
      taxonomy: "Coverage — effective database authorization", location: "(database authorization)", precisionTier: "review",
      evidence: `${groups.size} ordinary/partitioned tables; client/service roles and selected definer owners: ${roles.join(", ")}; ${data.tables.length} table/principal combinations; ${data.definers.length} definer functions, ${data.definers.filter((fn) => fn.callers.length).length} callable by a selected client/service role (the remainder lack effective schema/EXECUTE access for these callers). Read-only catalog snapshot. Views, other application roles, dynamic SQL and expression semantics beyond boolean constants require separate review.`,
      impact: "The inventory separates catalog posture from a proved direct client row-read path. Unsupported contexts remain review.",
      fix: "Resolve conditional policy and definer review rows against actual application callers.",
    }));
    return { findings, tables: assessed.map((entry) => entry.table) };
  } catch {
    return { tables: [], findings: [mechanicalFinding({
      id: "SB-AUTHZ-00", title: "Effective database authorization was not assessed", severity: "Info", category: "Coverage",
      taxonomy: "Coverage — effective database authorization", location: "(database authorization)", precisionTier: "review",
      evidence: "The read-only catalog query failed or returned incomplete role/grant/policy/owner metadata. Grants and RLS inventory do not establish exposure or isolation on this run.",
      impact: "Effective authorization remains an explicit review gap; missing metadata must not become an empty or safe authorization result.",
      fix: "Re-run with catalog visibility for the authorized database and review schema/table/column privileges, effective roles, RLS and definer owners together.",
    })] };
  }
}
