import { describe, expect, it } from "vitest";
import { classifyDefinerFunction, definerFindings, type DefinerFunction } from "./definer-classifier.js";

// Fixtures modeled on the ATC calibration case referenced in the issue and
// docs/example-report-atc.md F-02: auth_user_in_tenant/auth_user_can_access_conversation
// cleared caller-scoped, tenant_is_active flagged as arbitrary-ID exposure.

const callerScoped: DefinerFunction = {
  schema: "public",
  name: "get_my_conversations",
  argNames: [],
  exposedTo: ["anon", "authenticated"],
  body: "SELECT * FROM conversations WHERE user_id = auth.uid();",
};

const paramOnly: DefinerFunction = {
  schema: "public",
  name: "tenant_is_active",
  argNames: ["target_tenant_id"],
  exposedTo: ["authenticated"],
  body: "SELECT active FROM tenants WHERE id = target_tenant_id;",
};

const dynamicSql: DefinerFunction = {
  schema: "public",
  name: "admin_report",
  argNames: ["target_org_id"],
  exposedTo: ["authenticated"],
  body: "BEGIN RETURN QUERY EXECUTE format('SELECT * FROM %I WHERE org_id = $1', 'org_stats') USING target_org_id; END;",
};

describe("classifyDefinerFunction", () => {
  it("clears a function that constrains its query by auth.uid()", () => {
    const v = classifyDefinerFunction(callerScoped);
    expect(v.verdict).toBe("ok");
    expect(v.function).toBe("public.get_my_conversations");
  });

  it("flags a function that filters only by an id parameter with no caller check", () => {
    const v = classifyDefinerFunction(paramOnly);
    expect(v.verdict).toBe("flag");
    expect(v.reason).toContain("target_tenant_id");
    expect(v.reason).toContain("arbitrary IDs");
  });

  it("marks dynamic-SQL bodies ambiguous rather than guessing from the id parameter", () => {
    const v = classifyDefinerFunction(dynamicSql);
    expect(v.verdict).toBe("ambiguous");
    expect(v.reason).toContain("dynamic SQL");
  });

  it("marks a body with neither an id parameter nor an auth reference ambiguous, not OK", () => {
    const v = classifyDefinerFunction({
      schema: "public",
      name: "recent_signup_count",
      argNames: [],
      exposedTo: ["anon"],
      body: "SELECT count(*) FROM signups WHERE created_at > now() - interval '1 day';",
    });
    expect(v.verdict).toBe("ambiguous");
  });

  it("clears functions not granted to anon/authenticated without inspecting the body", () => {
    const v = classifyDefinerFunction({ ...paramOnly, exposedTo: ["service_role"] });
    expect(v.verdict).toBe("ok");
    expect(v.exposedTo).toEqual([]);
  });

  it("reports only the specific flagged function, not a blanket verdict across all functions", () => {
    const verdicts = [callerScoped, paramOnly, dynamicSql].map(classifyDefinerFunction);
    const flagged = verdicts.filter((v) => v.verdict === "flag");
    expect(flagged.map((v) => v.function)).toEqual(["public.tenant_is_active"]);
  });
});

describe("definerFindings", () => {
  it("emits a Finding only for flagged functions, naming the function in the location", () => {
    const verdicts = [callerScoped, paramOnly, dynamicSql].map(classifyDefinerFunction);
    const findings = definerFindings(verdicts);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.location).toBe("public.tenant_is_active");
    expect(findings[0]?.severity).toBe("High");
  });
});
