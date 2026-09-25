import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Page, Route } from "playwright";
import { startSite } from "./site-browser-harness.js";

let site: Awaited<ReturnType<typeof startSite>>;
beforeAll(async () => { site = await startSite(); });
afterAll(async () => { await site?.stop(); });

const target = "https://owned-project.example.invalid";
const anon = "owned-anon-key";
const secretRow = { id: "private-row-id", secret: "private-row-content" };
interface Seen { url: string; method: string; headers: Record<string, string>; body: string | null }
async function pageWithTransport(handler?: (route: Route) => Promise<void>) {
  const context = await site.browser.newContext();
  const seen: Seen[] = [];
  await context.route("**/*", async route => {
    const request = route.request();
    if (request.resourceType() === "fetch" || request.resourceType() === "xhr") {
      seen.push({ url: request.url(), method: request.method(), headers: await request.allHeaders(), body: request.postData() });
    }
    if (request.url().startsWith(target) || new URL(request.url()).pathname === "/api/scan") {
      if (handler) return handler(route);
    }
    if (new URL(request.url()).origin === site.origin) return route.continue();
    return route.abort();
  });
  return { context, page: await context.newPage(), seen };
}
async function checker(page: Page, cross = false) {
  await page.goto(`${site.origin}/supabase-security-checker`);
  await page.locator("#url").fill(target);
  await page.locator("#key").fill(anon);
  if (cross) {
    await page.locator("details summary").click();
    for (const [id, value] of Object.entries({ ea: "tenant-a@example.invalid", pa: "owned-password-a", eb: "tenant-b@example.invalid", pb: "owned-password-b" })) await page.locator(`#${id}`).fill(value);
  }
  await page.getByRole("button", { name: "Check my RLS" }).click();
}
function respond(route: Route, status: number, value: unknown) {
  return route.fulfill({ status, contentType: "application/json", body: JSON.stringify(value) });
}
const definition = { required: ["name"], properties: { name: { type: "string" } } };
async function healthy(route: Route) {
  const url = new URL(route.request().url());
  if (url.pathname === "/rest/v1/") return respond(route, 200, { definitions: { private_table: definition }, paths: {} });
  if (url.pathname === "/auth/v1/token") return respond(route, 200, { access_token: route.request().postDataJSON().email.startsWith("tenant-a") ? "owned-token-a" : "owned-token-b" });
  if (url.pathname === "/storage/v1/bucket") return respond(route, 403, {});
  if (route.request().method() === "POST") return respond(route, 403, { code: "42501" });
  return respond(route, 200, [secretRow]);
}

describe("shipping browser form journeys", () => {
  it.each([
    { path: "/", input: "email", button: "Run the free scan", success: "Request received.", payload: { email: "lead@example.invalid", repo: "https://repo.example.invalid/owned", context: "owned fixture" } },
    { path: "/sample-report", input: "pdf-email", button: "Email me the PDF", success: "Sent — check your inbox for the PDF.", payload: { kind: "sample-report-pdf", email: "lead@example.invalid" } },
  ])("submits $path exact payload, rejects invalid input and retries failures", async testCase => {
    let pending: Route | undefined;
    const { context, page, seen } = await pageWithTransport(async route => { pending = route; });
    try {
      await page.goto(`${site.origin}${testCase.path}`);
      await page.locator(`#${testCase.input}`).fill("invalid-email");
      await page.getByRole("button", { name: testCase.button }).click();
      expect(seen.filter(row => row.url.endsWith("/api/scan"))).toHaveLength(0);
      await page.locator(`#${testCase.input}`).fill(testCase.payload.email);
      if (testCase.path === "/") {
        await page.locator("#repo").fill(testCase.payload.repo!);
        await page.locator("#context").fill(testCase.payload.context!);
      }
      for (const outcome of [429, 502, "network", 200] as const) {
        pending = undefined;
        await page.getByRole("button", { name: testCase.button }).click();
        await expect.poll(() => Boolean(pending)).toBe(true);
        expect(await page.getByRole("button", { name: "Sending…" }).isDisabled()).toBe(true);
        expect(await page.getByText(testCase.success, { exact: true }).count()).toBe(0);
        expect(JSON.parse(pending!.request().postData()!)).toEqual(testCase.payload);
        if (outcome === "network") await pending!.abort();
        else await respond(pending!, outcome, outcome === 200 ? { ok: true } : { error: `owned failure ${outcome}` });
        if (outcome !== 200) {
          await page.locator(".form-err").waitFor();
          expect(await page.locator(".form-err").textContent()).toContain(outcome === "network" ? "Network error" : `owned failure ${outcome}`);
          expect(await page.getByRole("button", { name: testCase.button }).isEnabled()).toBe(true);
        }
      }
      await page.getByText(testCase.success, { exact: true }).waitFor();
      expect(seen.filter(row => row.url.endsWith("/api/scan"))).toHaveLength(4);
    } finally { await context.close(); }
  });

  it("keeps checker identities on the target and sends only an opt-in coarse lead", async () => {
    let pending: Route | undefined;
    const { context, page, seen } = await pageWithTransport(async route => {
      if (new URL(route.request().url()).pathname === "/api/scan") { pending = route; return; }
      return healthy(route);
    });
    try {
      await checker(page, true);
      await page.locator(".tool-result").waitFor();
      const requests = seen.filter(row => row.url.startsWith(target));
      expect(requests.length).toBeGreaterThan(6);
      expect(requests.every(row => row.headers.apikey === anon)).toBe(true);
      expect(requests.filter(row => row.url.includes("/auth/v1/token")).map(row => [row.method, JSON.parse(row.body!)])).toEqual([
        ["POST", { email: "tenant-a@example.invalid", password: "owned-password-a" }],
        ["POST", { email: "tenant-b@example.invalid", password: "owned-password-b" }],
      ]);
      expect(requests.filter(row => row.url.includes("limit=50")).map(row => row.headers.authorization)).toEqual(["Bearer owned-token-a", "Bearer owned-token-b"]);
      expect(requests.filter(row => row.method === "POST" && row.url.includes("/rest/")).every(row => row.body === "{}")).toBe(true);
      expect(seen.filter(row => row.url.endsWith("/api/scan"))).toHaveLength(0);
      await page.locator("#lead-email").fill("lead@example.invalid");
      for (const outcome of [429, 502, "network", 200] as const) {
        pending = undefined;
        await page.getByRole("button", { name: "Send my email to Harvey" }).click();
        await expect.poll(() => Boolean(pending)).toBe(true);
        expect(await page.getByRole("button", { name: "Sending…" }).isDisabled()).toBe(true);
        const payload = pending!.request().postDataJSON();
        expect(Object.keys(payload).sort()).toEqual(["email", "kind", "summary"]);
        expect(payload).toEqual({ kind: "checker-lead", email: "lead@example.invalid", summary: "1 table publicly readable of 1 total; 1 cross-tenant finding" });
        for (const value of [target, anon, "owned-password", "owned-token", "tenant-a@", "tenant-b@", "private_table", secretRow.id, secretRow.secret]) expect(JSON.stringify(payload)).not.toContain(value);
        if (outcome === "network") await pending!.abort();
        else await respond(pending!, outcome, outcome === 200 ? { ok: true } : { error: `owned failure ${outcome}` });
        if (outcome !== 200) {
          await page.locator(".tool-result .tool-err").waitFor();
          expect(await page.locator(".tool-result .tool-err").textContent()).toContain(outcome === "network" ? "Network error" : `owned failure ${outcome}`);
        }
      }
      await page.getByText(/Thanks — we've got it/).waitFor();
    } finally { await context.close(); }
  });

  it.each(["http", "malformed", "object", "network", "empty"] as const)("discloses %s probe results instead of a reassuring clean result", async mode => {
    const { context, page } = await pageWithTransport(async route => {
      const path = new URL(route.request().url()).pathname;
      if (path === "/rest/v1/" || path === "/auth/v1/token") return healthy(route);
      if (mode === "network") return route.abort();
      if (mode === "malformed") return route.fulfill({ status: 200, contentType: "application/json", body: "not-json" });
      if (mode === "object") return respond(route, 200, { error: "not a collection" });
      return respond(route, mode === "http" ? 503 : 200, []);
    });
    try {
      await checker(page, true);
      await page.locator(".tool-result").waitFor();
      const text = await page.locator(".tool-result").innerText();
      expect(text).not.toContain("good sign");
      expect(text).not.toContain("Writes appear locked");
      expect(text).not.toContain("Buckets not enumerable");
      expect(text).toMatch(/inconclusive|not assessed/i);
      if (mode === "empty") expect(text).not.toContain("Nothing was saved");
    } finally { await context.close(); }
  });

  it.each(["http", "malformed", "network"] as const)("surfaces REST discovery %s failure without displaying results or sending a lead", async mode => {
    let pending: Route | undefined;
    const { context, page, seen } = await pageWithTransport(async route => { pending = route; });
    try {
      await checker(page);
      await expect.poll(() => Boolean(pending)).toBe(true);
      expect(await page.getByRole("button", { name: "Checking…" }).isDisabled()).toBe(true);
      if (mode === "network") await pending!.abort();
      else if (mode === "malformed") await pending!.fulfill({ status: 200, body: "not-json" });
      else await respond(pending!, 503, {});
      await page.locator(".tool-err").waitFor();
      expect(await page.locator(".tool-result").count()).toBe(0);
      expect(seen).toHaveLength(1);
      expect(seen[0]).toMatchObject({ url: `${target}/rest/v1/`, method: "GET", headers: { apikey: anon, authorization: `Bearer ${anon}` } });
    } finally { await context.close(); }
  });

  it("keeps successful sibling probes when another table fails", async () => {
    const { context, page } = await pageWithTransport(async route => {
      const url = new URL(route.request().url());
      if (url.pathname === "/rest/v1/") return respond(route, 200, { definitions: { failed_table: definition, private_table: definition } });
      if (url.pathname.includes("failed_table")) return respond(route, 503, {});
      return healthy(route);
    });
    try {
      await checker(page, true);
      await page.locator(".tool-result").waitFor();
      const text = await page.locator(".tool-result").innerText();
      expect(text).toMatch(/Publicly readable/i);
      expect(text).toContain("Cross-tenant read");
      expect(text).toMatch(/Cross-tenant check inconclusive/i);
      expect(text).toMatch(/Write check inconclusive/i);
      expect(text).toContain("failed_table");
      expect(text).toContain("private_table");
    } finally { await context.close(); }
  });

  it("blocks invalid checker inputs before any project request", async () => {
    const { context, page, seen } = await pageWithTransport(healthy);
    try {
      await page.goto(`${site.origin}/supabase-security-checker`);
      for (const [url, key] of [["http://owned.example.invalid", anon], [target, ""], [target, `x.${Buffer.from('{"role":"service_role"}').toString("base64")}.x`]]) {
        await page.locator("#url").fill(url!); await page.locator("#key").fill(key!);
        await page.getByRole("button", { name: "Check my RLS" }).click();
        await page.locator(".tool-err").waitFor();
      }
      expect(seen).toHaveLength(0);
    } finally { await context.close(); }
  });
});

describe("shipping PDF requester delivery", () => {
  let identity = 0;
  it.each(["healthy", "requester-rejected", "requester-network", "operator-rejected", "operator-network"] as const)("binds HTTP success to required PDF delivery: %s", async mode => {
    site.setMailMode(mode === "healthy" ? {} : { [mode.startsWith("requester") ? "requester" : "operator"]: mode.endsWith("network") ? "network" : 502 });
    const response = await fetch(`${site.origin}/api/scan`, { method: "POST", headers: { "Content-Type": "application/json", "x-forwarded-for": `192.0.2.${++identity}` }, body: JSON.stringify({ kind: "sample-report-pdf", email: "reader@example.invalid" }) });
    expect(response.ok).toBe(!mode.startsWith("requester"));
    const mail = site.mail();
    expect(mail).toHaveLength(mode.startsWith("requester") ? 1 : 2);
    expect(mail[0]!.url).toBe("https://api.resend.com/emails");
    expect(mail[0]!.method).toBe("POST");
    expect(mail[0]!.headers.authorization).toBe("Bearer owned-fake-mail-key");
    expect(mail[0]!.body.to).toEqual(["reader@example.invalid"]);
    expect(mail[0]!.body.attachments).toHaveLength(1);
    expect(mail[0]!.body.attachments![0]!.filename).toBe("harvey-sample-report.pdf");
    expect(Buffer.from(mail[0]!.body.attachments![0]!.content, "base64").equals(site.pdf)).toBe(true);
    if (response.ok) expect(await response.json()).toEqual({ ok: true });
  });

  it("shows real requester failure then succeeds on retry through the browser, API and attachment transport", async () => {
    const { context, page } = await pageWithTransport();
    try {
      site.setMailMode({ requester: 502 });
      await page.goto(`${site.origin}/sample-report`);
      await page.locator("#pdf-email").fill("journey@example.invalid");
      await page.getByRole("button", { name: "Email me the PDF" }).click();
      await page.locator(".form-err").waitFor();
      expect(await page.getByText("Sent — check your inbox for the PDF.", { exact: true }).count()).toBe(0);
      expect(site.mail()).toHaveLength(1);
      site.setMailMode({ operator: 502 });
      await page.getByRole("button", { name: "Email me the PDF" }).click();
      await page.getByText("Sent — check your inbox for the PDF.", { exact: true }).waitFor();
      const mail = site.mail();
      expect(mail).toHaveLength(2);
      expect(mail[0]!.body.to).toEqual(["journey@example.invalid"]);
      expect(Buffer.from(mail[0]!.body.attachments![0]!.content, "base64").equals(site.pdf)).toBe(true);
    } finally { await context.close(); }
  });
});
