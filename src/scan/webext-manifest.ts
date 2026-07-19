// #625 — over-broad WebExtension (browser-extension) manifest permissions. A manifest.json that
// declares a BROAD host pattern (<all_urls>, *://*/*, https://*/*) together with a SENSITIVE
// capability (cookies, webRequest, tabs, history, …) can read the user's session/auth cookies — and
// run content scripts — on EVERY site they visit, not just the one origin the extension needs. The
// ATC apps/extension instance read the Supabase auth cookie for a single user-entered origin while
// declaring host_permissions ["https://*/*"] + "cookies", i.e. session-token read across every site.
//
// Precondition/N-A: an extension is present (a manifest.json with `manifest_version`). Precision:
// review tier — a broad-host + cookies extension is intent-dependent (a password manager legitimately
// needs it), so the combo is surfaced with the specific host/permission evidence, never free-counted.

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import type { Finding } from "../findings.js";
import { mechanicalFinding } from "./common.js";

// A host match pattern that covers effectively every site. Manifest V2 mixes host patterns into the
// `permissions` array; V3 splits them into `host_permissions`. content_scripts[].matches uses the
// same match-pattern grammar. `<all_urls>` and a scheme glob over `*` host are the broad forms.
const BROAD_HOST = /^(<all_urls>|\*|\*:\/\/\*\/?\*?|https?:\/\/\*\/?\*?)$/i;

// Capabilities that, combined with a broad host, expose sensitive cross-site data or control. `cookies`
// is the headline (session/auth-token read); the others grant request interception, tab/history
// enumeration, or debugging across every site.
const SENSITIVE_CAPS = new Set([
  "cookies", "webrequest", "webrequestblocking", "tabs", "history", "webnavigation",
  "clipboardread", "management", "debugger", "proxy", "privacy", "browsingdata",
]);

interface WebExtManifest {
  manifest_version?: number;
  name?: string;
  permissions?: string[];
  optional_permissions?: string[];
  host_permissions?: string[];
  content_scripts?: { matches?: string[] }[];
}

function findManifests(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    if (name === "node_modules" || name === ".next" || name === ".git" || name === "dist") continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) findManifests(p, out);
    else if (name === "manifest.json") out.push(p);
  }
  return out;
}

export function checkWebExtensionManifest(dir: string): Finding[] {
  if (!existsSync(dir)) return [];
  const findings: Finding[] = [];
  for (const file of findManifests(dir)) {
    let m: WebExtManifest;
    try {
      m = JSON.parse(readFileSync(file, "utf8")) as WebExtManifest;
    } catch {
      continue; // not JSON we can read — not a WebExtension manifest
    }
    if (typeof m.manifest_version !== "number") continue; // not a WebExtension manifest (N-A)

    const perms = [...(m.permissions ?? []), ...(m.optional_permissions ?? [])];
    const hostPatterns = [
      ...(m.host_permissions ?? []),
      ...perms, // V2 host patterns live here alongside capability names
      ...(m.content_scripts ?? []).flatMap((cs) => cs.matches ?? []),
    ];
    const broadHosts = [...new Set(hostPatterns.filter((h) => typeof h === "string" && BROAD_HOST.test(h.trim())))];
    const sensitiveCaps = [...new Set(perms.filter((p) => typeof p === "string" && SENSITIVE_CAPS.has(p.toLowerCase())))];
    if (broadHosts.length === 0 || sensitiveCaps.length === 0) continue;

    findings.push(
      mechanicalFinding({
        id: `WEBEXT-OVERBROAD-${relative(dir, file)}`,
        title: `Browser extension ${m.name ?? relative(dir, file)} requests broad host access with a sensitive capability`,
        severity: "High",
        category: "Multi-tenant security",
        taxonomy: "Over-broad WebExtension permissions",
        location: relative(dir, file),
        evidence: `manifest.json (v${m.manifest_version}) declares broad host access (${broadHosts.join(", ")}) together with the sensitive capability(ies) ${sensitiveCaps.join(", ")}. With a broad host + cookies, the extension can read auth/session cookies on EVERY site the user visits, not only the origin it needs.`,
        impact: "A broad host pattern plus cookies/webRequest/tabs lets the extension read session tokens, intercept requests, or enumerate tabs/history across all of the user's browsing — far beyond the single origin it operates on. If the extension (or an update) is compromised, every site's session is exposed.",
        fix: "Scope host_permissions/content_scripts.matches to the specific origin(s) the extension needs (e.g. https://app.example.com/*), and request only the capabilities that origin requires. Use activeTab / optional_permissions requested at runtime instead of a broad standing grant.",
        precisionTier: "review",
        bftb: { value: 4, ease: 4, safety: 4 },
      }),
    );
  }
  return findings;
}
