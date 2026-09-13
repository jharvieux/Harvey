import { posix } from "node:path";
import ts from "typescript";
import { parseRecordedReasons } from "./recorded-reasons.js";
import { censusLocation, type CensusFile, type CensusSnapshot } from "./environment-dependency-census-discovery.js";
import { censusDigest, ENVIRONMENT_CLASSES, type CensusReconciliation, type EnvironmentClass, type EnvironmentDependencyRow, type EvidenceLocation, type EvidenceVenue } from "./environment-dependency-census-schema.js";

type Fields = Record<string, unknown>;
const object = (v: unknown): Fields => v && typeof v === "object" && !Array.isArray(v) ? v as Fields : {};
const string = (v: unknown): string | null => typeof v === "string" && v.trim() ? v : null;
const isoDate = (v: unknown): string | null => typeof v === "string" && /^\d{4}-\d{2}-\d{2}(?:T.*)?$/.test(v) && Number.isFinite(Date.parse(v)) ? v : null;
const dateIn = (v: string): string | null => isoDate(v.match(/\b\d{4}-\d{2}-\d{2}\b/)?.[0]);
const unknownFreshness = () => ({ requirement: "No enforceable freshness requirement resolved from this evidence. Revalidation remains with the named owner.", observedAt: null, expiresAt: null, enforcedBy: null });

const CLASS_HINTS: [EnvironmentClass, RegExp][] = [
  ["tool", /\b(?:semgrep|gitleaks|trufflehog|osv.scanner|stryker|lighthouse|jscpd|knip|vitals|git version|jq version|pipx)\b/i],
  ["runtime", /\b(?:node(?:js)?|python[23]?|deno|bun|chrom(?:e|ium)|runtimeVersion)\b/i],
  ["package-manager", /\b(?:npm|pnpm|yarn|packageManager|lockfile)\b/i],
  ["database", /\b(?:postgres(?:ql)?|postgrest|gotrue|supabase|mysql|sqlite|redis|databaseVersion)\b/i],
  ["runner-image", /(?:runs-on|ImageVersion|ImageOS|ubuntu-latest|macos-\d|runnerImage|Darwin|linux\/x64)/i],
  ["shell", /\b(?:bash|zsh|pipefail|SHELL|shellVersion)\b|\/bin\/sh\b/],
  ["locale", /\b(?:LC_ALL|LC_COLLATE|LANG|locale|TZ|timezone)\b/],
  ["clock", /\b(?:expiresAt|capturedAt|recordedOn|measuredAt|generatedAt|freshness|Date\.now|setSystemTime|system clock)\b/],
  ["mutable-data", /\b(?:osv\.dev|advisory|advisories|registry\.npmjs|mutable|network|live.only|live-only|live API)\b/i],
  ["source-revision", /\b(?:targetCommit|sourceCommit|targetTree|commitSha|pinned revision|source revision)\b/i],
  ["hardware", /\b(?:cpuModel|hardwareIdentity|processor model|CPU model|memory model|GPU model)\b/i],
];

function literal(node: ts.Expression | undefined): unknown {
  if (!node) return undefined;
  if (ts.isAsExpression(node) || ts.isSatisfiesExpression(node) || ts.isParenthesizedExpression(node)) return literal(node.expression);
  if (ts.isStringLiteralLike(node)) return node.text;
  if (ts.isNumericLiteral(node)) return Number(node.text);
  if (node.kind === ts.SyntaxKind.TrueKeyword) return true;
  if (node.kind === ts.SyntaxKind.FalseKeyword) return false;
  if (ts.isObjectLiteralExpression(node)) return Object.fromEntries(node.properties.filter(ts.isPropertyAssignment).map((p) => [p.name.getText().replace(/^["']|["']$/g, ""), literal(p.initializer)]));
  if (ts.isArrayLiteralExpression(node)) return node.elements.map((n) => ts.isSpreadElement(n) ? { expression: n.getText() } : literal(n));
  return { expression: node.getText() };
}

function sourceObjects(file: CensusFile): { node: ts.ObjectLiteralExpression; value: Fields }[] {
  const out: { node: ts.ObjectLiteralExpression; value: Fields }[] = [];
  if (!file.source) return out;
  const visit = (node: ts.Node): void => { if (ts.isObjectLiteralExpression(node)) out.push({ node, value: object(literal(node)) }); ts.forEachChild(node, visit); };
  visit(file.source);
  return out;
}

function variableValue(file: CensusFile, name: string): unknown {
  let value: unknown;
  const visit = (node: ts.Node): void => { if (ts.isVariableDeclaration(node) && node.name.getText() === name) value = literal(node.initializer); ts.forEachChild(node, visit); };
  if (file.source) visit(file.source);
  return value;
}

interface AdapterContext {
  snapshot: CensusSnapshot; venues: EvidenceVenue[]; rows: EnvironmentDependencyRow[]; reconciliations: CensusReconciliation[];
  files: Map<string, CensusFile>;
}

function reference(ctx: AdapterContext, path: string, anchor: string, needle = anchor): EvidenceLocation {
  const file = ctx.files.get(path);
  if (!file) throw new Error(`environment census adapter lost authoritative source ${path}`);
  if (needle && !(file.text ?? "").includes(needle)) throw new Error(`environment census adapter lost ${path}#${anchor}`);
  if (needle === anchor && file.source) {
    let declaration: ts.Node | undefined;
    const visit = (node: ts.Node): void => {
      if ((ts.isFunctionDeclaration(node) || ts.isVariableDeclaration(node)) && node.name?.getText() === anchor) declaration = node;
      ts.forEachChild(node, visit);
    };
    visit(file.source);
    if (declaration) return { path, anchor, line: file.source.getLineAndCharacterOfPosition(declaration.getStart(file.source)).line + 1 };
  }
  return censusLocation(file, anchor, needle);
}

function row(ctx: AdapterContext, file: CensusFile, key: string, dependencyClass: EnvironmentClass, dependency: string, patch: Partial<EnvironmentDependencyRow> = {}): EnvironmentDependencyRow {
  const value: EnvironmentDependencyRow = {
    id: `${file.path}#${key}:${dependencyClass}:${dependency}`, venue: file.path,
    evidence: censusLocation(file, key),
    consumer: { location: null, resolution: "unresolved", reason: "No authoritative consumer was resolved for this candidate. Presence or a textual reference is not proof of executable consumption." },
    dependencyClass, classification: "authoritative-record", dependency, observedIdentity: null, identitySource: null, pinSource: null, assertionVenue: null,
    freshness: unknownFreshness(), state: "wholly-unbound", resolution: "unresolved",
    owner: "#1906 discovery", schemaOwner: null, environmentOwner: "#1909 stability evidence",
    links: [], reason: "Environment identity, binding, assertion and freshness remain unresolved; this row preserves the candidate instead of treating it as assessed.",
    ...patch,
  };
  ctx.rows.push(value);
  return value;
}

function authoritative(ctx: AdapterContext, file: CensusFile, owner: string): void {
  const venue = ctx.venues.find((v) => v.path === file.path)!;
  venue.disposition = "authoritative-adapter";
  venue.owner = owner;
  venue.reason = "An adapter resolves identified records to their authoritative consumer. The independent unresolved-content row still covers identities and literals outside that adapter's proven scope.";
}

function consumer(location: EvidenceLocation, reason: string): EnvironmentDependencyRow["consumer"] { return { location, resolution: "authoritative", reason }; }

function genericRows(ctx: AdapterContext): void {
  for (const file of ctx.snapshot.files) {
    // Always retain the semantic residual, including files with no vocabulary hit.
    row(ctx, file, "whole-content", "unresolved", "unclassified-content", { classification: "residual-unresolved", reason: file.limitation ?? "A byte-complete candidate, not a claim that this file is measured evidence. Unlabelled numeric/string measurements and environment dependencies cannot be exhaustively classified statically. Regeneration does not accept or bind them." });
    const text = file.text;
    if (!text) continue;
    for (const [kind, hint] of CLASS_HINTS) if (hint.test(text)) row(ctx, file, "content-hint", kind, "unresolved-reference", {
      classification: "vocabulary-candidate",
      evidence: censusLocation(file, "content-hint", text.match(hint)?.[0]),
      reason: "Content mentions this dependency class; comments, fixtures and executable operations may all match. No version or authoritative consumer is inferred from vocabulary alone.",
    });
    // New explicitly declared environment classes cannot be hidden in extensionless data.
    const visited = new Set<unknown>();
    const checkDeclared = (value: unknown): void => {
      if (!value || typeof value !== "object" || visited.has(value)) return;
      visited.add(value);
      const declared = object(value).environmentDependencyClass;
      if (declared !== undefined && !ENVIRONMENT_CLASSES.includes(declared as EnvironmentClass)) throw new Error(`unregistered environment dependency class ${String(declared)} in ${file.path}`);
      for (const child of Object.values(value)) checkDeclared(child);
    };
    checkDeclared(file.data);
    if (file.source && text.includes("environmentDependencyClass")) for (const entry of sourceObjects(file)) checkDeclared(entry.value);
  }
}

function reasonRows(ctx: AdapterContext): void {
  const authority = ctx.files.get("src/recorded-reasons.ts");
  if (!authority) return;
  const parser = reference(ctx, authority.path, "parseRecordedReasons");
  const assertion = reference(ctx, authority.path, "revalidateReasons");
  const members: CensusReconciliation["members"] = [];
  for (const file of ctx.snapshot.files) {
    if (!file.text || !file.text.includes("REASON:")) continue;
    for (const reason of parseRecordedReasons(file.text, file.path)) {
      const f = reason.fields;
      const evidence = { path: file.path, anchor: `REASON@${reason.line}`, line: reason.line };
      const decisional = f.KIND === "decisional";
      const live = f["FALSIFIER-TIER"];
      const text = Object.values(f).join("\n");
      const classes = CLASS_HINTS.filter(([, pattern]) => pattern.test(text)).map(([kind]) => kind);
      if (!classes.length) classes.push("unresolved");
      const ids = classes.map((kind) => row(ctx, file, evidence.anchor, kind, decisional ? "recorded-decision" : live ? `live-tier-${live}` : "empirical-falsifier", {
        evidence, consumer: consumer(parser, "The existing recorded-reason parser supplies the block fields; its usual directory/extension and execution-tier scope is not extended by this census."),
        owner: f.OWNER ?? "src/recorded-reasons.ts reason policy", environmentOwner: f.OWNER ?? "#1909 stability evidence",
        state: decisional && !!f.OWNER && !!f.DECISION ? "accepted" : "wholly-unbound",
        resolution: live || (f.FALSIFIER ?? "").includes("<") ? "dynamic" : "unresolved",
        assertionVenue: f.FALSIFIER ? { location: assertion, scope: "environment-behavior", claim: `Declared falsifier, not executed by the offline census${live ? `; requires ${live}` : ""}: ${f.FALSIFIER}` } : null,
        freshness: { requirement: decisional ? "Operator decision; no empirical revalidation is inferred." : "Revalidate the reason with its declared falsifier in its declared tier. This census records the command, never executes it.", observedAt: dateIn(f.PROVENANCE ?? ""), expiresAt: null, enforcedBy: f.FALSIFIER ? assertion : null },
        links: ["src/cli/validate-reasons.ts", "#1909"],
        reason: `${decisional ? `Decisional reason; explicit owner/decision ${f.OWNER && f.DECISION ? "recorded" : "unresolved"}` : "Empirical reason with environment/tool identities not supplied by the reason format"}. ${f.REASON ?? ""}${reason.parseErrors.length ? ` Parser reports: ${reason.parseErrors.join("; ")}` : ""}`,
      }).id);
      members.push({ key: `${file.path}:${reason.line}`, evidence, rowIds: ids, reason: "Reused parsed reason fields; no new reason or baseline was authored and no live falsifier was run." });
    }
  }
  ctx.reconciliations.push({ registry: authority.path, owner: "src/recorded-reasons.ts", state: "present", members, reason: "All decoded committed files are offered to the existing parser, including venues beyond its normal roots. Parsed blocks remain declarations; parse examples and historical prose are not evidence of current execution." });
}

interface ToolContract { name: string; identity: string; source: CensusFile; constant: string; captures: string[]; cli: string }
function capturedTools(ctx: AdapterContext): void {
  const contracts: ToolContract[] = [];
  const drift = ctx.files.get("src/cli/fixture-drift.ts");
  for (const path of ["src/scan/fixture-drift-contracts.ts", "src/scan/osv-fixture-contract.ts"]) {
    const file = ctx.files.get(path);
    if (!file?.source) continue;
    for (const match of (file.text ?? "").matchAll(/export const ([A-Z_]+)_PINNED_VERSION = "([^"]+)"/g)) {
      const name = match[1]!.toLowerCase().replaceAll("_", "-");
      const constant = `${match[1]}_PINNED_VERSION`;
      const captures: string[] = [];
      if (name === "osv-scanner") {
        const osvCli = ctx.files.get("src/cli/osv-fixture-drift.ts");
        for (const m of (osvCli?.text ?? "").matchAll(/["'](src\/[^"']+\.json)["']/g)) if (ctx.files.has(m[1]!)) captures.push(m[1]!);
        // Older CLI constructs this URL relative to import.meta.url; resolve its actual literal.
        if (!captures.length) for (const f of ctx.snapshot.files) if (f.data && f.path.includes(`/osv-scanner-${match[2]}-`) && (f.text ?? "").includes("results")) captures.push(f.path);
      } else if (drift) {
        for (const { node, value } of sourceObjects(drift)) if (object(value.pinnedVersion).expression === constant) {
          if (Array.isArray(value.fixturePaths)) captures.push(...value.fixturePaths.filter((p): p is string => typeof p === "string"));
          for (const spread of node.properties.filter(ts.isSpreadAssignment)) {
            const name = spread.expression.getText(drift.source);
            const visit = (candidate: ts.Node): void => {
              if (ts.isVariableDeclaration(candidate) && candidate.name.getText() === name) {
                const paths = object(literal(candidate.initializer)).fixturePaths;
                if (Array.isArray(paths)) captures.push(...paths.filter((p): p is string => typeof p === "string"));
              }
              ts.forEachChild(candidate, visit);
            };
            if (file.source) visit(file.source);
          }
        }
      }
      if (!captures.length) throw new Error(`fixture contract ${constant} has no resolved live capture path`);
      for (const capture of captures) if (!ctx.files.has(capture)) throw new Error(`fixture contract ${constant} has an absent capture ${capture}`);
      contracts.push({ name, identity: match[2]!, constant, source: file, captures, cli: name === "osv-scanner" ? "src/cli/osv-fixture-drift.ts" : "src/cli/fixture-drift.ts" });
    }
  }
  if (drift) {
    const names = Object.keys(object(variableValue(drift, "RUNNERS")));
    if (names.some((name) => !contracts.some((c) => c.name === name)) || contracts.filter((c) => c.name !== "osv-scanner").some((c) => !names.includes(c.name))) throw new Error("fixture RUNNERS and pinned contracts do not reconcile");
  }
  const members: CensusReconciliation["members"] = [];
  for (const contract of contracts) {
    const pin = reference(ctx, contract.source.path, contract.constant);
    const assertion = contract.name === "osv-scanner"
      ? reference(ctx, contract.cli, "installed-version-check", "if (version !== OSV_SCANNER_PINNED_VERSION)")
      : reference(ctx, contract.cli, "runDrift/installed-version-check", "if (o.installedVersion !== o.pinnedVersion)");
    for (const path of contract.captures) {
      const file = ctx.files.get(path)!;
      const provenance = ctx.files.get(posix.join(posix.dirname(path), "PROVENANCE.md"));
      const note = string(object(file.data)._note) ?? provenance?.text ?? "";
      const oldVersion = note.match(new RegExp(`${contract.name === "osv-scanner" ? "osv.scanner" : contract.name}[^\\d]{0,30}(\\d+\\.\\d+\\.\\d+)`, "i"))?.[1] ?? null;
      const identity = string(object(file.data).version) ?? string(object(file.data).lighthouseVersion) ?? oldVersion;
      const source = identity === object(file.data).version || identity === object(file.data).lighthouseVersion ? censusLocation(file, "embedded-version", identity ?? undefined) : provenance ? censusLocation(provenance, "capture-provenance", identity ?? undefined) : censusLocation(file, "_note", "_note");
      const value = row(ctx, file, "captured-output", "tool", contract.name, {
        consumer: consumer(assertion, "The live fixture-drift command directly loads this capture and checks its parser contract."),
        observedIdentity: identity, identitySource: identity ? source : null,
        pinSource: { location: pin, identity: contract.identity, scope: "output-schema" },
        assertionVenue: { location: assertion, scope: "output-schema", claim: "Installed version and fresh capture shape are checked. This is not a proof of OS, database, browser, shell or timing equivalence; Semgrep additionally compares its narrowly canonicalized capture." },
        freshness: { requirement: "Re-capture and run the owning drift check when the tool/contract changes; external mutable inputs may change independently.", observedAt: dateIn(note), expiresAt: null, enforcedBy: assertion },
        state: identity === contract.identity ? "pinned" : identity ? "recorded" : "wholly-unbound", resolution: identity ? "identified" : "unresolved",
        owner: "captured fixture integrity (#1130)", schemaOwner: "#1901 captured-output parser contracts", environmentOwner: "#1909 stability evidence",
        links: ["src/scan/__fixtures__/FIXTURE-INVENTORY.md", contract.source.path, contract.cli, "#1901", "#1909"],
        reason: `${identity && identity !== contract.identity ? `Identity disagreement: capture provenance records ${identity}; the active drift pin is ${contract.identity}. Neither is silently substituted for the other. ` : ""}${identity ? "Observed identity comes from committed capture/provenance, not the filename." : "Capture has no resolved observed version; the active pin is retained separately."} Parser-schema ownership and environment-behavior ownership remain separate.`,
      });
      authoritative(ctx, file, value.owner);
      members.push({ key: `${contract.name}:${path}`, evidence: value.evidence, rowIds: [value.id], reason: value.reason });
      // A version pin cannot pin the browser, Git history, live service or advisory DB.
      const extra: [EnvironmentClass, string][] = contract.name === "lighthouse" ? [["runtime", "browser"], ["hardware", "performance-environment"]]
        : contract.name === "vitals" ? [["tool", "git"], ["runtime", "python"], ["database", "vitals-provenance-db"], ["clock", "git-history-clock"]]
          : contract.name === "osv-scanner" ? [["mutable-data", "osv-advisory-database"]]
            : contract.name === "trufflehog" ? [["mutable-data", "live-secret-verification"], ["tool", "git"]] : [["runtime", "tool-host-runtime"]];
      for (const [kind, name] of extra) row(ctx, file, "capture-environment", kind, name, { consumer: value.consumer, owner: value.owner, schemaOwner: value.schemaOwner, environmentOwner: value.environmentOwner, links: [value.id, "#1909"], resolution: kind === "mutable-data" || kind === "clock" ? "dynamic" : "unresolved", reason: "The raw capture and tool schema pin do not bind this environment dependency. A fresh schema pass cannot establish its behavioral equivalence." });
    }
  }
  if (contracts.length) ctx.reconciliations.push({ registry: "fixture-drift contracts + OSV contract", owner: "#1901 output schema; #1909 environment", state: members.some((m) => m.reason.includes("Identity disagreement")) ? "identity-disagreement" : "present", members, reason: "Discovered pinned constants, reconciled the live RUNNERS keys and resolved their actual fixturePaths; the OSV contract retains its separate CLI. No imported executing registry was substituted for immutable source bytes." });

  const inventory = ctx.files.get("src/scan/__fixtures__/FIXTURE-INVENTORY.md");
  if (!inventory?.text) return;
  const inventoryMembers: CensusReconciliation["members"] = [];
  for (const [index, line] of inventory.text.split("\n").entries()) {
    const match = line.match(/^\|\s*(\d+[a-z]?)\s*\|/);
    if (!match) continue;
    const related = contracts.filter((c) => line.toLowerCase().includes(c.name));
    const evidence = { path: inventory.path, anchor: `fixture-row-${match[1]}`, line: index + 1 };
    const embedded = [...line.matchAll(/`(src\/[^`]+)`/g)].map((m) => m[1]!).filter((p) => !p.includes(" "));
    const missing = embedded.filter((p) => !ctx.files.has(p));
    const value = row(ctx, inventory, evidence.anchor, related.length ? "tool" : /PostgREST|Supabase/.test(line) ? "database" : "unresolved", `inventory-${match[1]}`, {
      evidence, owner: "captured fixture integrity (#1130)", schemaOwner: "#1901 captured-output parser contracts",
      links: [...new Set(related.flatMap((c) => c.captures)), ...embedded.filter((p) => ctx.files.has(p)), "#1901", "#1909"].sort(),
      resolution: /live.only|LIVE.STACK|LIVE project/i.test(line) ? "dynamic" : "unresolved",
      reason: `Existing inventory row retained without inventing a current capture or executing a live branch. ${missing.length ? `Historical/unresolved references: ${missing.join(", ")}. ` : ""}${related.length ? `Active pins (separate authority): ${related.map((c) => `${c.name} ${c.identity}`).join(", ")}. ` : ""}${line.replace(/^\|\s*\d+[a-z]?\s*\|/, "").slice(0, 900)}`,
    });
    const additionalIds: string[] = [];
    for (const path of embedded.filter((p) => ctx.files.get(p)?.data && !contracts.some((c) => c.captures.includes(p)))) {
      const capture = ctx.files.get(path)!;
      const tests = embedded.map((p) => ctx.files.get(p)).filter((f): f is CensusFile => !!f?.source && !!f.text?.includes(posix.basename(path)));
      const note = string(object(capture.data)._note) ?? "";
      const tool = related[0];
      const identity = tool ? note.match(new RegExp(`${tool.name}[^\\d]{0,30}(\\d+\\.\\d+\\.\\d+)`, "i"))?.[1] ?? null : null;
      const r = row(ctx, capture, `inventory-capture/${match[1]}`, tool ? "tool" : "database", tool?.name ?? "live-api-capture", {
        consumer: tests[0] ? consumer(censusLocation(tests[0], "capture-read", posix.basename(path)), "The inventory names this test consumer and its source directly names the capture. This does not assert that a live environment was re-created.") : value.consumer,
        observedIdentity: identity, identitySource: identity ? censusLocation(capture, "_note", "_note") : null,
        pinSource: tool ? { location: reference(ctx, tool.source.path, tool.constant), identity: tool.identity, scope: "output-schema" } : null,
        state: identity ? "recorded" : "wholly-unbound", resolution: tool ? identity ? "identified" : "unresolved" : "dynamic",
        owner: value.owner, schemaOwner: tool ? value.schemaOwner : null,
        links: [value.id, inventory.path, ...tests.map((f) => f.path), "#1909"],
        freshness: { requirement: "Frozen vendor/live capture or branch control; a current live body or browser/environment equivalence needs separately retained evidence.", observedAt: dateIn(note || line), expiresAt: null, enforcedBy: null },
        reason: "This capture is in the existing inventory but is not directly loaded by the generic tool drift command. Its actual test reader and optional recorded version are retained; no sibling capture's live assertion is borrowed.",
      });
      authoritative(ctx, capture, r.owner); additionalIds.push(r.id);
    }
    inventoryMembers.push({ key: match[1]!, evidence, rowIds: [value.id, ...additionalIds, ...ctx.rows.filter((r) => r.evidence.anchor === "captured-output" && related.some((c) => c.captures.includes(r.venue))).map((r) => r.id)], reason: value.reason });
  }
  authoritative(ctx, inventory, "captured fixture integrity (#1130)");
  ctx.reconciliations.push({ registry: inventory.path, owner: "captured fixture integrity (#1130)", state: "present", members: inventoryMembers, reason: "Every existing numbered row, including live-only and synthetic inline directions, links to its resolved captures or carries an explicit unresolved reason. Historical prose is not silently promoted to the active version." });
}

function corpusRows(ctx: AdapterContext): void {
  const external = ctx.files.get("src/scan/external-corpus.ts");
  if (external) {
    const scorer = reference(ctx, external.path, "scoreExternalBaseline");
    const members: CensusReconciliation["members"] = [];
    for (const { node, value } of sourceObjects(external)) {
      if (!string(value.slug) || !value.modules) continue;
      const slug = string(value.slug)!;
      const commit = string(value.commit);
      const evidence = censusLocation(external, `EXTERNAL_CORPUS/${slug}`, node.getText(external.source));
      for (const [module, baseline] of Object.entries(object(value.modules))) {
        const b = object(baseline);
        const note = string(b.note) ?? string(b.reason) ?? "";
        const source = row(ctx, external, `${evidence.anchor}/${module}`, "source-revision", `${slug}@${module}`, {
          evidence: { ...evidence, anchor: `${evidence.anchor}/${module}` }, consumer: consumer(scorer, "The production scorer consumes this target's inline module baseline; #1853 owns extraction into a versioned per-target schema."),
          observedIdentity: commit, identitySource: commit ? evidence : null,
          pinSource: commit ? { location: evidence, identity: commit, scope: "environment-behavior" } : null,
          assertionVenue: { location: reference(ctx, "src/cli/corpus-drift.ts", "scoreExternalBaseline"), scope: "environment-behavior", claim: "The drift consumer clones each declared pin and scores per-module output; this offline census does not rerun it." },
          freshness: { requirement: "Remeasure affected module baselines against the same target pin when scanner/toolchain/configuration behavior changes. Historical note dates are not expiry enforcement.", observedAt: dateIn(note), expiresAt: null, enforcedBy: null },
          state: commit && /^[a-f0-9]{40}$/.test(commit) ? "pinned" : commit ? "recorded" : "wholly-unbound", resolution: commit && /^[a-f0-9]{40}$/.test(commit) ? "identified" : "dynamic",
          owner: "#1853 external-corpus baselines", links: ["#1853", "src/cli/corpus-drift.ts", "#1909"],
          reason: string(b.reason) ? `Declared not-assessed module: ${b.reason}. Its falsifier remains owned by the existing corpus/reason registry.` : "A target revision pin is preserved; it does not also pin the historical tool/runtime/database identities behind this measurement.",
        });
        const dependencies: [EnvironmentClass, string][] = [["runtime", "historical-node-runtime"]];
        if (module === "M4") dependencies.push(["tool", "jscpd"]);
        if (module === "M5-knip") dependencies.push(["tool", "knip"], ["package-manager", "target-installation"]);
        if (module === "M8") dependencies.push(["tool", "stryker"], ["package-manager", "target-test-installation"]);
        if (module === "M10") dependencies.push(["database", "schema-dialect"]);
        const related = dependencies.map(([kind, name]) => row(ctx, external, `${evidence.anchor}/${module}`, kind, name, { evidence: source.evidence, consumer: source.consumer, owner: source.owner, freshness: source.freshness, links: [source.id, "#1853", "#1909"], reason: "This inline baseline has no uniform measured toolchain reference. A current package lock or workflow pin is not assigned retroactively to its historical measurement." }).id);
        members.push({ key: `${slug}:${module}`, evidence: source.evidence, rowIds: [source.id, ...related], reason: source.reason });
      }
    }
    authoritative(ctx, external, "#1853 external-corpus baselines");
    ctx.reconciliations.push({ registry: "#1853 external-corpus schema", owner: "#1853", state: "not-present-at-base", members, reason: "At this immutable source the authoritative registry is EXTERNAL_CORPUS and its typed ModuleBaseline/MutationBaseline/ModuleNotRun shapes in src/scan/external-corpus.ts. A schema-versioned per-target loader is not present here; these rows reconcile the real target/module population without fabricating the future schema. #1853 owns migration and #1909 owns shared stability records." });
    for (const { node, value } of sourceObjects(external)) if (value.targetCommit && value.beforeHarveyHead && value.afterHarveyHead) {
      const evidence = censusLocation(external, "count-neutral-semantic-baseline", node.getText(external.source));
      row(ctx, external, evidence.anchor, "source-revision", "before-after-scanner-heads", { evidence, consumer: consumer(reference(ctx, external.path, "scoreGhostfolioM7NestImportChain"), "This scorer checks the count-neutral semantic baseline, independently of aggregate finding counts."), observedIdentity: `${value.beforeHarveyHead} -> ${value.afterHarveyHead}`, identitySource: evidence, state: "recorded", resolution: "identified", owner: "#1853 external-corpus baselines", links: ["#1795", "#1853", "#1909"], reason: "Recorded controlled source revisions and target identity; environment toolchain provenance is not inferred from the before/after heads." });
    }
  }
  const semantic = ctx.files.get("src/scan/semantic-corpus.ts");
  if (semantic) {
    const members: CensusReconciliation["members"] = [];
    for (const { node, value } of sourceObjects(semantic)) if (value.slug && value.recordedCaught !== undefined && value.ref) {
      const evidence = censusLocation(semantic, `SEMANTIC_CORPUS/${value.slug}`, node.getText(semantic.source));
      const valueRow = row(ctx, semantic, evidence.anchor, "source-revision", String(value.slug), {
        evidence, consumer: consumer(reference(ctx, semantic.path, "scoreSemanticPass"), "Semantic recall scorer reads the transcribed per-target answer key."), observedIdentity: `${value.repo}@${value.ref}`, identitySource: evidence, state: "recorded", resolution: "dynamic",
        owner: "src/scan/semantic-corpus.ts semantic answer keys", links: [String(value.source), "src/cli/validate-semantic.ts", "#1909"],
        freshness: { requirement: "recordedCaught is historical. A present pass is scored with the existing MAX_PASS_AGE_MS policy; a branch name is not an immutable source pin.", observedAt: isoDate(value.recordedOn), expiresAt: null, enforcedBy: reference(ctx, semantic.path, "MAX_PASS_AGE_MS") },
        reason: "Retain the recorded branch/ref, measurement date and document link. No current model identity, immutable target commit or environment identity is inferred.",
      });
      const model = row(ctx, semantic, evidence.anchor, "mutable-data", "semantic-model-provider", { evidence, consumer: valueRow.consumer, owner: valueRow.owner, resolution: "dynamic", links: [valueRow.id, "#1909"], reason: "The answer key does not bind an executing model/provider identity. Only separately recorded pass evidence can establish a present semantic run." });
      members.push({ key: String(value.slug), evidence, rowIds: [valueRow.id, model.id], reason: valueRow.reason });
    }
    authoritative(ctx, semantic, "semantic recall answer keys");
    ctx.reconciliations.push({ registry: "SEMANTIC_CORPUS", owner: "src/scan/semantic-corpus.ts", state: "present", members, reason: "Separate semantic target/ref/date population; not merged with external-corpus's pinned module baselines." });
  }
  const calibration = ctx.files.get("src/scan/calibration.ts");
  if (calibration?.source) {
    const members: CensusReconciliation["members"] = [];
    const imports = new Map<string, string>();
    for (const statement of calibration.source.statements) if (ts.isImportDeclaration(statement) && ts.isStringLiteral(statement.moduleSpecifier) && statement.importClause?.namedBindings && ts.isNamedImports(statement.importClause.namedBindings)) {
      const specifier = statement.moduleSpecifier.text;
      const path = posix.normalize(posix.join(posix.dirname(calibration.path), specifier)).replace(/\.js$/, ".ts");
      for (const binding of statement.importClause.namedBindings.elements) imports.set(binding.name.text, path);
    }
    const spreads = (calibration.text ?? "").match(/export const CORPUS[^=]*=\s*\[([\s\S]*?)\n\]/)?.[1] ?? "";
    for (const match of spreads.matchAll(/\.\.\.([A-Za-z\d_]+)/g)) {
      const path = imports.get(match[1]!);
      const file = path ? ctx.files.get(path) : undefined;
      if (!file) throw new Error(`calibration spread ${match[1]} has no resolved source`);
      for (const { node, value } of sourceObjects(file)) if (typeof value.id === "string" && typeof value.kind === "string" && typeof value.location === "string") {
        const evidence = censusLocation(file, `CORPUS/${value.id}`, node.getText(file.source));
        const r = row(ctx, file, evidence.anchor, "unresolved", "calibration-execution-environment", { evidence,
          consumer: consumer(reference(ctx, calibration.path, "CORPUS"), `Imported as ${match[1]} and spread into the scored CORPUS. Source targets are intentional inputs, not raw external-tool output captures.`),
          assertionVenue: { location: reference(ctx, "src/cli/validate-calibration.ts", "CORPUS"), scope: "environment-behavior", claim: "The live calibration CLI scores actual output; unit scoring of recorded output is a separate assertion. This census does not rerun binaries or live tiers." },
          owner: "src/scan/calibration.ts scored answer keys", schemaOwner: "#1901 only for overlapping captured parser inputs", links: ["targets/calibration", "src/scan/calibration.test.ts", "src/cli/validate-calibration.ts", "#1909"],
          freshness: { requirement: "Re-measure each affected planted finding and declared tier through its live consumer when producer behavior changes.", observedAt: dateIn(String(value.note ?? "")), expiresAt: null, enforcedBy: null },
          reason: "The imported scored entry names expectation and scope, but does not uniformly bind measured tool, runtime, database or live-stack identities. These remain unresolved; a source-file digest is not a runtime measurement.",
        });
        members.push({ key: value.id, evidence, rowIds: [r.id], reason: `Resolved ${match[1]} import and actual CORPUS spread.` });
      }
      authoritative(ctx, file, "calibration answer-key registry");
    }
    ctx.reconciliations.push({ registry: "CORPUS imported/spread entries", owner: "src/scan/calibration.ts", state: "present", members, reason: "Source imports and CORPUS spreads determine the scored population. Filename matches alone are not used to assert membership; unmatched files stay visible conservative candidates." });
  }
}

function structuredRows(ctx: AdapterContext): void {
  for (const file of ctx.snapshot.files) {
    const data = object(file.data);
    const targets = object(data.targets);
    if (data.schema === 2 && Object.values(targets).some((v) => object(v).osvScannerVersion && object(v).expiresAt)) {
      const members: CensusReconciliation["members"] = [];
      const location = reference(ctx, "src/corpus-advisory-snapshot.ts", "loadCorpusAdvisorySnapshot");
      for (const [slug, unknown] of Object.entries(targets)) {
        const entry = object(unknown);
        const path = posix.join(posix.dirname(file.path), String(entry.file));
        const payload = ctx.files.get(path);
        if (!payload || censusDigest(payload.bytes) !== entry.sha256) throw new Error(`advisory manifest ${slug} has missing or mismatched payload bytes`);
        const evidence = censusLocation(file, `targets/${slug}`, `"${slug}"`);
        const shared = { evidence, consumer: consumer(location, "The production loader verifies target revision, gzip digest and expiry before corpus regression consumes advisory input."), owner: "src/corpus-advisory-snapshot.ts schema 2", schemaOwner: "#1901 raw OSV parser shape", links: [path, "src/cli/corpus-drift.ts", "#1853", "#1909"], freshness: { requirement: "Valid only between capturedAt and expiresAt for the exact target and payload digest. The loader checks current time; census generation is offline and does not assert it remains fresh now.", observedAt: isoDate(entry.capturedAt), expiresAt: isoDate(entry.expiresAt), enforcedBy: location } };
        const artifact = row(ctx, file, `targets/${slug}`, "mutable-data", "osv-advisory-snapshot", { ...shared, observedIdentity: String(entry.sha256), identitySource: evidence, pinSource: { location: evidence, identity: String(entry.sha256), scope: "artifact-integrity" }, assertionVenue: { location, scope: "artifact-integrity", claim: "Pinned compressed payload digest, exact target and expiry are checked; upstream OSV database remains mutable." }, state: "pinned", resolution: "dynamic", reason: "This binds a time-limited advisory snapshot, not the current live database. Per-target epochs are preserved; a sibling target's refresh cannot refresh this row." });
        const tool = row(ctx, file, `targets/${slug}`, "tool", "osv-scanner-and-scalibr", { ...shared, observedIdentity: String(entry.osvScannerVersion), identitySource: evidence, state: "recorded", resolution: "identified", reason: "Observed capture toolchain string is recorded. The snapshot loader does not assert that current installed scanner/scalibr versions equal the capture version." });
        const clock = row(ctx, file, `targets/${slug}`, "clock", "expiry-clock", { ...shared, resolution: "dynamic", reason: "Current clock determines admissibility. ISO capture/expiry timestamps do not bind the runner's system clock identity." });
        members.push({ key: slug, evidence, rowIds: [artifact.id, tool.id, clock.id], reason: "Reused schema-2 per-target identity, payload link and capture/expiry fields; no target baseline data duplicated." });
      }
      authoritative(ctx, file, "corpus advisory snapshot schema 2");
      ctx.reconciliations.push({ registry: file.path, owner: "src/corpus-advisory-snapshot.ts", state: "present", members, reason: "Current per-target external-corpus advisory provenance is reconciled alongside #1853's still-inline baseline registry." });
    }
    const receipt = data.sourceCommit && data.toolchain && data.reportSha256 ? data : object(object(data.census).receipt);
    if (receipt.sourceCommit && receipt.toolchain && receipt.reportSha256) {
      const location = reference(ctx, "src/guard-mutation-baseline.ts", "compareGuardMutationCensus");
      const toolchain = object(receipt.toolchain);
      const packages = object(toolchain.packages);
      const identities: [EnvironmentClass, string, unknown][] = [["runtime", "node", toolchain.node], ["package-manager", "package-manager", toolchain.packageManager], ...Object.entries(packages).map(([name, v]): [EnvironmentClass, string, unknown] => ["tool", name, object(v).version])];
      for (const [kind, name, identityValue] of identities) {
        const identity = string(identityValue);
        const evidence = censusLocation(file, `guard-receipt/toolchain/${name}`, identity ?? "toolchain");
        const baseline = file.path === "guard-mutation-baseline.json";
        row(ctx, file, evidence.anchor, kind, name, { evidence, consumer: consumer(location, baseline ? "The production comparator reads this root baseline and compares exact current receipt toolchain identities." : "This receipt is a retained test/capture input; its toolchain is historical and is not independently a current live run."), observedIdentity: identity, identitySource: identity ? evidence : null,
          pinSource: baseline && identity ? { location: evidence, identity, scope: "environment-behavior" } : null,
          assertionVenue: { location, scope: "environment-behavior", claim: "The comparator rejects unequal toolchain receipts. This census records that assertion venue without executing Stryker." },
          state: identity ? baseline ? "pinned" : "recorded" : "wholly-unbound", resolution: identity ? "identified" : "unresolved",
          owner: "#1890 guard mutation baseline", links: ["guard-mutation-baseline.json", "src/__fixtures__/guard-mutation/measured.receipt.json", "#1890", "#1891", "#1909"],
          freshness: { requirement: "Revalidate changed guard/config/source/toolchain inputs and expiring review rows with the measured baseline workflow.", observedAt: isoDate(receipt.finishedAt), expiresAt: null, enforcedBy: location }, reason: baseline ? "Exact package/runtime identities are compared by the baseline consumer; collector OS/hardware and clock identities are not inferred from these pins." : "Derived/captured receipt is linked to the baseline owner and never counted as a separate present execution.",
        });
      }
      authoritative(ctx, file, "#1890 guard mutation provenance");
    }
    if (data.schemaVersion === 1 && data.canonicalization && data.retainedDynamic && data.artifacts) {
      const location = reference(ctx, "src/dry-run-artifacts.ts", "validateDryRunFamily");
      const members: CensusReconciliation["members"] = [];
      for (const [name, entry] of Object.entries(object(data.artifacts))) {
        const path = posix.join(posix.dirname(file.path), name);
        const member = ctx.files.get(path);
        if (!member) throw new Error(`generated artifact family lost ${path}`);
        const evidence = censusLocation(file, `artifacts/${name}`, `"${name}"`);
        const r = row(ctx, member, "artifact-family-member", "source-revision", "family-source-and-content", { consumer: consumer(location, "Generated family validator checks member linkage and conservation; members are not independent measurements."), observedIdentity: string(object(entry).sha256), identitySource: evidence, state: "recorded", resolution: "identified", owner: "src/dry-run-artifacts.ts generated family", assertionVenue: { location, scope: "artifact-integrity", claim: "The owner canonicalizes member content and validates its recorded digest and transformations. A content digest is not an environment assertion." }, links: [file.path, "src/cli/dry-run.ts", "#1909"], reason: `Family target tree: ${String(object(data.source).targetTree)}. The family does not retain one complete toolchain/environment identity for its historical production run.` });
        authoritative(ctx, member, r.owner); members.push({ key: name, evidence, rowIds: [r.id], reason: r.reason });
      }
      const retained = object(data.retainedDynamic);
      const document = object(retained.document);
      const r = row(ctx, file, "retainedDynamic", "database", "historical-M2-stack", { consumer: consumer(location, "The generated family deliberately retains this historical dynamic input; regeneration does not rerun that live stack."), observedIdentity: string(retained.sha256), identitySource: censusLocation(file, "retainedDynamic", "retainedDynamic"), state: "recorded", resolution: "dynamic", owner: "src/dry-run-artifacts.ts retained dynamic evidence", freshness: { requirement: "Historical evidence only. A new live M2 run with retained stack and tool identities is required for a present-behavior claim.", observedAt: isoDate(document.generatedAt), expiresAt: null, enforcedBy: null }, links: [file.path, "dry-run/dynamic-scorecard.json", "#1909"], reason: `Retained role ${String(retained.role)} at ${String(document.target)} identifies an artifact, not a versioned database/API/runner environment.` });
      members.push({ key: "retainedDynamic", evidence: r.evidence, rowIds: [r.id], reason: r.reason });
      authoritative(ctx, file, "src/dry-run-artifacts.ts generated family");
      ctx.reconciliations.push({ registry: file.path, owner: "src/dry-run-artifacts.ts", state: "present", members, reason: "One generated artifact family and its distinct historical live input. Each generated member links to the owning family; no independent current M2 execution is inferred." });
    }
  }
}

function workflowRows(ctx: AdapterContext): void {
  for (const file of ctx.snapshot.files) {
    const data = object(file.data);
    if (!data.jobs && !object(data.runs).steps) continue;
    authoritative(ctx, file, "workflow/action declaration; #1909 runtime receipts");
    const jobs = data.jobs ? Object.entries(object(data.jobs)) : [["composite-action", data.runs]];
    for (const [jobName, rawJob] of jobs) {
      const job = object(rawJob);
      const evidence = censusLocation(file, `jobs/${jobName}`, String(jobName));
      const declaration = consumer(evidence, "This job/action declaration is interpreted by the hosted runner. It declares configuration; it is not an observed run receipt.");
      const declared = (key: string, kind: EnvironmentClass, dependency: string, value: unknown, reason: string): void => {
        const identity = typeof value === "string" ? value : value === undefined ? null : JSON.stringify(value);
        row(ctx, file, `jobs/${jobName}/${key}`, kind, dependency, { evidence, consumer: declaration, observedIdentity: identity, identitySource: identity ? evidence : null, state: identity ? "recorded" : "wholly-unbound", resolution: "dynamic", owner: file.path, links: ["#1909"], reason, freshness: { requirement: "Bind each actual run to resolved runner/image/runtime/shell identity before using its environment behavior as stable evidence.", observedAt: null, expiresAt: null, enforcedBy: null } });
      };
      if (data.jobs) declared("runs-on", "runner-image", "hosted-runner", job["runs-on"], "A runs-on label or expression is a mutable runner selector, not a measured immutable image identity.");
      const globalDefault = object(object(object(data.defaults).run)).shell;
      const jobDefault = object(object(job.defaults).run).shell;
      const steps = Array.isArray(job.steps) ? job.steps : [];
      for (const [index, rawStep] of steps.entries()) {
        const step = object(rawStep);
        if (step.run) declared(`steps/${index}/shell`, "shell", "command-shell", step.shell ?? jobDefault ?? globalDefault, "Shell command and flags may be declared; shell binary version and runner-default behavior remain unresolved without a run receipt.");
        if (step.uses) declared(`steps/${index}/uses`, "tool", "workflow-action", step.uses, "An action ref (including a content SHA) identifies action source, not the executing action's OS/runtime or mutable downloads.");
        const env = { ...object(data.env), ...object(job.env), ...object(step.env) };
        for (const key of ["LANG", "LC_ALL", "LC_COLLATE", "TZ"]) if (env[key] !== undefined) declared(`steps/${index}/${key}`, "locale", key, env[key], "Declared locale/timezone selection can change sorting, parsing or timestamps; no observed libc/timezone-database identity is implied.");
        if (typeof step.run === "string") {
          for (const match of step.run.matchAll(/(?:^|[\s"'])(?:export\s+)?(LANG|LC_ALL|LC_COLLATE|TZ)=([^\s;"']+)/g)) declared(`steps/${index}/inline-${match[1]}-${match.index}`, "locale", match[1]!, match[2]!, "Inline shell environment assignment is discovered from executable step content; it is not an observed environment receipt.");
          for (const match of step.run.matchAll(/["'](LANG|LC_ALL|LC_COLLATE|TZ)["']\s*:\s*["']([^"']+)["']/g)) declared(`steps/${index}/mapping-${match[1]}-${match.index}`, "locale", match[1]!, match[2]!, "A locale/timezone mapping literal appears inside the executable step. Its declared value is recorded without assuming every branch applies it or that a run occurred.");
        }
      }
    }
  }
}

function historicalRows(ctx: AdapterContext): void {
  const mechanical = ctx.files.get("src/__fixtures__/current-mechanical-run-32334325227.json");
  if (mechanical) {
    const data = object(mechanical.data);
    const runtime = object(data.commonRuntime);
    const location = reference(ctx, "src/corpus-mechanical-readiness.test.ts", "historical-run-fixture", "current-mechanical-run-32334325227.json");
    const identities: [string, EnvironmentClass, unknown][] = [["node", "runtime", runtime.node], ["semgrep", "tool", runtime.semgrep], ["gitleaks", "tool", runtime.gitleaks], ["platform/arch", "runner-image", `${runtime.platform}/${runtime.arch}`]];
    for (const shard of Array.isArray(data.producerShards) ? data.producerShards : []) identities.push([`git/shard-${object(shard).index}`, "tool", object(shard).gitVersion]);
    for (const [name, kind, raw] of identities) {
      const identity = string(raw);
      row(ctx, mechanical, `historical-run/${name}`, kind, name, { consumer: consumer(location, "The readiness test reads a historical hosted-run fixture, including its differing Git versions."), observedIdentity: identity, identitySource: identity ? censusLocation(mechanical, name, identity) : null, state: identity ? "recorded" : "wholly-unbound", resolution: identity ? "identified" : "unresolved", owner: "src/corpus-mechanical-readiness.test.ts historical fixture", schemaOwner: name === "semgrep" || name === "gitleaks" ? "#1901 captured output" : null, links: ["#1909", String(data.runId)], reason: `Observed historical run ${String(data.runId)} identity. Current tool pins or current runtime versions must not replace the historical value; no fresh hosted execution is claimed.` });
    }
    authoritative(ctx, mechanical, "historical mechanical readiness fixture");
  }
  for (const file of ctx.snapshot.files) {
    const data = object(file.data);
    const requalification = object(data.requalificationEnvironment);
    if (requalification.collector) {
      const collector = object(requalification.collector);
      for (const [name, kind] of [["node", "runtime"], ["git", "tool"], ["jq", "tool"], ["platform", "runner-image"]] as const) {
        const identity = string(collector[name]);
        row(ctx, file, `requalificationEnvironment/collector/${name}`, kind, name, { observedIdentity: identity, identitySource: identity ? censusLocation(file, `collector/${name}`, identity) : null, state: identity ? "recorded" : "wholly-unbound", resolution: identity ? "identified" : "unresolved", owner: "historical evidence package maintainer (#1758)", links: ["src/cli/validate-calibration.test.ts", "#1909"], freshness: { requirement: "Historical local requalification only; hosted collector identities absent from the original capture remain absent.", observedAt: isoDate(requalification.capturedAt), expiresAt: null, enforcedBy: null }, reason: String(requalification.purpose ?? "Collector identity is recorded in a historical package, with no current execution assertion.") });
      }
      authoritative(ctx, file, "historical evidence package (#1758)");
    }
    if (Array.isArray(data.files) && data.frozenAt && data.kind) {
      const evidence = censusLocation(file, "frozenAt", "frozenAt");
      row(ctx, file, "historical-package", "clock", "historical-freeze-epoch", { observedIdentity: string(data.frozenAt), identitySource: evidence, state: "recorded", resolution: "identified", owner: String(data.kind), links: ["docs/design/corpus-drift.md", "#1909"], freshness: { requirement: "Historical package has a freeze epoch; no present-behavior freshness or current runner equivalence follows.", observedAt: isoDate(data.frozenAt), expiresAt: null, enforcedBy: null }, reason: "Manifest and retained files preserve historical evidence. A documentation link is not an automated consumer/assertion, and member digests do not pin the collector environment." });
      authoritative(ctx, file, String(data.kind));
    }
    if (file.path.startsWith("reports/atc/captures/") && file.data) {
      row(ctx, file, "historical-post-parse-output", "unresolved", "historical-audit-environment", { owner: "ATC historical engagement evidence", links: ["src/scan/__fixtures__/FIXTURE-INVENTORY.md", "#1909"], reason: "Historical Harvey output is in this broader census even though the raw-tool fixture inventory excludes post-parse summaries. No direct current production consumer, complete collector identity or current freshness assertion is resolved." });
    }
  }
}

/** Narrow consumers add facts; the whole-content unresolved row is never removed. */
export function applyCensusAdapters(snapshot: CensusSnapshot, venues: EvidenceVenue[]): { rows: EnvironmentDependencyRow[]; reconciliations: CensusReconciliation[] } {
  const ctx: AdapterContext = { snapshot, venues, rows: [], reconciliations: [], files: new Map(snapshot.files.map((f) => [f.path, f])) };
  genericRows(ctx);
  reasonRows(ctx);
  capturedTools(ctx);
  corpusRows(ctx);
  structuredRows(ctx);
  workflowRows(ctx);
  historicalRows(ctx);
  ctx.rows.sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  ctx.reconciliations.sort((a, b) => a.registry < b.registry ? -1 : a.registry > b.registry ? 1 : 0);
  for (const r of ctx.reconciliations) r.members.sort((a, b) => a.key < b.key ? -1 : a.key > b.key ? 1 : 0);
  return { rows: ctx.rows, reconciliations: ctx.reconciliations };
}
