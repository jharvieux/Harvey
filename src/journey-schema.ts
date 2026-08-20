import { createHash } from "node:crypto";
import type { PackageManager } from "./package-manager.js";
import type { WorkspaceId } from "./workspaces.js";

export const JOURNEY_ADAPTER_IDS = ["cypress", "playwright", "vitest-browser", "webdriverio"] as const;
export type JourneyAdapterId = (typeof JOURNEY_ADAPTER_IDS)[number];
export type JourneyConfigFamilyId = `${JourneyAdapterId}:${string}`;

export type JourneySuiteId = `journey-suite:${string}`;
export type JourneyProjectId = `journey-project:${string}`;
export type JourneyTestId = `journey-test:${string}`;
export type JourneyFixtureId = `journey-fixture:${string}`;
export type JourneyPageObjectId = `journey-page-object:${string}`;
export type JourneyCommandId = `journey-command:${string}`;

export interface JourneyLocation {
  /** Repository-relative POSIX path. */
  path: string;
  line: number;
  column: number;
}

export interface JourneyEvidence {
  kind: "ci-invocation" | "config" | "fixture-source" | "package-manager" | "package-script" | "page-object-source" | "test-source" | "workspace-manifest";
  /** Repository-relative POSIX path. */
  path: string;
  line?: number;
  column?: number;
  pointer?: string;
  adapterId?: JourneyAdapterId;
  configFamilyId?: JourneyConfigFamilyId;
}

export interface JourneyConfigFamilyDefinition {
  id: JourneyConfigFamilyId;
  /** RegExp source matched against a repository-relative POSIX path. */
  pathPattern: string;
  flags?: string;
  /** Every marker is a case-insensitive substring requirement. */
  contentMarkers?: readonly string[];
  shape: "cypress" | "playwright" | "vitest-browser" | "webdriverio";
}

export interface JourneyAdapterDefinition {
  id: JourneyAdapterId;
  order: number;
  framework: "Cypress" | "Playwright" | "Vitest Browser" | "WebdriverIO";
  implementation: { file: string; exportName: string };
  configFamilies: readonly JourneyConfigFamilyDefinition[];
  testPathPatterns: readonly string[];
  suiteCalls: readonly string[];
  testCalls: readonly string[];
  routeCalls: readonly string[];
  scriptNamePattern: string;
  fixturePathPattern: string;
  pageObjectPathPattern: string;
  defaultTestRoots: readonly string[];
  focusedArgs: (testPath: string) => string[];
}

export interface JourneySuite {
  id: JourneySuiteId;
  workspaceId: WorkspaceId;
  adapterId: JourneyAdapterId;
  framework: JourneyAdapterDefinition["framework"];
  configFamilyId: JourneyConfigFamilyId;
  configPath: string;
  title: string;
  location: JourneyLocation;
  projectIds: JourneyProjectId[];
  testIds: JourneyTestId[];
  fixtureIds: JourneyFixtureId[];
  pageObjectIds: JourneyPageObjectId[];
  commandIds: JourneyCommandId[];
  criticality: "unconfirmed";
  evidence: JourneyEvidence[];
}

export interface JourneyProject {
  id: JourneyProjectId;
  suiteId: JourneySuiteId;
  name: string;
  location: JourneyLocation;
  testIds: JourneyTestId[];
  criticality: "unconfirmed";
  evidence: JourneyEvidence[];
}

export interface JourneyTest {
  id: JourneyTestId;
  suiteId: JourneySuiteId;
  projectIds: JourneyProjectId[];
  title: string;
  titlePath: string[];
  location: JourneyLocation;
  routes: string[];
  fixtures: string[];
  personas: string[];
  roles: string[];
  commandIds: JourneyCommandId[];
  criticality: "unconfirmed";
  evidence: JourneyEvidence[];
}

export interface JourneyFixture {
  id: JourneyFixtureId;
  workspaceId: WorkspaceId;
  path: string;
  names: string[];
  adapterIds: JourneyAdapterId[];
  evidence: JourneyEvidence[];
}

export interface JourneyPageObject {
  id: JourneyPageObjectId;
  workspaceId: WorkspaceId;
  path: string;
  names: string[];
  adapterIds: JourneyAdapterId[];
  evidence: JourneyEvidence[];
}

export interface JourneyCommand {
  id: JourneyCommandId;
  kind: "ci-literal" | "package-script";
  scope: "ci" | "focused" | "full";
  workspaceId: WorkspaceId;
  adapterId: JourneyAdapterId;
  suiteId?: JourneySuiteId;
  testId?: JourneyTestId;
  cwd: string;
  bin: PackageManager;
  args: string[];
  evidence: JourneyEvidence[];
}

export type JourneyNotAssessedReason =
  | "absent-suite"
  | "dynamic-config"
  | "generated-config"
  | "malformed-config"
  | "missing-script"
  | "package-manager-unresolved"
  | "unreadable-config"
  | "unsupported-framework"
  | "workspace-inventory-incomplete"
  | "zero-tests";

export type JourneyObservation =
  | {
      status: "examined";
      subject: "ci-invocations" | "config" | "fixtures" | "page-objects" | "tests" | "workspace";
      workspaceId?: WorkspaceId;
      adapterId?: JourneyAdapterId;
      configFamilyId?: JourneyConfigFamilyId;
      unitsExamined: number;
      scope: string;
      provenance: JourneyEvidence[];
    }
  | {
      status: "not-assessed";
      subject: "config" | "scripts" | "suite" | "tests" | "workspace";
      workspaceId?: WorkspaceId;
      adapterId?: JourneyAdapterId;
      configFamilyId?: JourneyConfigFamilyId;
      reason: JourneyNotAssessedReason;
      populationCount: number;
      unitsExamined: 0;
      scope: string;
      provenance: JourneyEvidence[];
      falsifier: string;
    };

export interface JourneyInventoryV1 {
  schemaVersion: 1;
  repoRootId: "workspace:root";
  workspaceIds: WorkspaceId[];
  registry: {
    adapterIds: JourneyAdapterId[];
    configFamilyIds: JourneyConfigFamilyId[];
  };
  suites: JourneySuite[];
  projects: JourneyProject[];
  tests: JourneyTest[];
  fixtures: JourneyFixture[];
  pageObjects: JourneyPageObject[];
  commands: JourneyCommand[];
  observations: JourneyObservation[];
  summary: {
    workspaces: number;
    suites: number;
    projects: number;
    tests: number;
    fixtures: number;
    pageObjects: number;
    commands: number;
    examinedRows: number;
    notAssessedRows: number;
  };
}

const FRAMEWORK_BY_ADAPTER: Readonly<Record<JourneyAdapterId, JourneyAdapterDefinition["framework"]>> = Object.freeze({
  cypress: "Cypress",
  playwright: "Playwright",
  "vitest-browser": "Vitest Browser",
  webdriverio: "WebdriverIO",
});

const NOT_ASSESSED_REASONS: readonly JourneyNotAssessedReason[] = [
  "absent-suite", "dynamic-config", "generated-config", "malformed-config", "missing-script",
  "package-manager-unresolved", "unreadable-config", "unsupported-framework", "workspace-inventory-incomplete", "zero-tests",
];

function digest(parts: readonly string[]): string {
  return createHash("sha256").update(JSON.stringify(parts)).digest("hex").slice(0, 24);
}

export function journeySuiteId(workspaceId: WorkspaceId, adapterId: JourneyAdapterId, configFamilyId: JourneyConfigFamilyId, configPath: string): JourneySuiteId {
  return `journey-suite:${digest([workspaceId, adapterId, configFamilyId, configPath])}`;
}

export function journeyProjectId(suiteId: JourneySuiteId, name: string): JourneyProjectId {
  return `journey-project:${digest([suiteId, name])}`;
}

export function journeyTestId(suiteId: JourneySuiteId, path: string, titlePath: readonly string[]): JourneyTestId {
  return `journey-test:${digest([suiteId, path, ...titlePath])}`;
}

export function journeyFixtureId(workspaceId: WorkspaceId, path: string): JourneyFixtureId {
  return `journey-fixture:${digest([workspaceId, path])}`;
}

export function journeyPageObjectId(workspaceId: WorkspaceId, path: string): JourneyPageObjectId {
  return `journey-page-object:${digest([workspaceId, path])}`;
}

export function journeyCommandId(command: Omit<JourneyCommand, "id" | "evidence">): JourneyCommandId {
  return `journey-command:${digest([
    command.kind,
    command.scope,
    command.workspaceId,
    command.adapterId,
    command.suiteId ?? "",
    command.testId ?? "",
    command.cwd,
    command.bin,
    ...command.args,
  ])}`;
}

function compareText(a: string, b: string): number {
  return a.localeCompare(b);
}

export function compareEvidence(a: JourneyEvidence, b: JourneyEvidence): number {
  return JSON.stringify(a).localeCompare(JSON.stringify(b));
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, allowed: readonly string[], required: readonly string[], at: string, problems: string[]): void {
  const allowedSet = new Set(allowed);
  for (const key of Object.keys(value)) if (!allowedSet.has(key)) problems.push(`${at}: unexpected field ${key}`);
  for (const key of required) if (!(key in value)) problems.push(`${at}: missing field ${key}`);
}

function validRelativePath(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && !value.startsWith("/") && !value.includes("\\")
    && value.split("/").every((part) => part !== "" && part !== "..");
}

function checkSortedUnique(values: unknown, at: string, problems: string[]): string[] {
  if (!Array.isArray(values) || !values.every((value) => typeof value === "string")) {
    problems.push(`${at}: expected string array`);
    return [];
  }
  const strings = values as string[];
  const expected = [...new Set(strings)].sort(compareText);
  if (JSON.stringify(strings) !== JSON.stringify(expected)) problems.push(`${at}: values must be unique and sorted`);
  return strings;
}

function checkLocation(value: unknown, at: string, problems: string[]): value is JourneyLocation {
  if (!isObject(value)) {
    problems.push(`${at}: expected location object`);
    return false;
  }
  exactKeys(value, ["path", "line", "column"], ["path", "line", "column"], at, problems);
  if (!validRelativePath(value.path)) problems.push(`${at}.path: expected repository-relative POSIX path`);
  if (!Number.isInteger(value.line) || (value.line as number) < 1) problems.push(`${at}.line: expected positive integer`);
  if (!Number.isInteger(value.column) || (value.column as number) < 1) problems.push(`${at}.column: expected positive integer`);
  return true;
}

function checkEvidence(value: unknown, at: string, problems: string[]): value is JourneyEvidence {
  if (!isObject(value)) {
    problems.push(`${at}: expected evidence object`);
    return false;
  }
  exactKeys(value, ["kind", "path", "line", "column", "pointer", "adapterId", "configFamilyId"], ["kind", "path"], at, problems);
  const kinds = new Set(["ci-invocation", "config", "fixture-source", "package-manager", "package-script", "page-object-source", "test-source", "workspace-manifest"]);
  if (!kinds.has(String(value.kind))) problems.push(`${at}.kind: unsupported evidence kind`);
  if (!validRelativePath(value.path)) problems.push(`${at}.path: expected repository-relative POSIX path`);
  for (const key of ["line", "column"] as const) if (value[key] !== undefined && (!Number.isInteger(value[key]) || (value[key] as number) < 1)) problems.push(`${at}.${key}: expected positive integer`);
  if (value.pointer !== undefined && typeof value.pointer !== "string") problems.push(`${at}.pointer: expected string`);
  if (value.adapterId !== undefined && !(JOURNEY_ADAPTER_IDS as readonly string[]).includes(String(value.adapterId))) problems.push(`${at}.adapterId: unsupported adapter`);
  if (value.configFamilyId !== undefined && typeof value.configFamilyId !== "string") problems.push(`${at}.configFamilyId: expected string`);
  return true;
}

function checkEvidenceArray(value: unknown, at: string, problems: string[], allowEmpty = false): JourneyEvidence[] {
  if (!Array.isArray(value)) {
    problems.push(`${at}: expected evidence array`);
    return [];
  }
  if (!allowEmpty && value.length === 0) problems.push(`${at}: evidence must not be empty`);
  value.forEach((entry, index) => checkEvidence(entry, `${at}[${index}]`, problems));
  const expected = [...value].sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  if (JSON.stringify(value) !== JSON.stringify(expected)) problems.push(`${at}: evidence must be stably sorted`);
  return value as JourneyEvidence[];
}

function checkRowOrder(rows: unknown, at: string, problems: string[]): Record<string, unknown>[] {
  if (!Array.isArray(rows)) {
    problems.push(`${at}: expected array`);
    return [];
  }
  if (!rows.every(isObject)) {
    problems.push(`${at}: every row must be an object`);
    return [];
  }
  const objects = rows as Record<string, unknown>[];
  const ids = objects.map((row) => row.id);
  if (!ids.every((id) => typeof id === "string")) problems.push(`${at}: every row needs a string id`);
  else if (JSON.stringify(ids) !== JSON.stringify([...new Set(ids as string[])].sort(compareText))) problems.push(`${at}: ids must be unique and sorted`);
  return objects;
}

function checkCriticality(row: Record<string, unknown>, at: string, problems: string[]): void {
  if (row.criticality !== "unconfirmed") problems.push(`${at}.criticality: inferred journeys must remain unconfirmed`);
}

/** Runtime validator for the durable child-process boundary. It rejects extensions as well as omissions. */
export function validateJourneyInventoryV1(value: unknown): string[] {
  const problems: string[] = [];
  if (!isObject(value)) return ["inventory: expected object"];
  exactKeys(
    value,
    ["schemaVersion", "repoRootId", "workspaceIds", "registry", "suites", "projects", "tests", "fixtures", "pageObjects", "commands", "observations", "summary"],
    ["schemaVersion", "repoRootId", "workspaceIds", "registry", "suites", "projects", "tests", "fixtures", "pageObjects", "commands", "observations", "summary"],
    "inventory",
    problems,
  );
  if (value.schemaVersion !== 1) problems.push("inventory.schemaVersion: expected 1");
  if (value.repoRootId !== "workspace:root") problems.push("inventory.repoRootId: expected workspace:root");
  const workspaceIds = checkSortedUnique(value.workspaceIds, "inventory.workspaceIds", problems);
  if (!workspaceIds.includes("workspace:root")) problems.push("inventory.workspaceIds: workspace:root is required");
  if (workspaceIds.some((id) => !id.startsWith("workspace:"))) problems.push("inventory.workspaceIds: invalid workspace identity");

  if (!isObject(value.registry)) problems.push("inventory.registry: expected object");
  else {
    exactKeys(value.registry, ["adapterIds", "configFamilyIds"], ["adapterIds", "configFamilyIds"], "inventory.registry", problems);
    const adapterIds = checkSortedUnique(value.registry.adapterIds, "inventory.registry.adapterIds", problems);
    if (adapterIds.some((id) => !(JOURNEY_ADAPTER_IDS as readonly string[]).includes(id))) problems.push("inventory.registry.adapterIds: unsupported adapter id");
    if (JSON.stringify(adapterIds) !== JSON.stringify([...JOURNEY_ADAPTER_IDS].sort(compareText))) problems.push("inventory.registry.adapterIds: incomplete supported adapter population");
    const configFamilyIds = checkSortedUnique(value.registry.configFamilyIds, "inventory.registry.configFamilyIds", problems);
    if (configFamilyIds.some((id) => !JOURNEY_ADAPTER_IDS.some((adapterId) => id.startsWith(`${adapterId}:`)))) problems.push("inventory.registry.configFamilyIds: invalid config-family identity");
  }

  const suites = checkRowOrder(value.suites, "inventory.suites", problems);
  const projects = checkRowOrder(value.projects, "inventory.projects", problems);
  const tests = checkRowOrder(value.tests, "inventory.tests", problems);
  const fixtures = checkRowOrder(value.fixtures, "inventory.fixtures", problems);
  const pageObjects = checkRowOrder(value.pageObjects, "inventory.pageObjects", problems);
  const commands = checkRowOrder(value.commands, "inventory.commands", problems);
  const suiteIds = new Set(suites.map((row) => String(row.id)));
  const projectIds = new Set(projects.map((row) => String(row.id)));
  const testIds = new Set(tests.map((row) => String(row.id)));
  const fixtureIds = new Set(fixtures.map((row) => String(row.id)));
  const pageObjectIds = new Set(pageObjects.map((row) => String(row.id)));
  const commandIds = new Set(commands.map((row) => String(row.id)));

  suites.forEach((row, index) => {
    const at = `inventory.suites[${index}]`;
    exactKeys(row, ["id", "workspaceId", "adapterId", "framework", "configFamilyId", "configPath", "title", "location", "projectIds", "testIds", "fixtureIds", "pageObjectIds", "commandIds", "criticality", "evidence"], ["id", "workspaceId", "adapterId", "framework", "configFamilyId", "configPath", "title", "location", "projectIds", "testIds", "fixtureIds", "pageObjectIds", "commandIds", "criticality", "evidence"], at, problems);
    if (!workspaceIds.includes(String(row.workspaceId))) problems.push(`${at}.workspaceId: unknown workspace`);
    if (!(JOURNEY_ADAPTER_IDS as readonly unknown[]).includes(row.adapterId)) problems.push(`${at}.adapterId: unsupported adapter`);
    else if (row.framework !== FRAMEWORK_BY_ADAPTER[row.adapterId as JourneyAdapterId]) problems.push(`${at}.framework: does not match adapter`);
    if (typeof row.configFamilyId !== "string" || typeof row.adapterId !== "string" || !row.configFamilyId.startsWith(`${row.adapterId}:`)) problems.push(`${at}.configFamilyId: does not belong to adapter`);
    if (!validRelativePath(row.configPath)) problems.push(`${at}.configPath: invalid path`);
    if (typeof row.title !== "string" || row.title.length === 0) problems.push(`${at}.title: expected non-empty string`);
    checkLocation(row.location, `${at}.location`, problems);
    const ps = checkSortedUnique(row.projectIds, `${at}.projectIds`, problems);
    if (ps.length === 0) problems.push(`${at}.projectIds: every suite requires at least one project`);
    const ts = checkSortedUnique(row.testIds, `${at}.testIds`, problems);
    const fs = checkSortedUnique(row.fixtureIds, `${at}.fixtureIds`, problems);
    const pos = checkSortedUnique(row.pageObjectIds, `${at}.pageObjectIds`, problems);
    const cs = checkSortedUnique(row.commandIds, `${at}.commandIds`, problems);
    for (const id of ps) if (!projectIds.has(id)) problems.push(`${at}.projectIds: unknown ${id}`);
    for (const id of ts) if (!testIds.has(id)) problems.push(`${at}.testIds: unknown ${id}`);
    for (const id of fs) if (!fixtureIds.has(id)) problems.push(`${at}.fixtureIds: unknown ${id}`);
    for (const id of pos) if (!pageObjectIds.has(id)) problems.push(`${at}.pageObjectIds: unknown ${id}`);
    for (const id of cs) if (!commandIds.has(id)) problems.push(`${at}.commandIds: unknown ${id}`);
    checkCriticality(row, at, problems);
    checkEvidenceArray(row.evidence, `${at}.evidence`, problems);
    if (typeof row.workspaceId === "string" && typeof row.adapterId === "string" && typeof row.configFamilyId === "string" && typeof row.configPath === "string") {
      const expected = journeySuiteId(row.workspaceId as WorkspaceId, row.adapterId as JourneyAdapterId, row.configFamilyId as JourneyConfigFamilyId, row.configPath);
      if (row.id !== expected) problems.push(`${at}.id: unstable or invalid suite identity`);
    }
  });

  projects.forEach((row, index) => {
    const at = `inventory.projects[${index}]`;
    exactKeys(row, ["id", "suiteId", "name", "location", "testIds", "criticality", "evidence"], ["id", "suiteId", "name", "location", "testIds", "criticality", "evidence"], at, problems);
    if (!suiteIds.has(String(row.suiteId))) problems.push(`${at}.suiteId: unknown suite`);
    if (typeof row.name !== "string" || row.name.length === 0) problems.push(`${at}.name: expected non-empty string`);
    checkLocation(row.location, `${at}.location`, problems);
    for (const id of checkSortedUnique(row.testIds, `${at}.testIds`, problems)) if (!testIds.has(id)) problems.push(`${at}.testIds: unknown ${id}`);
    checkCriticality(row, at, problems);
    checkEvidenceArray(row.evidence, `${at}.evidence`, problems);
    if (typeof row.suiteId === "string" && typeof row.name === "string" && row.id !== journeyProjectId(row.suiteId as JourneySuiteId, row.name)) problems.push(`${at}.id: unstable or invalid project identity`);
  });

  tests.forEach((row, index) => {
    const at = `inventory.tests[${index}]`;
    exactKeys(row, ["id", "suiteId", "projectIds", "title", "titlePath", "location", "routes", "fixtures", "personas", "roles", "commandIds", "criticality", "evidence"], ["id", "suiteId", "projectIds", "title", "titlePath", "location", "routes", "fixtures", "personas", "roles", "commandIds", "criticality", "evidence"], at, problems);
    if (!suiteIds.has(String(row.suiteId))) problems.push(`${at}.suiteId: unknown suite`);
    const rowProjectIds = checkSortedUnique(row.projectIds, `${at}.projectIds`, problems);
    if (rowProjectIds.length === 0) problems.push(`${at}.projectIds: every test requires at least one project`);
    for (const id of rowProjectIds) if (!projectIds.has(id)) problems.push(`${at}.projectIds: unknown ${id}`);
    const titlePath = checkSortedStringSequence(row.titlePath, `${at}.titlePath`, problems);
    if (typeof row.title !== "string" || row.title.length === 0 || titlePath.at(-1) !== row.title) problems.push(`${at}.title: must equal the last titlePath segment`);
    checkLocation(row.location, `${at}.location`, problems);
    for (const key of ["routes", "fixtures", "personas", "roles"] as const) checkSortedUnique(row[key], `${at}.${key}`, problems);
    const rowCommandIds = checkSortedUnique(row.commandIds, `${at}.commandIds`, problems);
    for (const id of rowCommandIds) if (!commandIds.has(id)) problems.push(`${at}.commandIds: unknown ${id}`);
    checkCriticality(row, at, problems);
    checkEvidenceArray(row.evidence, `${at}.evidence`, problems);
    if (typeof row.suiteId === "string" && row.location && isObject(row.location) && typeof row.location.path === "string" && titlePath.length > 0
      && row.id !== journeyTestId(row.suiteId as JourneySuiteId, row.location.path, titlePath)) problems.push(`${at}.id: unstable or invalid test identity`);
  });

  fixtures.forEach((row, index) => {
    const at = `inventory.fixtures[${index}]`;
    exactKeys(row, ["id", "workspaceId", "path", "names", "adapterIds", "evidence"], ["id", "workspaceId", "path", "names", "adapterIds", "evidence"], at, problems);
    if (!workspaceIds.includes(String(row.workspaceId))) problems.push(`${at}.workspaceId: unknown workspace`);
    if (!validRelativePath(row.path)) problems.push(`${at}.path: invalid path`);
    checkSortedUnique(row.names, `${at}.names`, problems);
    if ((row.names as unknown[] | undefined)?.length === 0) problems.push(`${at}.names: expected at least one symbol`);
    const adapterIds = checkSortedUnique(row.adapterIds, `${at}.adapterIds`, problems);
    if (adapterIds.length === 0 || adapterIds.some((id) => !(JOURNEY_ADAPTER_IDS as readonly string[]).includes(id))) problems.push(`${at}.adapterIds: expected supported adapter population`);
    checkEvidenceArray(row.evidence, `${at}.evidence`, problems);
    if (typeof row.workspaceId === "string" && typeof row.path === "string" && row.id !== journeyFixtureId(row.workspaceId as WorkspaceId, row.path)) problems.push(`${at}.id: unstable or invalid fixture identity`);
  });

  pageObjects.forEach((row, index) => {
    const at = `inventory.pageObjects[${index}]`;
    exactKeys(row, ["id", "workspaceId", "path", "names", "adapterIds", "evidence"], ["id", "workspaceId", "path", "names", "adapterIds", "evidence"], at, problems);
    if (!workspaceIds.includes(String(row.workspaceId))) problems.push(`${at}.workspaceId: unknown workspace`);
    if (!validRelativePath(row.path)) problems.push(`${at}.path: invalid path`);
    checkSortedUnique(row.names, `${at}.names`, problems);
    if ((row.names as unknown[] | undefined)?.length === 0) problems.push(`${at}.names: expected at least one symbol`);
    const adapterIds = checkSortedUnique(row.adapterIds, `${at}.adapterIds`, problems);
    if (adapterIds.length === 0 || adapterIds.some((id) => !(JOURNEY_ADAPTER_IDS as readonly string[]).includes(id))) problems.push(`${at}.adapterIds: expected supported adapter population`);
    checkEvidenceArray(row.evidence, `${at}.evidence`, problems);
    if (typeof row.workspaceId === "string" && typeof row.path === "string" && row.id !== journeyPageObjectId(row.workspaceId as WorkspaceId, row.path)) problems.push(`${at}.id: unstable or invalid page-object identity`);
  });

  commands.forEach((row, index) => {
    const at = `inventory.commands[${index}]`;
    exactKeys(row, ["id", "kind", "scope", "workspaceId", "adapterId", "suiteId", "testId", "cwd", "bin", "args", "evidence"], ["id", "kind", "scope", "workspaceId", "adapterId", "cwd", "bin", "args", "evidence"], at, problems);
    if (!workspaceIds.includes(String(row.workspaceId))) problems.push(`${at}.workspaceId: unknown workspace`);
    if (!(JOURNEY_ADAPTER_IDS as readonly unknown[]).includes(row.adapterId)) problems.push(`${at}.adapterId: unsupported adapter`);
    if (row.suiteId !== undefined && !suiteIds.has(String(row.suiteId))) problems.push(`${at}.suiteId: unknown suite`);
    if (row.testId !== undefined && !testIds.has(String(row.testId))) problems.push(`${at}.testId: unknown test`);
    if (!validRelativePath(row.cwd)) problems.push(`${at}.cwd: invalid path`);
    if (!(["npm", "pnpm", "yarn"] as unknown[]).includes(row.bin)) problems.push(`${at}.bin: unsupported package manager`);
    if (!Array.isArray(row.args) || row.args.length === 0 || !row.args.every((arg) => typeof arg === "string" && arg.length > 0 && !/[\n\r\0]/.test(arg))) problems.push(`${at}.args: expected non-empty safe token array`);
    if (row.kind === "package-script") {
      if (!(["full", "focused"] as unknown[]).includes(row.scope) || row.suiteId === undefined) problems.push(`${at}: package-script commands require full/focused scope and a suite`);
      if (!Array.isArray(row.args) || row.args[0] !== "run" || typeof row.args[1] !== "string") problems.push(`${at}.args: package-script command must use the tokenized run wrapper`);
      if (row.scope === "full" && Array.isArray(row.args) && row.args.length !== 2) problems.push(`${at}.args: full command may contain only run and script tokens`);
      if (row.scope === "focused" && (!Array.isArray(row.args) || !row.args.includes("--") || row.testId === undefined)) problems.push(`${at}.args: focused command requires -- forwarding and a test`);
    } else if (row.kind === "ci-literal") {
      if (row.scope !== "ci" || row.testId !== undefined) problems.push(`${at}: CI commands require ci scope and no test`);
    } else problems.push(`${at}.kind: unsupported command kind`);
    checkEvidenceArray(row.evidence, `${at}.evidence`, problems);
    if (typeof row.kind === "string" && typeof row.scope === "string" && typeof row.workspaceId === "string" && typeof row.adapterId === "string" && typeof row.cwd === "string" && typeof row.bin === "string" && Array.isArray(row.args)) {
      const expected = journeyCommandId({
        kind: row.kind as JourneyCommand["kind"], scope: row.scope as JourneyCommand["scope"], workspaceId: row.workspaceId as WorkspaceId,
        adapterId: row.adapterId as JourneyAdapterId, ...(row.suiteId ? { suiteId: row.suiteId as JourneySuiteId } : {}),
        ...(row.testId ? { testId: row.testId as JourneyTestId } : {}), cwd: row.cwd, bin: row.bin as PackageManager, args: row.args as string[],
      });
      if (row.id !== expected) problems.push(`${at}.id: unstable or invalid command identity`);
    }
  });

  if (!Array.isArray(value.observations)) problems.push("inventory.observations: expected array");
  else {
    const sorted = [...value.observations].sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
    if (JSON.stringify(value.observations) !== JSON.stringify(sorted)) problems.push("inventory.observations: rows must be stably sorted");
    value.observations.forEach((entry, index) => {
      const at = `inventory.observations[${index}]`;
      if (!isObject(entry)) { problems.push(`${at}: expected object`); return; }
      if (entry.status === "examined") {
        exactKeys(entry, ["status", "subject", "workspaceId", "adapterId", "configFamilyId", "unitsExamined", "scope", "provenance"], ["status", "subject", "unitsExamined", "scope", "provenance"], at, problems);
        if (!Number.isInteger(entry.unitsExamined) || (entry.unitsExamined as number) < 1) problems.push(`${at}.unitsExamined: examined rows require a positive count`);
        if (!(["ci-invocations", "config", "fixtures", "page-objects", "tests", "workspace"] as unknown[]).includes(entry.subject)) problems.push(`${at}.subject: unsupported examined subject`);
      } else if (entry.status === "not-assessed") {
        exactKeys(entry, ["status", "subject", "workspaceId", "adapterId", "configFamilyId", "reason", "populationCount", "unitsExamined", "scope", "provenance", "falsifier"], ["status", "subject", "reason", "populationCount", "unitsExamined", "scope", "provenance", "falsifier"], at, problems);
        if (entry.unitsExamined !== 0) problems.push(`${at}.unitsExamined: not-assessed rows must be zero`);
        if (!Number.isInteger(entry.populationCount) || (entry.populationCount as number) < 1) problems.push(`${at}.populationCount: expected positive integer`);
        if (typeof entry.falsifier !== "string" || entry.falsifier.length < 12) problems.push(`${at}.falsifier: expected concrete falsifier`);
        if (!(["config", "scripts", "suite", "tests", "workspace"] as unknown[]).includes(entry.subject)) problems.push(`${at}.subject: unsupported not-assessed subject`);
        if (!(NOT_ASSESSED_REASONS as readonly unknown[]).includes(entry.reason)) problems.push(`${at}.reason: unsupported not-assessed reason`);
      } else problems.push(`${at}.status: expected examined or not-assessed`);
      if (typeof entry.scope !== "string" || entry.scope.length === 0) problems.push(`${at}.scope: expected non-empty string`);
      if (entry.workspaceId !== undefined && !workspaceIds.includes(String(entry.workspaceId))) problems.push(`${at}.workspaceId: unknown workspace`);
      if (entry.adapterId !== undefined && !(JOURNEY_ADAPTER_IDS as readonly unknown[]).includes(entry.adapterId)) problems.push(`${at}.adapterId: unsupported adapter`);
      if (entry.configFamilyId !== undefined && (typeof entry.adapterId !== "string" || typeof entry.configFamilyId !== "string" || !entry.configFamilyId.startsWith(`${entry.adapterId}:`))) problems.push(`${at}.configFamilyId: does not belong to adapter`);
      checkEvidenceArray(entry.provenance, `${at}.provenance`, problems);
    });
  }

  for (const project of projects) {
    const suite = suites.find((row) => row.id === project.suiteId);
    const suiteProjectIds = suite && Array.isArray(suite.projectIds) ? suite.projectIds : [];
    if (suite && !suiteProjectIds.includes(project.id)) problems.push(`${project.id}: suite does not retain its project id`);
    for (const testId of Array.isArray(project.testIds) ? project.testIds : []) {
      const test = tests.find((row) => row.id === testId);
      if (test && test.suiteId !== project.suiteId) problems.push(`${project.id}: project references a test from another suite`);
    }
  }
  for (const test of tests) {
    const suite = suites.find((row) => row.id === test.suiteId);
    const suiteTestIds = suite && Array.isArray(suite.testIds) ? suite.testIds : [];
    if (suite && !suiteTestIds.includes(test.id)) problems.push(`${test.id}: suite does not retain its test id`);
    for (const projectId of Array.isArray(test.projectIds) ? test.projectIds : []) {
      const project = projects.find((row) => row.id === projectId);
      if (project && project.suiteId !== test.suiteId) problems.push(`${test.id}: test references a project from another suite`);
    }
  }
  for (const command of commands) {
    if (command.kind === "package-script" && command.suiteId) {
      const suite = suites.find((row) => row.id === command.suiteId);
      const suiteCommandIds = suite && Array.isArray(suite.commandIds) ? suite.commandIds : [];
      if (suite && !suiteCommandIds.includes(command.id)) problems.push(`${command.id}: suite does not retain its package command id`);
    }
    if (command.testId) {
      const test = tests.find((row) => row.id === command.testId);
      const testCommandIds = test && Array.isArray(test.commandIds) ? test.commandIds : [];
      if (test && !testCommandIds.includes(command.id)) problems.push(`${command.id}: test does not retain its focused command id`);
    }
  }

  if (!isObject(value.summary)) problems.push("inventory.summary: expected object");
  else {
    const keys = ["workspaces", "suites", "projects", "tests", "fixtures", "pageObjects", "commands", "examinedRows", "notAssessedRows"] as const;
    exactKeys(value.summary, keys, keys, "inventory.summary", problems);
    const observations = Array.isArray(value.observations) ? value.observations.filter(isObject) : [];
    const expected: Record<(typeof keys)[number], number> = {
      workspaces: workspaceIds.length, suites: suites.length, projects: projects.length, tests: tests.length,
      fixtures: fixtures.length, pageObjects: pageObjects.length, commands: commands.length,
      examinedRows: observations.filter((row) => row.status === "examined").length,
      notAssessedRows: observations.filter((row) => row.status === "not-assessed").length,
    };
    for (const key of keys) if (value.summary[key] !== expected[key]) problems.push(`inventory.summary.${key}: expected ${expected[key]}`);
  }
  return problems;
}

function checkSortedStringSequence(value: unknown, at: string, problems: string[]): string[] {
  if (!Array.isArray(value) || value.length === 0 || !value.every((entry) => typeof entry === "string" && entry.length > 0)) {
    problems.push(`${at}: expected non-empty string sequence`);
    return [];
  }
  return value as string[];
}

export function parseJourneyInventoryV1(value: string | unknown): JourneyInventoryV1 {
  let parsed: unknown = value;
  if (typeof value === "string") {
    try { parsed = JSON.parse(value); }
    catch { throw new Error("JourneyInventoryV1 is not valid JSON"); }
  }
  const problems = validateJourneyInventoryV1(parsed);
  if (problems.length > 0) throw new Error(`JourneyInventoryV1 is invalid:\n${problems.join("\n")}`);
  return parsed as JourneyInventoryV1;
}

export function serializeJourneyInventoryV1(inventory: JourneyInventoryV1): string {
  return `${JSON.stringify(parseJourneyInventoryV1(inventory), null, 2)}\n`;
}
