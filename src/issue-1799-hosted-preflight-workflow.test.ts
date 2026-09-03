import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";

const WORKFLOW_PATH = join(process.cwd(), ".github", "workflows", "issue-1799-hosted-preflight.yml");
const LIVENESS_PATH = join(process.cwd(), ".github", "gate-liveness.json");
const EXPECTED_PROFILE = "(version 1)\n(allow default)\n(deny network*)";
const EXPECTED_PROFILE_SHA256 = "9c5b74ccb7b1548dff667033de6f0b70fd71aa836247c164b64ba8bfdaeb4a3b";
const workflow = readFileSync(WORKFLOW_PATH, "utf8");

interface WorkflowStep { uses?: string; run?: string }
interface WorkflowDocument {
  on: Record<string, unknown>;
  permissions: Record<string, unknown>;
  jobs: Record<string, { "runs-on": string; "timeout-minutes": number; steps: WorkflowStep[] }>;
}

function embeddedSource(text: string, name: string): string {
  const match = text.match(new RegExp(`IFS= read -r -d '' ${name} <<'PY'.*?\\n([\\s\\S]*?)\\n {10}PY`));
  return match?.[1] ?? "";
}

function workflowErrors(text: string): string[] {
  const errors: string[] = [];
  let parsed: WorkflowDocument | undefined;
  let script = "";
  try {
    parsed = parse(text) as WorkflowDocument;
    script = Object.values(parsed.jobs ?? {}).flatMap((job) => job.steps ?? [])[0]?.run ?? "";
  } catch {
    errors.push("valid YAML");
  }
  if (parsed) {
    if (Object.keys(parsed.on ?? {}).join(",") !== "workflow_dispatch") errors.push("manual-only trigger");
    if (Object.keys(parsed.permissions ?? {}).length !== 0) errors.push("zero permissions");
    const jobs = Object.values(parsed.jobs ?? {});
    if (jobs.length !== 1 || jobs[0]?.["runs-on"] !== "macos-15" || jobs[0]?.["timeout-minutes"] !== 10) errors.push("bounded ARM64 job");
    const steps = jobs.flatMap((job) => job.steps ?? []);
    if (steps.length !== 1 || steps[0]?.uses || !steps[0]?.run) errors.push("single synthetic step");
  }
  if (!script.includes(`readonly DENY_NETWORK_PROFILE='${EXPECTED_PROFILE}'`)) errors.push("exact deny-network profile");
  if (!script.includes('readonly PYTHON="$(/usr/bin/xcrun --find python3)"')) errors.push("real Python resolver");
  if (!script.includes('[[ "$PYTHON" == /* && "$PYTHON" != *$\'\\n\'* && -x "$PYTHON" ]]')) errors.push("resolved Python validation");
  if ((text.match(new RegExp(EXPECTED_PROFILE_SHA256, "g")) ?? []).length < 3) errors.push("independent exact profile hash authorities");
  if (!text.includes('[[ "$profile_sha256" == "$EXPECTED_DENY_NETWORK_PROFILE_SHA256" ]]')) errors.push("staged profile hash binding");
  if (!text.includes('require(hashes["deny-network.sb"] == EXPECTED_DENY_NETWORK_PROFILE_SHA256)')) errors.push("controller profile hash binding");
  if (!text.includes('require(observations["profileSha256"] == EXPECTED_DENY_NETWORK_PROFILE_SHA256)')) errors.push("publisher profile hash binding");

  const controller = embeddedSource(text, "CONTROLLER_SOURCE");
  const helper = embeddedSource(text, "HELPER_SOURCE");
  const child = embeddedSource(text, "NETWORK_CHILD_SOURCE");
  const grandchild = embeddedSource(text, "NETWORK_GRANDCHILD_SOURCE");
  const allow = embeddedSource(text, "NETWORK_ALLOW_SOURCE");
  if (!controller || !helper || !child || !grandchild || !allow) errors.push("all embedded probes");
  if ((text.match(/__CF_USER_TEXT_ENCODING/g) ?? []).length < 8) errors.push("Apple Python environment declaration");
  if (!controller.includes("sys.executable") || !helper.includes("sys.executable") || !child.includes("sys.executable")) errors.push("real Python descendant launch");
  if ([controller, helper, child].some((source) => source.includes('"/usr/bin/python3"'))) errors.push("Apple Python shim bypass");
  if (helper.includes("sandbox-exec") || child.includes("sandbox-exec") || grandchild.includes("sandbox-exec")) errors.push("unwrapped descendants");
  if (!controller.includes('plain_python(root, "helper.py")')) errors.push("plain helper launch");
  if (!controller.includes('["/usr/bin/sandbox-exec", "-f", os.path.join(root, "deny-network.sb")')) errors.push("network child boundary launch");
  if (!controller.includes('os.path.join(root, "network-child.py")')) errors.push("network child launch");
  if (!child.includes('plain_python(root, "network-grandchild.py")')) errors.push("plain grandchild launch");
  if (script.includes('"$SANDBOX_EXEC" -f "$ROOT/deny-network.sb" "$ENV_BIN" -i')) errors.push("controller inside network boundary");
  if ((text.match(/close_fds=True/g) ?? []).length < 6 || text.includes("pass_fds=")) errors.push("closed inherited descriptors");

  for (const proof of [
    '"tcp4Bind"', '"tcp6Bind"', '"udp4Bind"', '"udp6Bind"', '"unixBind"',
    '"tcp4LoopbackConnect"', '"tcp6LoopbackConnect"', '"udp4LoopbackSend"', '"udp6LoopbackSend"',
    '"mdnsUnixConnect"', '"tcp4DocumentationConnect"', '"tcp6DocumentationConnect"',
    '"udp4DocumentationSend"', '"udp6DocumentationSend"', '"grandchildTcp4LoopbackConnect"',
    '"grandchildMdnsUnixConnect"',
  ]) if (!text.includes(proof)) errors.push(`missing probe ${proof}`);
  for (const operation of ["handle.connect(address)", 'handle.sendto(b"x", address)']) if (!child.includes(operation)) errors.push(`missing denied operation ${operation}`);
  if (!child.includes('("192.0.2.1", 443)') || !child.includes('("2001:db8::1", 443, 0, 0)')) errors.push("documentation-prefix remote endpoints");
  if (!child.includes('"/private/var/run/mDNSResponder"') || !grandchild.includes('"/private/var/run/mDNSResponder"')) errors.push("mDNS socket probes");
  if (!text.includes("errno.EPERM, errno.EACCES")) errors.push("strict denied errno set");
  if (!allow.includes("socket.AF_INET6") || !allow.includes("socket.AF_UNIX") || !allow.includes("sendto")) errors.push("local allow twins");
  if (!allow.includes('mdns.connect("/private/var/run/mDNSResponder")')) errors.push("exact mDNS allow twin");
  if ((text.match(/"networkConnectAttemptsByAuditedPrograms": 11/g) ?? []).length < 2) errors.push("truthful network attempt total");
  if (child.includes('os.path.join(root, "missing.sock")')) errors.push("nonexistent Unix endpoint");
  if (!text.includes('"remoteEndpointsAttempted": 4')) errors.push("truthful remote attempt total");
  if (!text.includes('"networkBindAttemptsByAuditedPrograms": 5')) errors.push("truthful bind attempt total");
  if (!text.includes('"successfulNetworkConnectsByAuditedPrograms": 0')) errors.push("zero successful connects");
  if (!text.includes('"successfulBinds": 0')) errors.push("zero successful binds");
  if (!text.includes('"allowControlAttempts": 6')) errors.push("allow control total");
  if (!text.includes('"nonNetworkFileIoPassed": True') || !text.includes('"nonNetworkProcessExecPassed": True')) errors.push("non-network controls");
  if (!text.includes("trap cleanup_on_exit EXIT HUP INT TERM") || !text.includes("trap - EXIT HUP INT TERM")) errors.push("signal-safe exact teardown");
  if (!text.includes('purge(root + ".p5-control")') || !text.includes("not os.path.lexists(root)")) errors.push("no-follow teardown controls");
  if (/actions\/checkout|secrets\.|\bsudo\b|\bpfctl\b|continue-on-error|\bretry\b/.test(text)) errors.push("forbidden expanded surface");
  return errors;
}

describe("#1799 hosted ARM64 egress preflight", () => {
  it("binds a minimal manual workflow to the exact Seatbelt policy and complete evidence", () => {
    expect(createHash("sha256").update(EXPECTED_PROFILE).digest("hex")).toBe(EXPECTED_PROFILE_SHA256);
    expect(workflowErrors(workflow)).toEqual([]);
  });

  it("fails the former bind-only implementation", () => {
    const mutant = workflow
      .replaceAll("handle.connect(address)", "handle.bind(address)")
      .replaceAll('handle.sendto(b"x", address)', "handle.bind(address)");
    expect(workflowErrors(mutant)).toContain("missing denied operation handle.connect(address)");
    expect(workflowErrors(mutant)).toContain('missing denied operation handle.sendto(b"x", address)');
  });

  it("fails a descendant that rewraps itself instead of proving inherited policy", () => {
    const mutant = workflow.replace(
      'plain_python(root, "network-grandchild.py")',
      '["/usr/bin/sandbox-exec", "-f", os.path.join(root, "deny-network.sb"), *plain_python(root, "network-grandchild.py")]',
    );
    expect(workflowErrors(mutant)).toContain("unwrapped descendants");
  });

  it("fails a controller-wide boundary that blocks the independent process census", () => {
    const launch = '          "$ENV_BIN" -i \\\n';
    const index = workflow.lastIndexOf(launch);
    expect(index).toBeGreaterThan(0);
    const mutant = `${workflow.slice(0, index)}          "$SANDBOX_EXEC" -f "$ROOT/deny-network.sb" "$ENV_BIN" -i \\\n${workflow.slice(index + launch.length)}`;
    expect(workflowErrors(mutant)).toContain("controller inside network boundary");
  });

  it("fails an arbitrary 64-hex profile authority", () => {
    const mutant = workflow.replaceAll(EXPECTED_PROFILE_SHA256, "0".repeat(64));
    expect(workflowErrors(mutant)).toContain("independent exact profile hash authorities");
  });

  it("fails zeroed attempt accounting", () => {
    const mutant = workflow.replace('"networkConnectAttemptsByAuditedPrograms": 11', '"networkConnectAttemptsByAuditedPrograms": 0');
    expect(workflowErrors(mutant)).toContain("truthful network attempt total");
  });

  it("fails an mDNS denial with no exact unconfined endpoint twin", () => {
    const mutant = workflow.replace(
      'mdns.connect("/private/var/run/mDNSResponder")',
      'results["mdnsUnixConnect"] = True',
    );
    expect(workflowErrors(mutant)).toContain("exact mDNS allow twin");
  });

  it("fails a Unix denial probe aimed at a nonexistent endpoint", () => {
    const mutant = workflow.replace(
      '"mdnsUnixConnect": denied(socket.AF_UNIX, socket.SOCK_STREAM, "/private/var/run/mDNSResponder", "connect")',
      '"mdnsUnixConnect": denied(socket.AF_UNIX, socket.SOCK_STREAM, os.path.join(root, "missing.sock"), "connect")',
    );
    expect(workflowErrors(mutant)).toContain("nonexistent Unix endpoint");
  });

  it("fails the Apple Python shim and an undeclared injected runtime key", () => {
    const shimMutant = workflow.replace(
      'readonly PYTHON="$(/usr/bin/xcrun --find python3)"',
      "readonly PYTHON='/usr/bin/python3'",
    );
    expect(workflowErrors(shimMutant)).toContain("real Python resolver");
    const environmentMutant = workflow.replaceAll(', "__CF_USER_TEXT_ENCODING"', "");
    expect(workflowErrors(environmentMutant)).toContain("Apple Python environment declaration");
  });

  it("keeps the liveness exemption truthful about the enforced outbound boundary", () => {
    const registry = JSON.parse(readFileSync(LIVENESS_PATH, "utf8")) as {
      exempt: { workflow: string; measures: string; whyDistinguishable: string }[];
    };
    const entry = registry.exempt.find(({ workflow: path }) => path.endsWith("issue-1799-hosted-preflight.yml"));
    expect(entry?.measures).toMatch(/Seatbelt deny-network.*TCP connect.*UDP sendto.*Unix\/mDNS.*unwrapped descendant/i);
    expect(entry?.whyDistinguishable).toMatch(/allow twins.*EPERM\/EACCES.*teardown/i);
  });
});
