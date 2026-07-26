// PLANTED (#1136): a real, hand-authored source file that carries exactly ONE very long line — an
// LLM tool-description string literal, the same shape that dropped a genuine M6 finding from
// inbox-zero's apps/web/utils/ai/assistant/tools/rules/update-rule-tool.ts under the pre-#1136
// isGeneratedSource heuristic ("any line over 1000 chars" excluded the whole file). This file must
// stay IN SCOPE: it is ordinary code with one long aside, not a minified/generated bundle. It plants
// a hand-rolled JSON.stringify(a) === JSON.stringify(b) deep-equal check (P-M6-LONGLINE-JSONEQ)
// so a real M6 "JSON deep-equal" indicator finding is the regression signal — if this heuristic
// regresses to the old behaviour, the whole file (and this finding) silently drops out of every
// loadSources-based module again, and the committed dry-run artifact moves.

export interface RuleCondition {
  from?: string;
  subject?: string;
  body?: string;
}

export interface RuleAction {
  type: "archive" | "label" | "forward" | "reply";
  label?: string;
  forwardTo?: string;
}

export interface RuleDefinition {
  id: string;
  name: string;
  condition: RuleCondition;
  actions: RuleAction[];
  enabled: boolean;
}

function normalizeCondition(condition: RuleCondition): RuleCondition {
  return {
    from: condition.from?.trim().toLowerCase(),
    subject: condition.subject?.trim(),
    body: condition.body?.trim(),
  };
}

function normalizeActions(actions: RuleAction[]): RuleAction[] {
  return actions.map((a) => ({ ...a, label: a.label?.trim() }));
}

// P-M6-LONGLINE-JSONEQ: deep-equal via JSON string comparison. Key order and undefined/function
// values change the serialized string even when the two rules are semantically identical, so this
// is a real "looks hand-rolled" M6 indicator, unrelated to the long string literal below.
export function hasRuleChanged(before: RuleDefinition, after: RuleDefinition): boolean {
  const beforeNormalized = {
    condition: normalizeCondition(before.condition),
    actions: normalizeActions(before.actions),
    enabled: before.enabled,
  };
  const afterNormalized = {
    condition: normalizeCondition(after.condition),
    actions: normalizeActions(after.actions),
    enabled: after.enabled,
  };
  return JSON.stringify(beforeNormalized) !== JSON.stringify(afterNormalized);
}

export function describeRuleChange(before: RuleDefinition, after: RuleDefinition): string {
  if (!hasRuleChanged(before, after)) return "no change";
  if (before.enabled !== after.enabled) return after.enabled ? "enabled" : "disabled";
  return "condition or actions updated";
}

export function findRuleById(rules: RuleDefinition[], id: string): RuleDefinition | undefined {
  return rules.find((r) => r.id === id);
}

export function upsertRule(rules: RuleDefinition[], rule: RuleDefinition): RuleDefinition[] {
  const index = rules.findIndex((r) => r.id === rule.id);
  if (index === -1) return [...rules, rule];
  const next = rules.slice();
  next[index] = rule;
  return next;
}

export function disableRule(rules: RuleDefinition[], id: string): RuleDefinition[] {
  return rules.map((r) => (r.id === id ? { ...r, enabled: false } : r));
}

export function rulesForSender(rules: RuleDefinition[], from: string): RuleDefinition[] {
  const lower = from.trim().toLowerCase();
  return rules.filter((r) => r.enabled && r.condition.from?.toLowerCase() === lower);
}

export function summarizeActions(actions: RuleAction[]): string {
  return actions.map((a) => a.type).join(", ");
}

export function validateRuleDefinition(rule: RuleDefinition): string[] {
  const errors: string[] = [];
  if (!rule.name.trim()) errors.push("name is required");
  if (rule.actions.length === 0) errors.push("at least one action is required");
  for (const action of rule.actions) {
    if (action.type === "label" && !action.label) errors.push("label action requires a label");
    if (action.type === "forward" && !action.forwardTo) errors.push("forward action requires forwardTo");
  }
  return errors;
}

// The long line the false-exclusion is about: a single tool-description string literal handed to
// the LLM tool-calling API, the exact shape #1136 measured in inbox-zero's update-rule-tool.ts.
export const UPDATE_RULE_TOOL_DESCRIPTION = "Update an existing email rule's condition and actions. Use this when the user wants to change how an existing rule matches incoming email or what happens when it matches — for example narrowing a sender condition, adding a forward action, renaming the rule, or disabling it entirely. Always pass the full updated condition and full updated action list, not a partial patch, because the underlying store replaces the rule wholesale rather than merging fields; omitting a field the user did not mention will silently clear it. If the user only wants to toggle whether the rule is active, prefer the dedicated enable/disable tool instead of round-tripping the whole definition through this one, since that tool is cheaper and less error-prone for that single case. Do not call this tool speculatively to preview what a change would look like — it applies the update immediately and there is no separate dry-run mode, so confirm the intended condition and action list with the user first when the request is ambiguous, and never guess at a forwardTo address or label name that was not stated explicitly somewhere in the conversation.";

export function toolDescriptionLength(): number {
  return UPDATE_RULE_TOOL_DESCRIPTION.length;
}
