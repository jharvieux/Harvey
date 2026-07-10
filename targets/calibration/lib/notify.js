// PLANTED BUG (P-SLACK-WEBHOOK-URL): a Slack workflow-webhook URL committed in source. The
// hooks.slack.com/workflows/… shape is unambiguous — anyone with the URL can trigger the
// workflow it targets. Value is FAKE (the /workflows/ path, vs the /services/ incoming-webhook
// shape, keeps the fixture inert to GitHub push protection while gitleaks slack-webhook-url —
// which matches any hooks.slack.com/{services,workflows,triggers}/ path — still fires → high).
const SLACK_WEBHOOK = "https://hooks.slack.com/workflows/T0FAKE000/A0FAKE000/000000000000000000/FAKExXxXxXxXxXxX";

// NEGATIVE (N-SLACK-WEBHOOK-PLACEHOLDER): a documentation placeholder, not a real webhook token —
// the token segments are angle-bracketed, so the gitleaks pattern (which needs a 43+ char path)
// does not match. Cleared.
const SLACK_WEBHOOK_TEMPLATE = "https://hooks.slack.com/workflows/<TEAM_ID>/<WORKFLOW_ID>/<STEP_ID>/<WEBHOOK_TOKEN>";

export function notifiers() {
  return { primary: SLACK_WEBHOOK, template: SLACK_WEBHOOK_TEMPLATE };
}
