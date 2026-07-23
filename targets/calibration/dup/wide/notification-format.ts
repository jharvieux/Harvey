// dup/wide/notification-format.ts — PLANTED WHOLE-REPO NEGATIVE (M4-N-DIVERGED-WIDE-DISTINCT,
// #809): an independently-written function of similar token mass to buildExportJobConfig
// (export-config-a/b.ts) but a structurally distinct shape (loop + string building, not an
// object-literal config). The whole-repo near-miss pass must not pair this with anything —
// "similar size" alone is not "diverged clone".
export interface NotificationEvent {
  actor: string;
  action: string;
  at: number;
}

export function formatNotificationDigest(events: NotificationEvent[], limit: number): string[] {
  const lines: string[] = [];
  for (const event of events) {
    if (lines.length >= limit) break;
    lines.push(`${event.actor} ${event.action} at ${String(event.at)}`);
  }
  if (lines.length === 0) {
    lines.push("no recent activity");
  }
  return lines;
}
