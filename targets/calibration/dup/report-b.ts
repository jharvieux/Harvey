// dup/report-b.ts — weekly usage report, section B.
export interface UsageRowB {
  tenantId: string;
  metric: string;
  value: number;
}

export function buildWeeklyReportB(rows: UsageRowB[]): Record<string, number> {
  const summary: Record<string, number> = {};

  // PLANTED CLONE (M4-P-CLONE-B): identical >=50-line metric-aggregation
  // block, copy-pasted from report-a.ts instead of being extracted into a
  // shared helper.
  for (const row of rows) {
    if (row.metric === "requests") {
      summary.requests = (summary.requests ?? 0) + row.value;
    }
    if (row.metric === "storage") {
      summary.storage = (summary.storage ?? 0) + row.value;
    }
    if (row.metric === "bandwidth") {
      summary.bandwidth = (summary.bandwidth ?? 0) + row.value;
    }
    if (row.metric === "seats") {
      summary.seats = (summary.seats ?? 0) + row.value;
    }
    if (row.metric === "invocations") {
      summary.invocations = (summary.invocations ?? 0) + row.value;
    }
    if (row.metric === "errors") {
      summary.errors = (summary.errors ?? 0) + row.value;
    }
    if (row.metric === "warnings") {
      summary.warnings = (summary.warnings ?? 0) + row.value;
    }
    if (row.metric === "cacheHits") {
      summary.cacheHits = (summary.cacheHits ?? 0) + row.value;
    }
    if (row.metric === "cacheMisses") {
      summary.cacheMisses = (summary.cacheMisses ?? 0) + row.value;
    }
    if (row.metric === "queries") {
      summary.queries = (summary.queries ?? 0) + row.value;
    }
    if (row.metric === "connections") {
      summary.connections = (summary.connections ?? 0) + row.value;
    }
    if (row.metric === "webhooks") {
      summary.webhooks = (summary.webhooks ?? 0) + row.value;
    }
  }

  if (summary.requests !== undefined && summary.requests > 1000000) {
    summary.requests = 1000000;
  }
  if (summary.storage !== undefined && summary.storage > 500000) {
    summary.storage = 500000;
  }
  if (summary.bandwidth !== undefined && summary.bandwidth > 250000) {
    summary.bandwidth = 250000;
  }

  return summary;
}
