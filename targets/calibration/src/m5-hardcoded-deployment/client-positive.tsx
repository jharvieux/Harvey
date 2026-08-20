"use client";

export const telemetryClient = createTelemetryClient({
  endpoint: "https://telemetry.prod.harvey-platform.com/ingest",
});
