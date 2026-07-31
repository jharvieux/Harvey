// #1544 support file for job-queue.ts — the scheduler's own configuration, read from the database.
export interface JobRow {
  script: string;
  logfile: string;
  archive: string;
}

export const params: JobRow = { script: "nightly.sh", logfile: "nightly.log", archive: "nightly" };

export const defaultRetention = "30d";

export function loadQueue(): [JobRow, ...JobRow[]] {
  return [params];
}
