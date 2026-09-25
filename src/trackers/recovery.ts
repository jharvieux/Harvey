import type { CreatedRef } from "./types.js";

// Preserve a successful remote creation even when a later operation fails.
export class PartialTrackerWriteError extends Error {
  constructor(readonly ref: CreatedRef, readonly stage: string, cause: unknown) {
    super(`${stage} failed after ticket ${ref.id} was created: ${cause instanceof Error ? cause.message : String(cause)}`);
    this.name = "PartialTrackerWriteError";
  }
}
