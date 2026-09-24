import { performance } from "node:perf_hooks";
import {
  validateEffectivenessDelivery,
  validateEffectivenessInventory,
} from "../../effectiveness-registry.ts";

// This process never builds an inventory. Its first request must independently
// discover source evidence for the exact census inventory supplied by the test.
process.on("message", (request) => {
  const started = performance.now();
  try {
    const problems = request.kind === "inventory"
      ? validateEffectivenessInventory(request.inventory, request.options)
      : validateEffectivenessDelivery(request.inventory, request.delivered);
    process.send({ id: request.id, problems, elapsedMs: performance.now() - started, pid: process.pid });
  } catch (error) {
    process.send({ id: request.id, error: error instanceof Error ? error.stack : String(error) });
  }
});

process.on("disconnect", () => process.exit(0));
