// dead/dispatch.ts — knip entry point. Looks up a handler by a runtime
// string key; the handlerA reference is invisible to static analysis, which
// is exactly the M5-N-DYNAMIC-REF FP class this fixture exercises.
import { handlers } from "./registry";

export function dispatch(name: string): string {
  const fn = handlers[name];
  return fn ? fn() : "unknown";
}
