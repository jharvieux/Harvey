// dead/registry.ts — PLANTED NEGATIVE (M5-N-DYNAMIC-REF): handlerA is looked
// up by string key at runtime (dead/dispatch.ts's handlers[name]), so static
// analysis can't see the reference. Tagged @lintignore; knip.json's
// tags:["-lintignore"] marks it as a known-dynamic export — must not be
// flagged.

/** @lintignore referenced only via handlers[name] string lookup, see dead/dispatch.ts */
export function handlerA(): string {
  return "handler-a";
}

export const handlers: Record<string, () => string> = {
  handlerA,
};
