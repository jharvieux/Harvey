// #841: src/cli/lighthouse-scan.ts's launchChrome() used to fall through to the next Chrome
// candidate only when a candidate THREW while launching — a candidate that launched fine but then
// failed to measure anything (NO_FCP or any other Lighthouse runtimeError) kept that candidate
// instead of trying the next one. The fix wires each candidate's post-launch verification into the
// SAME failure path as a launch failure (see launchChrome's `attempt`), so this — generic,
// dependency-free — is the resulting fallthrough contract: a candidate's `attempt()` throwing for
// ANY reason abandons it in favor of the next one. Extracted so it's unit-testable without a real
// browser: a nested Chrome launch has proven unreliable to even exercise inside a sandboxed child
// process locally (the same class of issue #838 found with jscpd), so real-browser behavior stays
// untested per this file's existing convention — only lighthouse-scan.test.ts's #556 ENOENT case
// is a child-process test.

export interface ChromeCandidate<T> {
  label: string;
  attempt: () => Promise<T>;
}

// Tries each candidate in order, returning the first one whose attempt() resolves. Throws, naming
// the last candidate's failure, once every candidate is exhausted.
export async function tryChromeCandidates<T>(candidates: ChromeCandidate<T>[]): Promise<T> {
  let lastErr: Error = new Error("no Chrome candidate was reachable");
  for (const candidate of candidates) {
    try {
      return await candidate.attempt();
    } catch (err) {
      lastErr = err instanceof Error ? new Error(`${candidate.label}: ${err.message}`) : new Error(String(err));
    }
  }
  throw lastErr;
}
