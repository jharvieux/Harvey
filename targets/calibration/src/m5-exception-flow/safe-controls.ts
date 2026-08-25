declare const telemetry: { captureException(error: unknown): void };
declare function loadOrder(): Promise<void>;
declare function rollbackOrder(error: unknown): Promise<void>;
declare function closeOptionalHandle(): void;

type Result<T> = { ok: true; value: T } | { ok: false; error: unknown };

export async function rationaleBearingIgnore(): Promise<void> {
  try {
    await loadOrder();
  } catch {
    // Intentionally ignored: best-effort cleanup is safe after the owner has gone away.
  }
}

export async function rationaleBearingTelemetry(): Promise<void> {
  try {
    await loadOrder();
  } catch (error) {
    // Telemetry only: this optional metric must not affect the completed operation.
    telemetry.captureException(error);
  }
}

export async function directRethrow(): Promise<void> {
  try {
    await loadOrder();
  } catch (error) {
    throw error;
  }
}

export async function wrappedRethrow(): Promise<void> {
  try {
    await loadOrder();
  } catch (error) {
    throw new Error("order load failed", { cause: error });
  }
}

export async function typedFailure(): Promise<Result<string>> {
  try {
    await loadOrder();
    return { ok: true, value: "ready" };
  } catch (error) {
    return { ok: false, error };
  }
}

export async function compensation(): Promise<void> {
  try {
    await loadOrder();
  } catch (error) {
    await rollbackOrder(error);
  }
}

export async function termination(): Promise<void> {
  try {
    await loadOrder();
  } catch (error) {
    console.error(error);
    process.exit(1);
  }
}

export async function cleanupOnly(): Promise<void> {
  try {
    await loadOrder();
  } catch {
    closeOptionalHandle();
  }
}

export async function nestedSafeCatch(): Promise<Result<void>> {
  try {
    await loadOrder();
    return { ok: true, value: undefined };
  } catch (outerError) {
    try {
      await rollbackOrder(outerError);
    } catch (rollbackError) {
      throw new Error("rollback failed", { cause: rollbackError });
    }
    return { ok: false, error: outerError };
  }
}
