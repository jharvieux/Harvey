declare function loadOrder(): Promise<void>;
declare function logError(error: unknown): void;

export async function emptyCatch(): Promise<void> {
  try {
    await loadOrder();
  } catch (error) {
  }
}

export async function logAndContinue(): Promise<string> {
  try {
    await loadOrder();
  } catch (error) {
    const message = "order load failed";
    logError(error);
    console.warn(message);
  }
  return "ready";
}

export async function failureLooksLikeSuccess(): Promise<null | { id: string }> {
  try {
    await loadOrder();
    return { id: "order-1" };
  } catch (error) {
    return null;
  }
}
