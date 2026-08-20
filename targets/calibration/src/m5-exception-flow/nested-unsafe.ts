declare function loadOrder(): Promise<void>;

export async function nestedCatch(): Promise<void> {
  try {
    await loadOrder();
  } catch (outerError) {
    try {
      await loadOrder();
    } catch (innerError) {
    }
    await Promise.resolve(outerError);
  }
}
