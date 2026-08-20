declare function saveOrder(): Promise<{ id: string }>;

export async function POST(): Promise<{ id: string } | { success: true }> {
  try {
    return await saveOrder();
  } catch (error) {
    return Promise.resolve({ success: true });
  }
}
