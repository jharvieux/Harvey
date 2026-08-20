declare function readSession(): Promise<string>;

export async function requireSession(): Promise<string | undefined> {
  try {
    return await readSession();
  } catch (error) {
  }
}
