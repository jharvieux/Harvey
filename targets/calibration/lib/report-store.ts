// Shared stub for the #1184 verbose-error fixture pair (app/api/ar-debug-env{,-safe}/route.ts).
// Throws so both handlers reach their catch block; the only difference under test is what each one
// puts in the response.
export async function getReport(id: string | null): Promise<{ id: string }> {
  if (!id) throw new Error("report id is required");
  return { id };
}
