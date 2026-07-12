// N-SB-DEMO-KEY-BEARER (NEGATIVE — must NOT be flagged in the free count): the fixed public
// Supabase local-dev demo service_role key inlined as a literal Bearer token in a smoke-test
// script, modeling the "anon-key equivalent" FP from #210 — harvey-http-authorization-bearer
// matches any 24+ char literal after "Bearer", including this one (the literal must sit inline
// on the line, not behind a variable reference, for that rule to match at all). The
// supabase-demo-key-marker correlation (same file+line) clears it here, same as the seed.sql
// occurrence.
export async function checkLocalStack(baseUrl) {
  const res = await fetch(`${baseUrl}/rest/v1/`, {
    headers: {
      Authorization:
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_FAKE",
    },
  });
  return res.ok;
}
