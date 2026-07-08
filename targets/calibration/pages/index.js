export default function Home() {
  return (
    <main style={{ fontFamily: "system-ui", maxWidth: 640, margin: "3rem auto", padding: "0 1rem" }}>
      <h1>Calibration target</h1>
      <p style={{ color: "#b00", fontWeight: 600 }}>
        INTENTIONALLY VULNERABLE. Do not deploy or expose this app. It exists only as
        controlled ground truth for the Harvey audit scanner. See GROUND-TRUTH.md.
      </p>
      <h2>Planted-bug routes</h2>
      <ul>
        <li><code>GET  /api/search?q=</code> — SQL injection (service DB connection)</li>
        <li><code>POST /api/webhook</code> — signed webhook, no replay protection</li>
        <li><code>POST /api/counter/increment</code> — read-modify-write race</li>
        <li><code>POST /api/profile/update</code> — unscoped .update() (cross-tenant)</li>
        <li><code>GET  /api/redirect?url=</code> — open redirect</li>
      </ul>
      <p>RLS bugs live in <code>supabase/migrations/20260708000002_rls.sql</code>.</p>
    </main>
  );
}
