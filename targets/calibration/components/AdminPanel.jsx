"use client";
import { createClient } from "@supabase/supabase-js";

// PLANTED BUG (P-SRV-KEY-CLIENT): a Client Component ("use client") that builds its
// own service-role client. The SERVICE_ROLE_KEY is inlined into a module that ships to
// the browser bundle — full RLS bypass for anyone who opens devtools. The correct place
// for the service-role key is a server-only module (see lib/supabaseAdmin.js, lib/cron.js).
const admin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
);

export default function AdminPanel({ rows }) {
  return (
    <ul>
      {rows.map((r) => (
        <li key={r.id}>{r.name}</li>
      ))}
    </ul>
  );
}
