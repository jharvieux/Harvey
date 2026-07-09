// PLANTED BUG (P-SRV-ROLE-IN-BUNDLE): a service_role JWT that leaked into a built client bundle
// chunk (what `next build` would emit into .next/static and ship to the browser). This is a
// committed pre-built fixture (the calibration harness does not run `next build`); the source
// secret scan reads it like any file and the decoded "role":"service_role" claim fires the
// supabase-service-role-jwt rule → high. A leaked service-role key in browser-shipped JS is a
// full RLS bypass exposed to every visitor. Value is FAKE (same fake token as lib/admin.js).
(self.__NEXT_P=self.__NEXT_P||[]).push([2107,{4411:function(e,t,n){t.k="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImNhbGlicmF0aW9ucmVmMDEiLCJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjIwMDAwMDAwMDB9.Rm3kL9pQ2vXcW8rNpKdLhGfYsAe4Uo1Bx6Vt0Zi7Ny"}}]);
