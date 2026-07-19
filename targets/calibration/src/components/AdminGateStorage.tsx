// PLANTED BUG (P-CLIENT-AUTHZ-STORAGE, #576): the admin gate is a role read from Web Storage —
// user-editable — compared to a privilege literal in the browser. Anyone can set
// localStorage.role = "admin" in DevTools and unlock the admin controls; the real gate must be an
// RLS policy / a server route that re-checks the verified session. leftover-auth's client-side-authz
// heuristic → review. This is nocode-rescue's client-side-authz half.
export function AdminPanel() {
  const role = localStorage.getItem("role");
  if (role === "admin") {
    return <AdminControls />;
  }
  return <p>Members only</p>;
}
