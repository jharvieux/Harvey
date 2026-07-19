import { useNavigate } from "react-router-dom";

// PLANTED BUG (P-CLIENT-AUTHZ-USER, #576): navigation to the admin view is gated on the user object's
// role field in client code — bypassable by patching the bundle or the in-memory user object. The
// data behind /admin is still fetched with the client's own key; the gate protects nothing. The real
// enforcement must be RLS/server. leftover-auth's client-side-authz heuristic → review.
export function AdminRoute({ user }) {
  const navigate = useNavigate();
  if (user.user_metadata.role !== "admin") {
    return null;
  }
  navigate("/admin");
  return <AdminControls />;
}
