// OWASP React Security CS (draft), Sensitive Data Exposure: "Keep Sensitive Data Out of URLs".
// A router navigation carrying the reset token puts it in browser history, the Referer header of
// every subsequent third-party request, and any proxy or analytics access log on the path.

import { useNavigate } from "react-router-dom";

export function useResetRedirect() {
  const navigate = useNavigate();
  return (passwordResetToken: string) => {
    navigate(`/reset?token=${passwordResetToken}`);
  };
}

export function useResetRedirectSafe() {
  const navigate = useNavigate();
  return (passwordResetToken: string) => {
    sessionStorage.setItem("pendingReset", passwordResetToken);
    navigate("/reset");
  };
}
