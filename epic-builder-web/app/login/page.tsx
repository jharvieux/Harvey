"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

export default function LoginPage() {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const router = useRouter();

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ password }),
    });
    if (res.ok) router.push("/");
    else setError("Incorrect password.");
  }

  return (
    <main>
      <h1>Epic Builder</h1>
      <p className="sub">Operator sign-in.</p>
      <form className="panel" onSubmit={submit}>
        <label htmlFor="pw">Password</label>
        <input id="pw" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus />
        {error && <p className="err">{error}</p>}
        <div className="row">
          <button type="submit">Sign in</button>
        </div>
      </form>
    </main>
  );
}
