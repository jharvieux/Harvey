import { redirect } from "next/navigation";
import { isAuthenticated } from "../lib/auth.js";
import Wizard from "./wizard.js";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export default async function Home() {
  if (!(await isAuthenticated())) redirect("/login");
  return <Wizard />;
}
