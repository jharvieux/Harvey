import { admin } from "../../lib/supabaseAdmin";
import { DocumentCard } from "../../components/DocumentCard";

// TRUE NEGATIVE (N-DTO-MAPPED): only an explicit DTO (two named fields) reaches the Client
// Component, not the raw select('*') row — harvey-server-client-leak's sink pattern requires a
// {...$DATA} spread of the destructured select('*') result; a picked object literal is a
// different (safe) shape and does not match.
export default async function DocumentDetailPageSafe({ id }: { id: string }) {
  const { data } = await admin.from("documents").select("*").eq("id", id);
  return <DocumentCard title={data.title} updated_at={data.updated_at} />;
}
