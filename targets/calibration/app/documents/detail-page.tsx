import { admin } from "../../lib/supabaseAdmin";
import { DocumentCard } from "../../components/DocumentCard";

// PLANTED BUG (P-SERVER-CLIENT-LEAK): the full documents row (select('*')) is spread directly
// into a Client Component as props — every column (including any internal/sensitive ones, not
// just the two DocumentCard renders) serializes across the Server -> Client Component boundary
// in the RSC payload. Map to an explicit DTO with only the fields the client needs.
export default async function DocumentDetailPage({ id }: { id: string }) {
  const { data } = await admin.from("documents").select("*").eq("id", id);
  return <DocumentCard {...data} />;
}
