import { admin } from "../lib/supabaseAdmin";

// PLANTED BUG (P-PUBLIC-BUCKET, #560): app seed/setup code creates a Supabase Storage bucket with
// public: true. A public bucket skips storage RLS for reads, so every object in "documents"
// (KYC/patient files on the vandyand teardown) is world-readable by URL. This is the static,
// source-only sibling of the connected-tier live checkPublicBucketsWithNoPolicies. harvey-public-bucket
// → review (High severity).
export async function seedStorage() {
  await admin.storage.createBucket("documents", { public: true });
}
