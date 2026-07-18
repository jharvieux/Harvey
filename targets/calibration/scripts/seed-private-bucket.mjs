import { admin } from "../lib/supabaseAdmin";

// TRUE NEGATIVE (N-PRIVATE-BUCKET, #560): the same createBucket call, but private (public: false)
// with a size limit. A private bucket enforces storage RLS, so it is not a public-exposure defect.
// harvey-public-bucket's { public: true } pattern must not match public: false — must clear.
export async function seedStorage() {
  await admin.storage.createBucket("documents", { public: false, fileSizeLimit: "5mb" });
}
