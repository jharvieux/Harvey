import { supabase } from "../db/supabase";
import { auth } from "../auth";

// OWASP Multi-Tenant CS section 6: "Use tenant-prefixed paths for file storage" and "Validate
// tenant ownership before serving files". The object path is the caller-supplied filename alone, so
// one tenant writes over -- and reads -- another tenant's objects in a shared bucket.

export async function uploadAttachment(file: File, filename: string) {
  return supabase.storage.from("attachments").upload(filename, file);
}

export async function downloadAttachment(filename: string) {
  return supabase.storage.from("attachments").download(filename);
}

// #1198 negative -- the correct form. The path is prefixed with the tenant id off the verified
// session, so one tenant's objects cannot collide with another's in the shared bucket.
export async function uploadAttachmentScoped(file: File, filename: string) {
  const session = await auth();
  const path = `${session.user.tenantId}/${filename}`;
  return supabase.storage.from("attachments").upload(path, file);
}
