import { supabase } from "../db/supabase";

// OWASP Multi-Tenant CS section 6: "Use tenant-prefixed paths for file storage" and "Validate
// tenant ownership before serving files". The object path is the caller-supplied filename alone, so
// one tenant writes over -- and reads -- another tenant's objects in a shared bucket.

export async function uploadAttachment(file: File, filename: string) {
  return supabase.storage.from("attachments").upload(filename, file);
}

export async function downloadAttachment(filename: string) {
  return supabase.storage.from("attachments").download(filename);
}
