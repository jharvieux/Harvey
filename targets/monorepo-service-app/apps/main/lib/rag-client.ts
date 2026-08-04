export async function retrieve() {
  return fetch(`${process.env.RAG_SERVICE_URL}/api/retrieve`);
}
