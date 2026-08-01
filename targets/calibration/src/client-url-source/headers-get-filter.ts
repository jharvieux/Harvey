// #1708 NEGATIVE (N-CLIENT-URL-HEADERS-GET). A Headers object a background worker assembles for
// its OWN outbound calls, read into a PostgREST string filter. `Headers.get()` is the second
// receiver base.yml's canonical block names as firing under a bare `$SP.get(...)`, and this pairs
// it with the second of the three sinks #1708 widened (.or/.filter/.textSearch). Nothing in this
// module is request-derived: the header bag is constructed from a literal on the line above.
declare const serviceClient: {
  from(table: string): { select(cols: string): { or(filter: string): Promise<unknown> } };
};

export async function sweepStaleJobs() {
  const workerHeaders = new Headers({ "x-worker-lane": "nightly" });
  const lane = workerHeaders.get("x-worker-lane");
  return serviceClient.from("jobs").select("id").or(`lane.eq.${lane},lane.is.null`);
}
