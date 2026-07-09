// PLANTED BUG (P-VERBOSE-ERROR): the caught error's stack trace is echoed straight into the
// JSON response — leaks file paths, library internals, and code structure to the client.
export default async function handler(req, res) {
  try {
    await doWork(req.body);
    res.status(200).json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, stack: err.stack });
  }
}
