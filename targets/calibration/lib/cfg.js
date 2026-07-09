// N-EVAL-JSON (NEGATIVE — must NOT be flagged): the request body is parsed as DATA with
// JSON.parse, not evaluated as code. JSON.parse cannot execute the input, so there is no code
// injection. The eval rule must fire only on eval()/new Function().
export default function handler(req, res) {
  let parsed;
  try {
    parsed = JSON.parse(req.body);
  } catch {
    return res.status(400).json({ error: "invalid JSON" });
  }
  res.status(200).json({ keys: Object.keys(parsed) });
}
