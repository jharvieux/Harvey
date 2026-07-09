import { unserialize } from "node-serialize";

// PLANTED BUG (P-INSECURE-DESERIALIZE): the request body is deserialized with node-serialize's
// unserialize(), which executes an embedded IIFE function body — remote code execution. Review
// tier. e.g. data = '{"x":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(...)}()"}'
export default function handler(req, res) {
  const obj = unserialize(req.body.data);
  res.status(200).json({ keys: Object.keys(obj) });
}
