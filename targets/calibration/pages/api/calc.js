// PLANTED BUG (P-EVAL-CODE-INJ): the request body is passed straight to eval() — arbitrary code
// execution in the server process. e.g. expr="process.mainModule.require('child_process').exec(...)"
export default function handler(req, res) {
  const { expr } = req.body;

  const result = eval(expr);

  res.status(200).json({ result });
}
