// NEGATIVE (N-PLATFORM-HEADER-SINK, #1295): the tainted value is `x-real-ip`, a header whose
// canonical producer is the reverse proxy in front of the app. Whether a client's own copy survives
// to the application is a deployment-topology question this scan does not see, so #984's guardrail
// says this must land at REVIEW tier and must NOT enter the free count. It was ERROR + HIGH
// (free-count) until #1295 built the routing that guardrail assumed.
const { exec } = require("child_process");

module.exports = function lookupCountry(req, res) {
  const ip = req.headers["x-real-ip"];
  exec(`geoiplookup ${ip}`, (e, out) => res.end(out));
};
