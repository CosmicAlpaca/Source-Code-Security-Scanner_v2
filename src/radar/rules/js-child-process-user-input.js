// Test fixture for js-child-process-user-input (intentionally vulnerable snippets)
const { exec, execSync } = require("child_process");

function pingHost(req, res) {
  const host = req.query.host;
  // ruleid: js-child-process-user-input
  exec("ping -c 1 " + host, (err, out) => res.send(out));
}

function traceRoute(req, res) {
  // ruleid: js-child-process-user-input
  execSync(`traceroute ${req.body.target}`);
}

function pingFixed(req, res) {
  // ok: js-child-process-user-input
  exec("ping -c 1 127.0.0.1", (err, out) => res.send(out));
}
