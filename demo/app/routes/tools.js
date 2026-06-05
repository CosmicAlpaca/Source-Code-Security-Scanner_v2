// ⚠️ INTENTIONALLY VULNERABLE — command injection (custom rule: js-child-process-user-input)
const { Router } = require("express");
const { exec } = require("child_process");

const router = Router();

function ping(req, res) {
  const host = req.query.host;
  // VULN: user input flows into exec
  exec("ping -c 1 " + host, (err, stdout) => {
    res.send(stdout);
  });
}

router.get("/ping", ping);

module.exports = router;
