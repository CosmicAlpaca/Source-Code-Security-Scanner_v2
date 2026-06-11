// ⚠️ INTENTIONALLY VULNERABLE — hardcoded JWT secret (custom rule: js-hardcoded-jwt-secret)
const { Router } = require("express");
const jwt = require("jsonwebtoken");
const { validateUser } = require("../utils/validate");
const db = require("../services/db");

const router = Router();

function login(req, res) {
  if (!validateUser(req.body)) {
    return res.status(400).json({ error: "invalid credentials" });
  }
  const user = db.findUser(req.body.username);
  // VULN: hardcoded JWT secret
  const token = jwt.sign({ id: user.id }, "fake-jwt-secret-for-demo");
  res.json({ token });
}

function register(req, res) {
  if (!validateUser(req.body)) {
    return res.status(400).json({ error: "invalid payload" });
  }
  db.createUser(req.body);
  res.status(201).end();
}

router.post("/login", login);
router.post("/register", register);

module.exports = router;
