const { Router } = require("express");
const { validateUser } = require("../utils/validate");
const db = require("../services/db");

const router = Router();

function login(req, res) {
  if (!validateUser(req.body)) {
    return res.status(400).end();
  }
  const user = db.findUser(req.body.username);
  res.json(user);
}

function register(req, res) {
  if (!validateUser(req.body)) {
    return res.status(400).end();
  }
  db.createUser(req.body);
  res.status(201).end();
}

router.post("/login", login);
router.post("/register", register);

module.exports = router;
