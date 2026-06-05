const { Router } = require("express");
const db = require("../services/db");

const router = Router();

function getUser(req, res) {
  res.json(db.findUserById(req.params.id));
}

function listUsers(req, res) {
  res.json(db.allUsers());
}

router.get("/users/:id", getUser);
router.get("/users", listUsers);

module.exports = router;
