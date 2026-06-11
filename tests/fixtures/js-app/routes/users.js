const { Router } = require("express");
const db = require("../services/db");

const router = Router();

const listUsers = (req, res) => {
  res.json(db.allUsers());
};

router.get("/users", listUsers);

router.delete("/users/:id", (req, res) => {
  db.removeUser(req.params.id);
  res.status(204).end();
});

module.exports = router;
