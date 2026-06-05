// Test fixture for js-sql-string-concat (intentionally vulnerable snippets)

function getUserById(db, req, res) {
  // ruleid: js-sql-string-concat
  db.query("SELECT * FROM users WHERE id = " + req.query.id);
}

function getUserByName(db, req, res) {
  // ruleid: js-sql-string-concat
  db.execute(`SELECT * FROM users WHERE name = '${req.query.name}'`);
}

function getUserSafe(db, req, res) {
  // ok: js-sql-string-concat
  db.query("SELECT * FROM users WHERE id = ?", [req.query.id]);
}

function getAllUsers(db) {
  // ok: js-sql-string-concat
  db.query("SELECT * FROM users");
}
