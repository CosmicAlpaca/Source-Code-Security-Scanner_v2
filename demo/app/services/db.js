// ⚠️ INTENTIONALLY VULNERABLE — SQL injection (custom rule: js-sql-string-concat)
const { sanitize } = require("../utils/validate");

const pool = { query: (sql) => ({ sql }) };

function findUser(username) {
  // VULN: SQL built by string concatenation
  return pool.query("SELECT * FROM users WHERE name = '" + username + "'");
}

function findUserById(id) {
  // VULN: SQL built by template interpolation
  return pool.query(`SELECT * FROM users WHERE id = ${id}`);
}

function createUser(payload) {
  return pool.query("INSERT INTO users (name) VALUES (?)", [sanitize(payload.username)]);
}

function allUsers() {
  return pool.query("SELECT * FROM users");
}

module.exports = { findUser, findUserById, createUser, allUsers };
