// NOTE: circular import with ../utils/validate on purpose (tests cycle handling)
const { sanitize } = require("../utils/validate");

function findUser(username) {
  return query("SELECT * FROM users WHERE name = ?", [sanitize(username)]);
}

function createUser(payload) {
  return query("INSERT INTO users VALUES (?)", [sanitize(payload.username)]);
}

function allUsers() {
  return query("SELECT * FROM users", []);
}

function removeUser(id) {
  return query("DELETE FROM users WHERE id = ?", [id]);
}

function query(sql, params) {
  return { sql, params };
}

module.exports = { findUser, createUser, allUsers, removeUser };
