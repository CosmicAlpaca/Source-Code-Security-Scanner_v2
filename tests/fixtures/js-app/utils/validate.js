// NOTE: circular import with ../services/db on purpose (tests cycle handling)
const db = require("../services/db");

function validateUser(payload) {
  if (!payload || !payload.username) {
    return false;
  }
  return !db.findUser(payload.username).locked;
}

function sanitize(value) {
  return String(value).replace(/['";]/g, "");
}

module.exports = { validateUser, sanitize };
