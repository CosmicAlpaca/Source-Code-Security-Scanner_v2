// Demo edit target: change validateUser in a PR and watch the blast radius.
function validateUser(payload) {
  if (!payload || !payload.username || !payload.password) {
    return false;
  }
  return payload.username.length >= 3 && payload.password.length >= 8;
}

function sanitize(value) {
  return String(value).replace(/['";]/g, "");
}

module.exports = { validateUser, sanitize };
