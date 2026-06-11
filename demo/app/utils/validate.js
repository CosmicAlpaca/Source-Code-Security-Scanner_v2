// Demo edit target: change validateUser in a PR and watch the blast radius.
function validateUser(payload) {
  if (!payload || !payload.username) {
    return false;
  }
  return payload.username.length >= 3;
}

function sanitize(value) {
  return String(value).replace(/['";]/g, "");
}

module.exports = { validateUser, sanitize };
