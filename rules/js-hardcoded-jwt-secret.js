// Test fixture for js-hardcoded-jwt-secret (intentionally vulnerable snippets)
const jwt = require("jsonwebtoken");

function issueToken(user) {
  // ruleid: js-hardcoded-jwt-secret
  return jwt.sign({ id: user.id }, "fake-jwt-secret-for-demo");
}

function checkToken(token) {
  // ruleid: js-hardcoded-jwt-secret
  return jwt.verify(token, "fake-jwt-secret-for-demo");
}

function issueTokenSafe(user) {
  // ok: js-hardcoded-jwt-secret
  return jwt.sign({ id: user.id }, process.env.JWT_SECRET);
}
