const express = require("express");
const SessionHandler = require("./session");

const app = express();
const db = {};
const sessionHandler = new SessionHandler(db);

// Routes reference the handler as `instance.method` (member expression).
app.get("/login", sessionHandler.displayLogin);
app.post("/login", sessionHandler.handleLogin);

module.exports = app;
