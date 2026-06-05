// ⚠️ INTENTIONALLY VULNERABLE demo app — never deploy. See demo/run-demo.md.
const express = require("express");
const authRoutes = require("./routes/auth");
const userRoutes = require("./routes/users");
const toolRoutes = require("./routes/tools");

const app = express();
app.use(express.json());

app.use("/api", authRoutes);
app.use("/api", userRoutes);
app.use("/api", toolRoutes);

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

module.exports = app;
