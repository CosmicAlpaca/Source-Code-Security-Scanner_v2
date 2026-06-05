const express = require("express");
const authRoutes = require("./routes/auth");
const userRoutes = require("./routes/users");

const app = express();

app.use("/api", authRoutes);
app.use("/api", userRoutes);

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

module.exports = app;
