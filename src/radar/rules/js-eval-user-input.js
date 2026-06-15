const express = require('express');
const router = express.Router();

// ruleid: js-eval-user-input
router.post('/calculate', (req, res) => {
  const expr = req.body.expression;
  const result = eval(expr);
  res.json({ result });
});

// ruleid: js-eval-user-input
router.get('/run', (req, res) => {
  const code = req.query.code;
  const fn = new Function(code);
  res.send(fn());
});

// ok: js-eval-user-input
router.post('/parse', (req, res) => {
  const data = JSON.parse(req.body.json);
  res.json(data);
});
