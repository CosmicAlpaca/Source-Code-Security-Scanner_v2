const express = require('express');
const router = express.Router();

router.post('/calculate', (req, res) => {
  const expr = req.body.expression;
  // ruleid: js-eval-user-input
  const result = eval(expr);
  res.json({ result });
});

router.get('/run', (req, res) => {
  const code = req.query.code;
  // ruleid: js-eval-user-input
  const fn = new Function(code);
  res.json({ result: fn() });
});

// ok: js-eval-user-input
const safe = eval('1 + 1');
