const express = require('express');
const router = express.Router();

router.get('/redirect', (req, res) => {
  const target = req.query.url;
  // ruleid: js-open-redirect
  res.redirect(target);
});

router.get('/go', (req, res) => {
  const next = req.query.next;
  // ruleid: js-open-redirect
  res.redirect(302, next);
});

// ok: js-open-redirect
res.redirect('/dashboard');
