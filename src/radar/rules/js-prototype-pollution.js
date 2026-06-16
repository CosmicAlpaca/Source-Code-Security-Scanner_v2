const _ = require('lodash');
const express = require('express');
const router = express.Router();

router.post('/settings', (req, res) => {
  const config = {};
  // ruleid: js-prototype-pollution
  Object.assign(config, req.body);
  res.json(config);
});

router.post('/merge', (req, res) => {
  const defaults = { role: 'user' };
  // ruleid: js-prototype-pollution
  _.merge(defaults, req.body);
  res.json(defaults);
});

// ok: js-prototype-pollution
Object.assign({}, { name: 'static', value: 42 });
