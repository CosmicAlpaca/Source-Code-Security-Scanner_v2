const express = require('express');
const axios = require('axios');
const router = express.Router();

// Case 1: fetch with user-controlled URL
router.get('/proxy', async (req, res) => {
  const target = req.query.url;
  // ruleid: js-ssrf-user-input
  const response = await fetch(target);
  res.send(await response.text());
});

// Case 2: axios with user-controlled endpoint
router.post('/fetch', async (req, res) => {
  const endpoint = req.body.endpoint;
  // ruleid: js-ssrf-user-input
  const data = await axios.get(endpoint);
  res.json(data.data);
});

// ok: js-ssrf-user-input
const data = await fetch('https://trusted-internal-api.local/data');
