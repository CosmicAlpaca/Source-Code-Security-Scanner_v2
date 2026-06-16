const express = require('express');
const axios = require('axios');
const https = require('https');
const router = express.Router();

// ruleid: js-ssrf-user-input
router.get('/proxy', async (req, res) => {
  const target = req.query.url;
  const response = await fetch(target);
  res.send(await response.text());
});

// ruleid: js-ssrf-user-input
router.post('/fetch', async (req, res) => {
  const data = await axios.get(req.body.endpoint);
  res.json(data.data);
});

// ok: js-ssrf-user-input
router.get('/safe', async (req, res) => {
  const response = await fetch('https://api.example.com/data');
  res.json(await response.json());
});
