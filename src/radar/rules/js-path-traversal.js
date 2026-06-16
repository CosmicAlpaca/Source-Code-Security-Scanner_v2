const express = require('express');
const fs = require('fs');
const path = require('path');
const router = express.Router();

router.get('/file', (req, res) => {
  const filename = req.query.name;
  // ruleid: js-path-traversal
  fs.readFile(filename, 'utf8', (err, data) => res.send(data));
});

router.post('/upload', (req, res) => {
  const dest = req.body.path;
  const content = req.body.content;
  // ruleid: js-path-traversal
  fs.writeFile(dest, content, () => res.send('ok'));
});

// ok: js-path-traversal
fs.readFile('/var/app/static/index.html', 'utf8', (err, data) => {});
