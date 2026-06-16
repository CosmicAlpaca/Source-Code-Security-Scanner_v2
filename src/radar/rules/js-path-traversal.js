const express = require('express');
const fs = require('fs');
const path = require('path');
const router = express.Router();

// ruleid: js-path-traversal
router.get('/file', (req, res) => {
  const filename = req.query.name;
  fs.readFile(filename, 'utf8', (err, data) => {
    res.send(data);
  });
});

// ruleid: js-path-traversal
router.post('/upload', (req, res) => {
  const dest = req.body.path;
  fs.writeFile(dest, req.body.content, () => res.send('ok'));
});

// ok: js-path-traversal
router.get('/safe', (req, res) => {
  const filename = path.basename(req.query.name);
  const safe = path.join('/var/uploads', filename);
  fs.readFile(safe, 'utf8', (err, data) => res.send(data));
});
