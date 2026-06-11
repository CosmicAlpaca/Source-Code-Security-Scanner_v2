const express = require('express');
const router = express.Router();

router.get('/greet', function (req, res) {
  const name = req.query.name;
  // ruleid: js-express-xss-res-send
  res.send('<h1>Hello ' + name + '</h1>');
});

router.post('/echo', function (req, res) {
  // ruleid: js-express-xss-res-send
  res.write(req.body.text);
});

router.get('/safe', function (req, res) {
  const name = req.query.name;
  // ok: js-express-xss-res-send
  res.json({ message: 'Hello ' + name });
});
