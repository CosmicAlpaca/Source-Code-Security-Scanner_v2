const express = require('express');
const app = express();

app.get('/login', (req, res) => {
    // ruleid: js-open-redirect
    res.redirect(req.query.next);
});

app.get('/safe', (req, res) => {
    // ok: js-open-redirect
    res.redirect('/dashboard');
});
