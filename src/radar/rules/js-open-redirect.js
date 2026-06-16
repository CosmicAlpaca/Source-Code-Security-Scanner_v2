// ruleid: js-open-redirect
app.get('/login', (req, res) => {
  res.redirect(req.query.next);
});

// ok: js-open-redirect
app.get('/login', (req, res) => {
  res.redirect('/dashboard');
});
