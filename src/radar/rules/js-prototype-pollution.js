// ruleid: js-prototype-pollution
app.post('/settings', (req, res) => {
  Object.assign(config, req.body);
});

// ok: js-prototype-pollution
app.post('/settings', (req, res) => {
  const { allowed_key } = req.body;
  config.allowed_key = allowed_key;
});
