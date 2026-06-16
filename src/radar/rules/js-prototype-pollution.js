app.post('/settings', (req, res) => {
    // ruleid: js-prototype-pollution
    Object.assign(config, req.body);
});

app.post('/safe', (req, res) => {
    const { allowed_key } = req.body;
    // ok: js-prototype-pollution
    config.allowed_key = allowed_key;
});
