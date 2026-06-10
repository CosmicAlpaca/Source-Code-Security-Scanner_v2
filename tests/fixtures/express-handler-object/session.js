// Handler-object pattern (như OWASP NodeGoat): methods gán qua `this.x = arrow`
// trong một constructor function, rồi route tham chiếu `instance.method`.
function SessionHandler(db) {
  this.handleLogin = (req, res) => {
    const user = db.find(req.body);
    res.send(user);
  };

  this.displayLogin = (req, res) => {
    res.render("login");
  };
}

module.exports = SessionHandler;
