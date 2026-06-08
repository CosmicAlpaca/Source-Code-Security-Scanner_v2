# Test fixture for py-flask-debug-true (intentionally vulnerable snippets)
from flask import Flask

app = Flask(__name__)


def run_dev():
    # ruleid: py-flask-debug-true
    app.run(debug=True)


def run_dev_with_host():
    # ruleid: py-flask-debug-true
    app.run(host="0.0.0.0", debug=True)


def run_prod():
    # ok: py-flask-debug-true
    app.run(host="0.0.0.0")
