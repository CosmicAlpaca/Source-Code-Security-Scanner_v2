import os
from flask import Flask

app = Flask(__name__)

# ruleid: py-flask-hardcoded-secret
app.secret_key = "super-secret-key-do-not-share"

# ruleid: py-flask-hardcoded-secret
app.secret_key = "dev-only-secret"

# ok: py-flask-hardcoded-secret
app.secret_key = os.environ.get('SECRET_KEY')

# ok: py-flask-hardcoded-secret
app.secret_key = os.getenv('FLASK_SECRET')
