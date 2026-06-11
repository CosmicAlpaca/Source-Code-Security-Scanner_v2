import os
from pathlib import Path
from flask import Flask, request, send_file

app = Flask(__name__)

# ruleid: py-path-traversal
@app.route('/download')
def download():
    filename = request.args.get('file')
    return open(filename, 'rb').read()

# ruleid: py-path-traversal
@app.route('/read')
def read_file():
    name = request.args['name']
    path = os.path.join('/var/data', name)
    return open(path).read()

# ok: py-path-traversal
@app.route('/safe')
def safe():
    filename = os.path.basename(request.args.get('file', ''))
    safe_path = os.path.join('/var/uploads', filename)
    return open(safe_path, 'rb').read()
