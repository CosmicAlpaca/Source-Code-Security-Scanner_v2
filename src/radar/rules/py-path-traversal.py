import os
from flask import Flask, request

app = Flask(__name__)

@app.route('/download')
def download():
    filename = request.args.get('file')
    # ruleid: py-path-traversal
    return open(filename, 'rb').read()

@app.route('/read')
def read_file():
    name = request.args['name']
    # ruleid: py-path-traversal
    path = os.path.join('/var/data', name)
    # ruleid: py-path-traversal
    return open(path).read()

@app.route('/safe')
def safe():
    # ok: py-path-traversal
    return open('/var/uploads/static.txt', 'rb').read()
