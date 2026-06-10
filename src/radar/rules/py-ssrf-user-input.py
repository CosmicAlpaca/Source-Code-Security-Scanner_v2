import requests
import urllib.request
from flask import Flask, request

app = Flask(__name__)

# ruleid: py-ssrf-user-input
@app.route('/proxy')
def proxy():
    url = request.args.get('url')
    resp = requests.get(url)
    return resp.text

# ruleid: py-ssrf-user-input
@app.route('/fetch', methods=['POST'])
def fetch_url():
    endpoint = request.json['endpoint']
    return requests.post(endpoint).text

# ok: py-ssrf-user-input
@app.route('/safe')
def safe():
    resp = requests.get('https://api.example.com/data')
    return resp.json()
