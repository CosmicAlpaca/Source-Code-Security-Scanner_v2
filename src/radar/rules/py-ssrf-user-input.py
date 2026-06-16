import requests
import urllib.request
from flask import Flask, request

app = Flask(__name__)

@app.route('/proxy')
def proxy():
    url = request.args.get('url')
    # ruleid: py-ssrf-user-input
    resp = requests.get(url)
    return resp.text

@app.route('/fetch', methods=['POST'])
def fetch_url():
    endpoint = request.json['endpoint']
    # ruleid: py-ssrf-user-input
    return requests.post(endpoint).text

@app.route('/safe')
def safe():
    # ok: py-ssrf-user-input
    resp = requests.get('https://api.example.com/data')
    return resp.json()
