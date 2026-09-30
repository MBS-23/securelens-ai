import os
import sqlite3
import subprocess
import hashlib
import json
import secrets
import yaml
import requests
from markupsafe import escape
from werkzeug.utils import safe_join
from flask import Flask, request, abort
from db import get_user, find_orders

app = Flask(__name__)
app.secret_key = "super-secret-signing-key-123"
ALLOWED_HOSTS = {"status.example.com"}

@app.route("/user")
def user():
    user_id = request.args.get("id")
    return str(get_user(user_id))

@app.route("/orders/<int:order_id>")
def orders(order_id):
    return str(find_orders(order_id))

@app.route("/ping")
def ping():
    host = request.args["host"]
    if host not in ALLOWED_HOSTS:
        abort(400)
    return subprocess.check_output(["ping", "-c", "1", host])

@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return "<h1>Hello " + str(escape(name)) + "</h1>"

@app.route("/file")
def read_file():
    fname = request.args.get("f")
    path = safe_join("/var/data", fname)
    if path is None:
        abort(404)
    with open(path) as fh:
        return fh.read()

@app.route("/load", methods=["POST"])
def load():
    return str(json.loads(request.data))

@app.route("/calc")
def calc():
    return str(eval(request.args["expr"]))

def token():
    return secrets.token_urlsafe(32)

def hashpw(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1).hex()

def cfg(path):
    return yaml.safe_load(open(path))

if __name__ == "__main__":
    app.run(debug=False)
