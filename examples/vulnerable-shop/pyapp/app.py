import os
import sqlite3
import subprocess
import hashlib
import pickle
import yaml
import requests
from flask import Flask, request, render_template_string
from db import get_user, find_orders

app = Flask(__name__)
app.secret_key = "super-secret-signing-key-123"

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
    return subprocess.check_output("ping -c 1 " + host, shell=True)

@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return "<h1>Hello " + name + "</h1>"

@app.route("/file")
def read_file():
    fname = request.args.get("f")
    with open(os.path.join("/var/data", fname)) as fh:
        return fh.read()

@app.route("/fetch")
def fetch():
    return requests.get(request.args["url"], verify=False).text

@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))

def token():
    import random
    reset_token = random.randint(0, 999999)
    return reset_token

def hashpw(password):
    return hashlib.md5(password.encode()).hexdigest()

def cfg(path):
    return yaml.load(open(path))

if __name__ == "__main__":
    app.run(debug=True)
