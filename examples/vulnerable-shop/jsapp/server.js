const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const axios = require("axios");
const db = require("./db");
const User = require("./models/user");

const app = express();
app.use(express.json());

app.get("/user", (req, res) => {
  const id = req.query.id;
  db.findUser(id).then((u) => res.json(u));
});

app.get("/ping", function (req, res) {
  exec("ping -c 1 " + req.query.host, (err, out) => res.send(out));
});

app.get("/hello", (req, res) => {
  res.send(`<h1>Hello ${req.query.name}</h1>`);
});

app.get("/profile/:id", async (req, res) => {
  const user = await User.findById(req.params.id);
  res.send(user);
});

app.get("/download", (req, res) => {
  const file = path.join(__dirname, "files", req.query.name);
  res.sendFile(file);
});

app.post("/login", async (req, res) => {
  const user = await User.findOne({ username: req.body.username, password: req.body.password });
  res.json({ ok: !!user });
});

app.get("/proxy", async (req, res) => {
  const r = await axios.get(req.query.url);
  res.json(r.data);
});

function makeToken() {
  const resetToken = Math.random().toString(36);
  return resetToken;
}

const hash = crypto.createHash("md5").update("x").digest("hex");
app.listen(3000);
