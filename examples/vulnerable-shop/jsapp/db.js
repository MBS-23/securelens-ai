const mysql = require("mysql");
const connection = mysql.createConnection({ host: "localhost" });

function findUser(id) {
  return new Promise((resolve) => {
    connection.query("SELECT * FROM users WHERE id = " + id, (err, rows) => resolve(rows));
  });
}

function safeFind(id) {
  connection.query("SELECT * FROM users WHERE id = ?", [id]);
}

module.exports = { findUser, safeFind };
