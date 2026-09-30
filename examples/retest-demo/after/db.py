import sqlite3

conn = sqlite3.connect("app.db")

def get_user(user_id):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=?", (user_id,))
    return cur.fetchone()

def find_orders(order_id):
    cur = conn.cursor()
    cur.execute("SELECT * FROM orders WHERE id=?", (int(order_id),))
    return cur.fetchall()

def safe_user(user_id):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=?", (user_id,))
    return cur.fetchone()

REPORT_TABLES = {"orders", "users"}

def report(table):
    if table not in REPORT_TABLES:
        raise ValueError("unknown table")
    conn.execute("SELECT count(*) FROM %s" % table)
