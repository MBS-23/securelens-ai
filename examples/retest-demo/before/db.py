import sqlite3

conn = sqlite3.connect("app.db")

def get_user(user_id):
    query = "SELECT * FROM users WHERE id=" + user_id
    cur = conn.cursor()
    cur.execute(query)
    return cur.fetchone()

def find_orders(order_id):
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM orders WHERE id={order_id}")
    return cur.fetchall()

def safe_user(user_id):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=?", (user_id,))
    return cur.fetchone()

def report(table):
    conn.execute("SELECT count(*) FROM %s" % table)
