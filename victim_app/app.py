import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)
ADMIN_USER = "admin"
ADMIN_PASSWORD = "summer2026"


def users_db():
    db = sqlite3.connect(":memory:")
    db.executescript(
        """
        CREATE TABLE users(id INTEGER, name TEXT, email TEXT);
        INSERT INTO users VALUES(1,'Alice','alice@example.test');
        INSERT INTO users VALUES(2,'Bob','bob@example.test');
        """
    )
    return db


@app.get("/")
def home():
    return '<h1>Acme Portal</h1><a href="/search">Directory search</a>'


@app.get("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /internal/\n", 200, {"Content-Type": "text/plain"}


@app.get("/debug")
def debug():
    return jsonify(environment="development", admin_user=ADMIN_USER, admin_password=ADMIN_PASSWORD)


@app.route("/admin", methods=["GET", "POST"])
def admin():
    user = request.values.get("username", "")
    password = request.values.get("password", "")
    if user == ADMIN_USER and password == ADMIN_PASSWORD:
        return "<h1>Admin Console</h1><p>FLAG{counterprompt_demo_victim}</p>"
    return (
        '<form method="post"><input name="username"><input name="password" '
        'type="password"><button>Login</button></form>',
        401,
    )


@app.get("/search")
def search():
    query = request.args.get("q", "")
    sql = f"SELECT id,name,email FROM users WHERE name LIKE '%{query}%'"
    try:
        rows = users_db().execute(sql).fetchall()
        return jsonify(rows)
    except sqlite3.Error as exc:
        return jsonify(error=str(exc), query=sql), 400


@app.get("/internal/")
def internal():
    return "<h1>Internal operations</h1><p>Restricted.</p>", 403


if __name__ == "__main__":
    app.run(port=5001)
