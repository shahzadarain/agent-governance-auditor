"""A small inventory API. There is no model and no agent here."""

import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)
DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, qty INTEGER)")


def tool_tip(name):
    # "tool" in a name does not make this an agent tool.
    return "Item: " + name


@app.get("/items")
def list_items():
    rows = DB.execute("SELECT id, name, qty FROM items ORDER BY id").fetchall()
    return jsonify([{"id": r[0], "name": r[1], "qty": r[2]} for r in rows])


@app.post("/items")
def add_item():
    body = request.get_json()
    DB.execute("INSERT INTO items (name, qty) VALUES (?, ?)", (body["name"], int(body["qty"])))
    DB.commit()
    return jsonify({"ok": True}), 201


if __name__ == "__main__":
    app.run()
