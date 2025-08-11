from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import sqlite3

app = Flask(__name__)
CORS(app)

DB = 'server_store.sqlite'

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  recipient_pub TEXT NOT NULL,
  payload TEXT NOT NULL        -- JSON blob with fields from the client
);

CREATE TABLE IF NOT EXISTS served (
  id TEXT PRIMARY KEY
);
"""

db = sqlite3.connect(DB, check_same_thread=False)
db.executescript(SCHEMA)

@app.get('/ping')
def ping():
    return 'ok', 200

@app.post("/sync")
def sync():
    msgs = request.json.get("msgs", [])
    cur = db.cursor()
    for m in msgs:
        cur.execute(
            "INSERT OR IGNORE INTO messages(id, recipient_pub, payload) VALUES (?,?,?)",
            (m["id"], m["recipient_pub"], json.dumps(m)),
        )
    db.commit()
    return jsonify({"accepted": len(msgs)})

@app.get("/pull")
def pull():
    recipient = request.args.get("recipient")
    rows = db.execute(
        "SELECT id, payload FROM messages "
        "WHERE recipient_pub=? AND id NOT IN (SELECT id FROM served) "
        "ORDER BY rowid ASC LIMIT 500",
        (recipient,),
    ).fetchall()
    out = []
    cur = db.cursor()
    for mid, payload in rows:
        out.append(json.loads(payload))
        cur.execute("INSERT OR IGNORE INTO served(id) VALUES (?)", (mid,))
        # or: cur.execute("DELETE FROM messages WHERE id=?", (mid,))
    db.commit()
    return jsonify({"msgs": out})



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)

