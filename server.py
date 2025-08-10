from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import time

app = Flask(__name__)
CORS(app)

DB = 'server_store.sqlite'

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  sender_pub TEXT,
  sender_sig_pub TEXT,
  recipient_pub TEXT,
  ciphertext BLOB,
  signature BLOB,
  ts INTEGER,
  ttl INTEGER
);
CREATE INDEX IF NOT EXISTS idx_pull ON messages(recipient_pub, ts);
"""

db = sqlite3.connect(DB, check_same_thread=False)
db.executescript(SCHEMA)

def insert_or_ignore(m):
    try:
        db.execute(
            "INSERT INTO messages(id,sender_pub,sender_sig_pub,recipient_pub,ciphertext,signature,ts,ttl) VALUES(?,?,?,?,?,?,?,?)",
            (m['id'], m['sender_pub'], m['sender_sig_pub'], m['recipient_pub'], m['ciphertext'], m['signature'], m['ts'], m['ttl'])
        )
        db.commit()
        return True
    except sqlite3.IntegrityError:
        return False

@app.get('/ping')
def ping():
    return 'ok', 200

@app.post('/sync')
def sync():
    payload = request.get_json(force=True)
    msgs = payload.get('msgs', [])
    for m in msgs:
        # trust model is minimal here; production must verify signatures, etc.
        insert_or_ignore(m)
    return jsonify({'accepted': len(msgs)})

@app.get('/pull')
def pull():
    recipient = request.args.get('recipient')
    cur = db.execute("SELECT id,sender_pub,sender_sig_pub,recipient_pub,ciphertext,signature,ts,ttl FROM messages WHERE recipient_pub=? ORDER BY ts ASC LIMIT 500", (recipient,))
    cols = [c[0] for c in cur.description]
    msgs = [dict(zip(cols, r)) for r in cur.fetchall()]
    return jsonify({'msgs': msgs})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)

