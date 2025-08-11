# server.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import json, sqlite3, os, shutil, argparse, atexit

# ─────────────────── Tor Hidden Service (via stem) ───────────────────
try:
    from stem.process import launch_tor_with_config
except Exception:
    launch_tor_with_config = None  # shown if --tor-hidden is used without stem

def _find_tor_binary() -> str | None:
    tor_path = os.environ.get("TOR_BINARY")
    if tor_path and os.path.exists(tor_path):
        return tor_path
    tor_path = shutil.which("tor")
    if tor_path:
        return tor_path
    for p in ("/opt/homebrew/bin/tor", "/usr/local/bin/tor", "/usr/bin/tor"):
        if os.path.exists(p):
            return p
    for p in (r"C:\Program Files\Tor\tor.exe", r"C:\Program Files (x86)\Tor\tor.exe"):
        if os.path.exists(p):
            return p
    return None

class HiddenService:
    def __init__(self, state_dir="tor_hs"):
        self.proc = None
        self.state_dir = state_dir
        self.hs_dir = os.path.join(self.state_dir, "hidden_service")
        self.onion = None

    def start(self, local_port=8080):
        if self.onion:
            return self.onion
        if launch_tor_with_config is None:
            raise RuntimeError("Missing dependency: pip install stem")
        tor_bin = _find_tor_binary()
        if not tor_bin:
            raise RuntimeError("'tor' binary not found. Install Tor (e.g., brew install tor).")
        os.makedirs(self.hs_dir, exist_ok=True)
        self.proc = launch_tor_with_config(
            tor_cmd=tor_bin,
            config={
                "SOCKSPort": "0",  # server doesn't offer SOCKS
                "ControlPort": "0",
                "AvoidDiskWrites": "1",
                "HiddenServiceDir": self.hs_dir,
                "HiddenServiceVersion": "3",
                "HiddenServicePort": f"80 127.0.0.1:{local_port}",
            },
            take_ownership=True,
            timeout=90,
        )
        with open(os.path.join(self.hs_dir, "hostname"), "r") as f:
            self.onion = f.read().strip()
        return self.onion

    def stop(self):
        if self.proc:
            try: self.proc.terminate()
            except Exception: pass
        self.proc = None

HS = HiddenService()  # optional, only used if --tor-hidden

# ───────────────────────── Flask app + DB ─────────────────────────
app = Flask(__name__)
CORS(app)

def open_db(db_path: str):
    db = sqlite3.connect(db_path, check_same_thread=False)
    db.execute("PRAGMA journal_mode=WAL;")
    db.executescript("""
    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      recipient_pub TEXT NOT NULL,
      payload TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS served (
      id TEXT PRIMARY KEY
    );
    """)
    return db

# these are set in main()
DB_PATH = "server_store.sqlite"
ONION_HOST = os.environ.get("MESH_ONION")
db = None

@app.get("/ping")
def ping():
    return "ok", 200

@app.get("/onion")
def onion():
    if ONION_HOST:
        return jsonify({"onion": ONION_HOST}), 200
    return jsonify({"onion": None}), 404

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
        # alternatively: cur.execute("DELETE FROM messages WHERE id=?", (mid,))
    db.commit()
    return jsonify({"msgs": out})

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--db", default="server_store.sqlite")
    ap.add_argument("--tor-hidden", action="store_true", help="Start a Tor v3 hidden service for this server")
    args = ap.parse_args()

    DB_PATH = args.db
    db = open_db(DB_PATH)

    if args.tor_hidden:
        try:
            onion = HS.start(local_port=args.port)
            print(f"[TOR] Hidden service online: http://{onion}  →  127.0.0.1:{args.port}")
            atexit.register(HS.stop)
        except Exception as e:
            print(f"[TOR] Failed to start hidden service: {e}")

    app.run(host="0.0.0.0", port=args.port)
