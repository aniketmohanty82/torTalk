import sqlite3
import time
from typing import List, Dict, Optional

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  sender_pub TEXT NOT NULL,
  sender_sig_pub TEXT NOT NULL,
  recipient_pub TEXT NOT NULL,
  ciphertext BLOB NOT NULL,
  signature BLOB NOT NULL,
  ts INTEGER NOT NULL,
  ttl INTEGER NOT NULL,
  delivered INTEGER DEFAULT 0,
  synced INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_recipient ON messages(recipient_pub, delivered);
CREATE TABLE IF NOT EXISTS peers (
  pubkey TEXT PRIMARY KEY,
  last_seen INTEGER,
  host TEXT,
  tcp_port INTEGER
);
"""

class Store:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript(SCHEMA)

    def save_peer(self, pubkey: str, host: str, tcp_port: int):
        now = int(time.time())
        self.db.execute(
            "INSERT INTO peers(pubkey,last_seen,host,tcp_port) VALUES(?,?,?,?)\n"
            "ON CONFLICT(pubkey) DO UPDATE SET last_seen=excluded.last_seen, host=excluded.host, tcp_port=excluded.tcp_port",
            (pubkey, now, host, tcp_port)
        )
        self.db.commit()

    def upsert_message(self, msg: Dict) -> bool:
        # returns True if inserted new
        try:
            self.db.execute(
                "INSERT INTO messages(id,sender_pub,sender_sig_pub,recipient_pub,ciphertext,signature,ts,ttl,delivered,synced)\n"
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    msg['id'], msg['sender_pub'], msg['sender_sig_pub'], msg['recipient_pub'],
                    msg['ciphertext'], msg['signature'], msg['ts'], msg['ttl'], msg.get('delivered', 0), msg.get('synced', 0)
                )
            )
            self.db.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def mark_delivered(self, msg_id: str):
        self.db.execute("UPDATE messages SET delivered=1 WHERE id=?", (msg_id,))
        self.db.commit()

    def mark_synced(self, ids: List[str]):
        if not ids: return
        q = f"UPDATE messages SET synced=1 WHERE id IN ({','.join('?'*len(ids))})"
        self.db.execute(q, ids)
        self.db.commit()

    def outbox_for_recipient(self, recipient_pub: str) -> List[Dict]:
        cur = self.db.execute("SELECT id,sender_pub,sender_sig_pub,recipient_pub,ciphertext,signature,ts,ttl FROM messages WHERE recipient_pub=? AND delivered=0", (recipient_pub,))
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    def pending_for_mesh_forward(self) -> List[Dict]:
        cur = self.db.execute("SELECT id,sender_pub,sender_sig_pub,recipient_pub,ciphertext,signature,ts,ttl FROM messages WHERE delivered=0 AND ttl>0")
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    def all_unsynced(self) -> List[Dict]:
        cur = self.db.execute("SELECT id,sender_pub,sender_sig_pub,recipient_pub,ciphertext,signature,ts,ttl FROM messages WHERE synced=0")
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
