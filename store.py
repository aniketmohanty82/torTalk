# store.py (only the relevant bits)

import sqlite3, time

class Store:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL;")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS messages (
        id TEXT PRIMARY KEY,
        sender_pub TEXT NOT NULL,
        sender_sig_pub TEXT NOT NULL,
        recipient_pub TEXT NOT NULL,
        ciphertext BLOB NOT NULL,
        signature BLOB NOT NULL,
        ts INTEGER NOT NULL,
        ttl INTEGER NOT NULL,
        nonce TEXT,
        delivered INTEGER DEFAULT 0,
        synced INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS peers (
        pubkey TEXT PRIMARY KEY,
        last_seen INTEGER NOT NULL,
        host TEXT,
        tcp_port INTEGER,
        username TEXT,
        is_friend INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS forwarded (
        peer_pub TEXT NOT NULL,
        msg_id TEXT NOT NULL,
        PRIMARY KEY (peer_pub, msg_id)
        );
        """)
    
    def recent_peers(self, max_age: int = 30):
        cutoff = int(time.time()) - max_age
        cur = self.db.execute(
            "SELECT pubkey, username, host, tcp_port, last_seen, is_friend "
            "FROM peers WHERE last_seen >= ? ORDER BY last_seen DESC",
            (cutoff,),
        )
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    def username_for(self, pubkey: str) -> str | None:
        row = self.db.execute("SELECT username FROM peers WHERE pubkey=?", (pubkey,)).fetchone()
        return row[0] if row and row[0] else None

    def upsert_message(self, m: dict) -> bool:
        cur = self.db.execute(
            "INSERT OR IGNORE INTO messages(id, sender_pub, sender_sig_pub, recipient_pub, ciphertext, signature, ts, ttl, nonce, delivered, synced) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                m["id"], m["sender_pub"], m["sender_sig_pub"], m["recipient_pub"],
                m["ciphertext"], m["signature"], m["ts"], m["ttl"], m.get("nonce"),
                m.get("delivered", 0), m.get("synced", 0),
            ),
        )
        self.db.commit()
        return cur.rowcount == 1

    def mark_delivered(self, mid: str):
        self.db.execute("UPDATE messages SET delivered=1 WHERE id=?", (mid,))
        self.db.commit()

    def all_unsynced(self) -> list[dict]:
        rows = self.db.execute(
            "SELECT id, sender_pub, sender_sig_pub, recipient_pub, ciphertext, signature, ts, ttl, nonce FROM messages WHERE synced=0"
        ).fetchall()
        out = []
        for r in rows:
            out.append({
                "id": r[0], "sender_pub": r[1], "sender_sig_pub": r[2], "recipient_pub": r[3],
                "ciphertext": r[4], "signature": r[5], "ts": r[6], "ttl": r[7], "nonce": r[8],
            })
        return out

    def mark_synced(self, ids: list[str]):
        if not ids: return
        q = "UPDATE messages SET synced=1 WHERE id IN (%s)" % ",".join("?"*len(ids))
        self.db.execute(q, ids); self.db.commit()

    def save_peer(self, pubkey: str, host: str, tcp_port: int, username: str | None = None):
        self.db.execute(
            "INSERT INTO peers(pubkey,last_seen,host,tcp_port,username,is_friend) "
            "VALUES (?,?,?,?,?,COALESCE((SELECT is_friend FROM peers WHERE pubkey=?),0)) "
            "ON CONFLICT(pubkey) DO UPDATE SET last_seen=excluded.last_seen, host=excluded.host, "
            "tcp_port=excluded.tcp_port, username=COALESCE(excluded.username, peers.username)",
            (pubkey, int(time.time()), host, tcp_port, username, pubkey)
        )
        self.db.commit()

    def set_friend(self, pubkey: str, is_friend: int = 1):
        self.db.execute("UPDATE peers SET is_friend=? WHERE pubkey=?", (is_friend, pubkey))
        self.db.commit()

    def is_friend(self, pubkey: str) -> bool:
        row = self.db.execute("SELECT is_friend FROM peers WHERE pubkey=?", (pubkey,)).fetchone()
        return bool(row[0]) if row else False

    def get_peers(self):
        cur = self.db.execute(
            "SELECT pubkey, username, host, tcp_port, last_seen, is_friend FROM peers ORDER BY last_seen DESC"
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    # --- mesh dedupe helpers ---

    def outbox_for_recipient(self, recipient_pub: str):
        rows = self.db.execute(
            """
            SELECT id, sender_pub, sender_sig_pub, recipient_pub, ciphertext, signature, ts, ttl, nonce
            FROM messages
            WHERE recipient_pub = ?
            AND id NOT IN (SELECT msg_id FROM forwarded WHERE peer_pub = ?)
            """,
            (recipient_pub, recipient_pub),
        ).fetchall()
        out = []
        for r in rows:
            out.append({
                "id": r[0], "sender_pub": r[1], "sender_sig_pub": r[2], "recipient_pub": r[3],
                "ciphertext": r[4], "signature": r[5], "ts": r[6], "ttl": r[7], "nonce": r[8],
            })
        return out

    def mark_forwarded(self, peer_pub: str, mid: str):
        self.db.execute("INSERT OR IGNORE INTO forwarded(peer_pub,msg_id) VALUES (?,?)", (peer_pub, mid))
        self.db.commit()

    def pending_for_mesh_forward(self) -> list[dict]:
        # (Optional) If you keep this, return messages that aren't for us and not delivered.
        rows = self.db.execute(
            "SELECT id, sender_pub, sender_sig_pub, recipient_pub, ciphertext, signature, ts, ttl, nonce "
            "FROM messages WHERE delivered=0 AND ttl>0"
        ).fetchall()
        return [
            {
                "id": r[0], "sender_pub": r[1], "sender_sig_pub": r[2], "recipient_pub": r[3],
                "ciphertext": r[4], "signature": r[5], "ts": r[6], "ttl": r[7], "nonce": r[8],
            }
            for r in rows
        ]
