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
          tcp_port INTEGER
        );

        -- Track which messages we've already sent to which peer
        CREATE TABLE IF NOT EXISTS forwarded (
          peer_pub TEXT NOT NULL,
          msg_id TEXT NOT NULL,
          PRIMARY KEY (peer_pub, msg_id)
        );
        """)

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

    def save_peer(self, pubkey: str, host: str, tcp_port: int):
        self.db.execute(
            "INSERT OR REPLACE INTO peers(pubkey,last_seen,host,tcp_port) VALUES (?,?,?,?)",
            (pubkey, int(time.time()), host, tcp_port),
        )
        self.db.commit()

    # --- mesh dedupe helpers ---

    def mark_forwarded(self, peer_pub: str, msg_id: str):
        self.db.execute("INSERT OR IGNORE INTO forwarded(peer_pub, msg_id) VALUES (?,?)", (peer_pub, msg_id))
        self.db.commit()

    def outbox_for_recipient(self, recipient_pub: str) -> list[dict]:
        # Only messages for that recipient, and which we have NOT already sent to that peer
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
