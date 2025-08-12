import argparse
import asyncio
import base64
import json
import os
import socket
import struct
import time
from typing import Dict, Optional, Callable

import requests
import tomllib
import toml  # for writing settings.toml
from nacl.hash import blake2b
from nacl.encoding import RawEncoder

from bootstrap import ensure_initialized
from crypto_utils import (
    Identity, load_or_create_identity, seal_for,
    open_sealed, sign, verify
)
from app.store import Store

# ---------- helpers ----------

def format_address(identity: Identity) -> str:
    """Return 'mesh:<enc_b64>.<sig_b64>' for sharing."""
    return f"mesh:{identity.pub_b64}.{identity.sign_b64}"

def _normalize_recipient(s: Optional[str]) -> Optional[str]:
    """Allow --send-to to be either <enc_b64> or 'mesh:<enc>.<sig>'."""
    if not s:
        return s
    s = s.strip()
    if s.startswith("mesh:"):
        s = s.split("mesh:", 1)[1]
    if "." in s:
        s = s.split(".", 1)[0]
    return s

def _msg_id(sender_b64: str, recipient_b64: str, nonce: bytes) -> str:
    """Stable(ish) id per (sender, recipient, nonce)."""
    return blake2b(
        (sender_b64 + "|" + recipient_b64).encode() + nonce, encoder=RawEncoder
    ).hex()

# ---------- constants ----------

MULTICAST_GRP = "239.1.2.3"
MULTICAST_PORT = 54545
GOSSIP_PORT_DEFAULT = 45454
HELLO_INTERVAL = 5           # seconds
GOSSIP_INTERVAL = 3          # seconds
MESH_TTL_DEFAULT = 4         # max hops in LAN flood

# ---------- node ----------

class Node:
    """
    Hybrid Mesh Messenger node:
      - LAN multicast discovery + TCP gossip
      - Optional server sync (direct or via Tor SOCKS)
      - Settings persistence helpers for server_url and username
    """
    def __init__(self, cfg_path: str, on_delivered: Optional[Callable[[Dict], None]] = None):
        self.cfg_path = cfg_path
        with open(cfg_path, "rb") as f:
            cfg = tomllib.load(f)

        self.identity: Identity = load_or_create_identity(cfg["identity"]["path"])
        self.username = (cfg.get("user", {}) or {}).get("username") or f"user-{self.identity.pub_b64[:6]}"
        self.admin_mode = True  # TEMP: grant superuser for now (we’ll tighten later)

        self.store = Store(cfg["storage"]["path"])
        self.listen_port = int(cfg["network"].get("tcp_port", GOSSIP_PORT_DEFAULT))
        self.server_url = (cfg.get("server") or {}).get("url")
        self.tor_socks = (cfg.get("server") or {}).get("tor_socks")
        self.safety_mode = bool((cfg.get("server") or {}).get("safety_mode", False))
        self.on_delivered = on_delivered

        self.session = requests.Session()
        if self.safety_mode and self.tor_socks:
            self.session.proxies = {"http": self.tor_socks, "https": self.tor_socks}
        else:
            self.session.proxies = {}

        self._tasks: list[asyncio.Task] = []

    # ---------- persistence helpers ----------

    def _load_cfg(self) -> dict:
        with open(self.cfg_path, "rb") as f:
            return tomllib.load(f)

    def _write_cfg(self, cfg: dict) -> None:
        os.makedirs(os.path.dirname(self.cfg_path), exist_ok=True)
        with open(self.cfg_path, "w") as f:
            toml.dump(cfg, f)

    def persist_server_url(self, new_url: str,
                           safety_mode: Optional[bool] = None,
                           tor_socks: Optional[str] = None) -> None:
        """
        Persist server.url (and optionally safety_mode/tor_socks) to settings.toml,
        and update in-memory values + session proxies.
        """
        cfg = self._load_cfg()
        cfg.setdefault("server", {})
        cfg["server"]["url"] = new_url
        if safety_mode is not None:
            cfg["server"]["safety_mode"] = bool(safety_mode)
        if tor_socks is not None:
            cfg["server"]["tor_socks"] = tor_socks
        self._write_cfg(cfg)

        # reflect in-memory
        self.server_url = new_url
        if safety_mode is not None or tor_socks is not None:
            self.set_safety_mode(
                enabled=self.safety_mode if safety_mode is None else bool(safety_mode),
                tor_socks=self.tor_socks if tor_socks is None else tor_socks
            )

    def persist_username(self, new_username: str) -> None:
        """Persist user.username into settings.toml and update self.username."""
        cfg = self._load_cfg()
        cfg.setdefault("user", {})
        cfg["user"]["username"] = new_username
        self._write_cfg(cfg)
        self.username = new_username

    # ---------- public controls ----------

    def set_safety_mode(self, enabled: bool, tor_socks: Optional[str] = None):
        """Flip Safety (Tor) ON/OFF; optionally update tor_socks."""
        self.safety_mode = bool(enabled)
        if tor_socks:
            self.tor_socks = tor_socks
        if self.safety_mode and self.tor_socks:
            self.session.proxies = {"http": self.tor_socks, "https": self.tor_socks}
        else:
            self.session.proxies = {}

    def send_text(self, recipient_any: str, text: str, ttl: int = MESH_TTL_DEFAULT) -> Dict:
        """Convenience: accept mesh:<enc>.<sig> or raw enc b64."""
        s = recipient_any.strip()
        if s.startswith("mesh:"):
            s = s.split("mesh:", 1)[1]
        if "." in s:
            s = s.split(".", 1)[0]
        return self.create_message(s, text, ttl=ttl)

    async def start(self):
        """Start all background loops."""
        self._tasks = [
            asyncio.create_task(self.multicast_hello_loop(), name="mcast-hello"),
            asyncio.create_task(self.multicast_listen_loop(), name="mcast-listen"),
            asyncio.create_task(self.gossip_server(), name="gossip-server"),
            asyncio.create_task(self.gossip_client_loop(), name="gossip-client"),
            asyncio.create_task(self.sync_loop(), name="sync"),
        ]

    async def stop(self):
        """Stop background loops."""
        tasks = list(self._tasks)
        self._tasks.clear()
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    # ---------- Message API ----------

    def create_message(self, recipient_pub_b64: str, plaintext: str,
                       ttl: int = MESH_TTL_DEFAULT) -> Dict:
        nonce = os.urandom(16)
        ct = seal_for(recipient_pub_b64, plaintext.encode())
        mid = _msg_id(self.identity.pub_b64, recipient_pub_b64, nonce)
        payload = (mid + recipient_pub_b64).encode()
        sig = sign(self.identity, payload)
        m = {
            "id": mid,
            "sender_pub": self.identity.pub_b64,
            "sender_sig_pub": self.identity.sign_b64,
            "recipient_pub": recipient_pub_b64,
            "ciphertext": ct,
            "signature": sig,
            "ts": int(time.time()),
            "ttl": ttl,
            "nonce": base64.b64encode(nonce).decode(),
            "delivered": 0,
            "synced": 0,
        }
        self.store.upsert_message(m)
        return m

    def try_deliver_locally(self, msg: Dict):
        """If message is for us, verify, decrypt, mark delivered, and notify GUI."""
        if msg["recipient_pub"] != self.identity.pub_b64:
            return
        if not verify(msg["signature"], (msg["id"] + msg["recipient_pub"]).encode(), msg["sender_sig_pub"]):
            return
        try:
            pt = open_sealed(self.identity, msg["ciphertext"]).decode()
            print(f"\n[DELIVERED] from={msg['sender_pub'][:16]}... id={msg['id'][:12]} msg=\n  {pt}\n")
            self.store.mark_delivered(msg["id"])
            if self.on_delivered:
                self.on_delivered({"id": msg["id"], "sender_pub": msg["sender_pub"], "text": pt, "ts": msg.get("ts")})
        except Exception:
            pass

    # ---------- Mesh: discovery + gossip ----------

    async def multicast_hello_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        ttl_bin = struct.pack("@i", 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl_bin)
        while True:
            payload = json.dumps({
                "type": "hello",
                "pub": self.identity.pub_b64,
                "port": self.listen_port,
                "username": self.username,
            }).encode()
            sock.sendto(payload, (MULTICAST_GRP, MULTICAST_PORT))
            await asyncio.sleep(HELLO_INTERVAL)

    async def multicast_listen_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        sock.bind(("", MULTICAST_PORT))
        mreq = struct.pack("4sl", socket.inet_aton(MULTICAST_GRP), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.setblocking(False)
        loop = asyncio.get_event_loop()
        while True:
            try:
                data, addr = await loop.run_in_executor(None, sock.recvfrom, 65536)
                msg = json.loads(data.decode())
                if msg.get("type") == "hello" and msg.get("pub") != self.identity.pub_b64:
                    self.store.save_peer(msg["pub"], addr[0], int(msg["port"]), msg.get("username"))
            except Exception:
                await asyncio.sleep(0.1)

    async def gossip_server(self):
        server = await asyncio.start_server(self.handle_peer_conn, host="0.0.0.0", port=self.listen_port)
        async with server:
            await server.serve_forever()

    async def handle_peer_conn(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            raw = await asyncio.wait_for(reader.readline(), timeout=5)
            header = json.loads(raw.decode())
            if header.get("type") != "pull":
                writer.close(); await writer.wait_closed(); return
            their_pub = header.get("pub")

            # ACL: only send to friend peers unless admin_mode
            if not self.admin_mode and not self.store.is_friend(their_pub):
                writer.write((json.dumps({"type": "end"}) + "\n").encode())
                await writer.drain()
                writer.close(); await writer.wait_closed()
                return

            msgs = self.store.outbox_for_recipient(their_pub)
            writer.write((json.dumps({"type": "push", "count": len(msgs)}) + "\n").encode())
            await writer.drain()

            for m in msgs:
                out = m.copy()
                out["ciphertext"] = base64.b64encode(out["ciphertext"]).decode()
                out["signature"] = base64.b64encode(out["signature"]).decode()
                writer.write((json.dumps({"type": "msg", "data": out}) + "\n").encode())
                await writer.drain()
                self.store.mark_forwarded(their_pub, m["id"])

            writer.write((json.dumps({"type": "end"}) + "\n").encode())
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close(); await writer.wait_closed()

    async def gossip_client_loop(self):
        while True:
            peers = self.store.db.execute("SELECT pubkey,host,tcp_port FROM peers").fetchall()
            for pub, host, port in peers:
                try:
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=1.5)
                    writer.write((json.dumps({"type": "pull", "pub": self.identity.pub_b64}) + "\n").encode())
                    await writer.drain()

                    while True:
                        line = await asyncio.wait_for(reader.readline(), timeout=2)
                        if not line:
                            break
                        evt = json.loads(line.decode())
                        if evt.get("type") == "msg":
                            m = evt["data"]
                            m["ciphertext"] = base64.b64decode(m["ciphertext"])
                            m["signature"] = base64.b64decode(m["signature"])
                            inserted = self.store.upsert_message(m)
                            if inserted:
                                self.try_deliver_locally(m)
                                if m["recipient_pub"] != self.identity.pub_b64 and m["ttl"] > 0:
                                    m2 = m.copy(); m2["ttl"] = m["ttl"] - 1
                                    self.store.upsert_message(m2)
                        elif evt.get("type") == "end":
                            break
                except Exception:
                    continue
            await asyncio.sleep(GOSSIP_INTERVAL)

    # ---------- Server sync (direct or via Tor SOCKS) ----------

    def server_available(self) -> bool:
        if not self.server_url:
            return False
        try:
            r = self.session.get(self.server_url + "/ping", timeout=2)
            return r.status_code == 200
        except Exception:
            return False

    async def sync_loop(self):
        while True:
            if self.server_available():
                try:
                    # push unsynced
                    batch = self.store.all_unsynced()
                    wire = []
                    for m in batch:
                        out = m.copy()
                        out["ciphertext"] = base64.b64encode(out["ciphertext"]).decode()
                        out["signature"] = base64.b64encode(out["signature"]).decode()
                        wire.append(out)
                    if wire:
                        r = self.session.post(self.server_url + "/sync", json={"msgs": wire}, timeout=8)
                        if r.ok:
                            self.store.mark_synced([m["id"] for m in batch])

                    # pull for us
                    r = self.session.get(self.server_url + f"/pull?recipient={self.identity.pub_b64}", timeout=8)
                    if r.ok:
                        for m in r.json().get("msgs", []):
                            m["ciphertext"] = base64.b64decode(m["ciphertext"])
                            m["signature"] = base64.b64decode(m["signature"])
                            inserted = self.store.upsert_message(m)
                            if inserted:
                                self.try_deliver_locally(m)
                except Exception:
                    pass
            await asyncio.sleep(5)

# ---------- runner ----------

async def main_node(cfg_path: str, send_to: Optional[str], text: Optional[str], ttl: int):
    node = Node(cfg_path)

    # One-shot send and exit
    if send_to and text is not None:
        node.create_message(_normalize_recipient(send_to), text, ttl=ttl)
        print("Queued message; it will deliver via mesh and/or server when possible.")
        return

    # Run full node: discovery, gossip, sync
    await asyncio.gather(
        node.multicast_hello_loop(),
        node.multicast_listen_loop(),
        node.gossip_server(),
        node.gossip_client_loop(),
        node.sync_loop(),
    )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hybrid Mesh Messenger Node")
    parser.add_argument("--config", help="Path to TOML config (if omitted, auto-init is used)")
    parser.add_argument("--send-to", help="Recipient public key (b64 or mesh:<enc>.<sig>)")
    parser.add_argument("--text", help="Message text")
    parser.add_argument("--ttl", type=int, default=MESH_TTL_DEFAULT)

    # Auto-init knobs (ignored if --config is given)
    parser.add_argument("--profile", help='Profile name (env MESH_PROFILE or "default")')
    parser.add_argument("--port", type=int, help="Preferred mesh TCP port (else auto-find)")
    parser.add_argument("--server", help="Central sync server URL (http or .onion)")
    parser.add_argument("--safety-mode", action="store_true", help="Use Tor for server sync")
    parser.add_argument("--tor-socks", default=None, help="Tor SOCKS endpoint (e.g., socks5h://127.0.0.1:9050)")
    parser.add_argument("--print-address", action="store_true", help="Print address and exit")

    args = parser.parse_args()

    if args.config:
        cfg_path = args.config
        if args.print_address and not (args.send_to or args.text):
            n = Node(cfg_path)
            print(format_address(n.identity))
        else:
            asyncio.run(main_node(cfg_path, args.send_to, args.text, args.ttl))
    else:
        cfg_path, cfg, ident, address = ensure_initialized(
            profile=args.profile,
            server_url=args.server,
            safety_mode=True if args.safety_mode else None,
            tor_socks=args.tor_socks,
            prefer_port=args.port,
        )
        if args.print_address and not (args.send_to or args.text):
            print(address)
        else:
            asyncio.run(main_node(cfg_path, args.send_to, args.text, args.ttl))
