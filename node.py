import argparse
import asyncio
import json
import socket
import struct
import time
from typing import Dict, List
import base64

import requests
import tomllib

from crypto_utils import Identity, load_or_create_identity, seal_for, open_sealed, sign, verify, msg_id
from store import Store

MULTICAST_GRP = '239.1.2.3'
MULTICAST_PORT = 54545
GOSSIP_PORT_DEFAULT = 45454
HELLO_INTERVAL = 5           # seconds
GOSSIP_INTERVAL = 3          # seconds
MESH_TTL_DEFAULT = 4         # max hops in LAN flood


class Node:
    def __init__(self, cfg_path: str):
        with open(cfg_path, 'rb') as f:
            cfg = tomllib.load(f)
        self.identity: Identity = load_or_create_identity(cfg['identity']['path'])
        self.store = Store(cfg['storage']['path'])
        self.listen_port = cfg['network'].get('tcp_port', GOSSIP_PORT_DEFAULT)
        self.server_url = cfg['server'].get('url')
        self.tor_socks = cfg['server'].get('tor_socks')  # e.g., "socks5h://127.0.0.1:9050"
        self.safety_mode = cfg['server'].get('safety_mode', False)
        self.session = requests.Session()
        if self.safety_mode and self.tor_socks:
            self.session.proxies = {
                'http': self.tor_socks,
                'https': self.tor_socks,
            }

    # ---- Message API ----
    def create_message(self, recipient_pub_b64: str, plaintext: str, ttl: int = MESH_TTL_DEFAULT) -> Dict:
        ct = seal_for(recipient_pub_b64, plaintext.encode())
        mid = msg_id(ct)
        payload = (mid + recipient_pub_b64).encode()  # simple binding
        sig = sign(self.identity, payload)
        m = {
            'id': mid,
            'sender_pub': self.identity.pub_b64,
            'sender_sig_pub': self.identity.sign_b64,
            'recipient_pub': recipient_pub_b64,
            'ciphertext': ct,
            'signature': sig,
            'ts': int(time.time()),
            'ttl': ttl,
            'delivered': 0,
            'synced': 0,
        }
        self.store.upsert_message(m)
        return m

    def try_deliver_locally(self, msg: Dict):
        # if message is for us, open and print; mark delivered
        if msg['recipient_pub'] == self.identity.pub_b64:
            # verify signature
            if not verify(msg['signature'], (msg['id'] + msg['recipient_pub']).encode(), msg['sender_sig_pub']):
                return
            try:
                pt = open_sealed(self.identity, msg['ciphertext']).decode()
                print(f"\n[DELIVERED] from={msg['sender_pub'][:16]}... id={msg['id'][:12]} msg=\n  {pt}\n")
                self.store.mark_delivered(msg['id'])
            except Exception:
                pass

    # ---- Mesh: discovery + gossip ----
    async def multicast_hello_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        ttl_bin = struct.pack('@i', 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl_bin)
        while True:
            payload = json.dumps({
                'type': 'hello',
                'pub': self.identity.pub_b64,
                'port': self.listen_port,
            }).encode()
            sock.sendto(payload, (MULTICAST_GRP, MULTICAST_PORT))
            await asyncio.sleep(HELLO_INTERVAL)

    async def multicast_listen_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', MULTICAST_PORT))
        mreq = struct.pack('4sl', socket.inet_aton(MULTICAST_GRP), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.setblocking(False)
        loop = asyncio.get_event_loop()
        while True:
            try:
                data, addr = await loop.run_in_executor(None, sock.recvfrom, 65536)
                msg = json.loads(data.decode())
                if msg.get('type') == 'hello' and msg.get('pub') != self.identity.pub_b64:
                    self.store.save_peer(msg['pub'], addr[0], int(msg['port']))
            except Exception:
                await asyncio.sleep(0.1)

    async def gossip_server(self):
        server = await asyncio.start_server(self.handle_peer_conn, host='0.0.0.0', port=self.listen_port)
        async with server:
            await server.serve_forever()

    async def handle_peer_conn(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            raw = await asyncio.wait_for(reader.readline(), timeout=5)
            header = json.loads(raw.decode())
            if header.get('type') != 'pull':
                writer.close(); await writer.wait_closed(); return
            their_pub = header.get('pub')
            # 1) Send any messages we have for them
            msgs = self.store.outbox_for_recipient(their_pub)
            writer.write((json.dumps({'type':'push','count':len(msgs)})+'\n').encode())
            await writer.drain()
            for m in msgs:
                out = m.copy();
                # base64-encode binary fields for transport
                out['ciphertext'] = base64.b64encode(out['ciphertext']).decode()
                out['signature'] = base64.b64encode(out['signature']).decode()
                writer.write((json.dumps({'type':'msg','data':out})+'\n').encode())
                await writer.drain()
            writer.write((json.dumps({'type':'end'})+'\n').encode())
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close(); await writer.wait_closed()

    async def gossip_client_loop(self):
        while True:
            # forward/flood pending (TTL>0) to any peers we know
            pending = self.store.pending_for_mesh_forward()
            # build peer list
            peers = self.store.db.execute("SELECT pubkey,host,tcp_port FROM peers").fetchall()
            for pub, host, port in peers:
                # pull from them any messages destined to us; also gives them a chance to request ours
                try:
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=1.5)
                    writer.write((json.dumps({'type':'pull','pub': self.identity.pub_b64})+'\n').encode())
                    await writer.drain()

                    while True:
                        line = await asyncio.wait_for(reader.readline(), timeout=2)
                        if not line: break
                        evt = json.loads(line.decode())
                        if evt.get('type') == 'msg':
                            m = evt['data']
                            m['ciphertext'] = base64.b64decode(m['ciphertext'])
                            m['signature'] = base64.b64decode(m['signature'])
                            inserted = self.store.upsert_message(m)
                            if inserted:
                                self.try_deliver_locally(m)
                                # decrement TTL and keep circulating if not delivered
                                if m['recipient_pub'] != self.identity.pub_b64 and m['ttl'] > 0:
                                    m2 = m.copy(); m2['ttl'] = m['ttl'] - 1
                                    self.store.upsert_message(m2)
                        elif evt.get('type') == 'end':
                            break
                except Exception:
                    continue
            await asyncio.sleep(GOSSIP_INTERVAL)

    # ---- Server sync (direct or via Tor SOCKS) ----
    def server_available(self) -> bool:
        if not self.server_url:
            return False
        try:
            r = self.session.get(self.server_url + '/ping', timeout=2)
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
                        out['ciphertext'] = base64.b64encode(out['ciphertext']).decode()
                        out['signature'] = base64.b64encode(out['signature']).decode()
                        wire.append(out)
                    if wire:
                        r = self.session.post(self.server_url + '/sync', json={'msgs': wire}, timeout=8)
                        if r.ok:
                            self.store.mark_synced([m['id'] for m in batch])
                    # pull for us
                    r = self.session.get(self.server_url + f"/pull?recipient={self.identity.pub_b64}", timeout=8)
                    if r.ok:
                        for m in r.json().get('msgs', []):
                            m['ciphertext'] = base64.b64decode(m['ciphertext'])
                            m['signature'] = base64.b64decode(m['signature'])
                            inserted = self.store.upsert_message(m)
                            if inserted:
                                self.try_deliver_locally(m)
                except Exception:
                    pass
            await asyncio.sleep(5)


async def main_node(cfg: str, send_to: str | None, text: str | None, ttl: int):
    node = Node(cfg)
    # Optionally send a message and exit
    if send_to and text is not None:
        node.create_message(send_to, text, ttl=ttl)
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


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Hybrid Mesh Messenger Node')
    parser.add_argument('--config', required=True, help='Path to TOML config')
    parser.add_argument('--send-to', help='Recipient public key (b64)')
    parser.add_argument('--text', help='Message text')
    parser.add_argument('--ttl', type=int, default=MESH_TTL_DEFAULT)
    args = parser.parse_args()
    asyncio.run(main_node(args.config, args.send_to, args.text, args.ttl))
