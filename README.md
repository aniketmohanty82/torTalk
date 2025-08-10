# torTalk
trying a tor based messaging app

## Install deps
### Python 3.11+
#### macOS/Linux:
- python -m venv .venv && source .venv/bin/activate
- - pip install pynacl flask flask-cors requests tomli
#### Windows (PowerShell):
- py -m venv .venv; .venv\Scripts\Activate.ps1
- pip install pynacl flask flask-cors requests tomli

## 1) Start the central server
In one terminal:
- ``` python server.py ```

## 2) Configure a node
Copy settings.example.toml to settings.toml and adjust the TCP port if running multiple nodes on one machine.

## 3) Start two nodes (two terminals or two machines on same LAN)
``` python node.py --config settings.toml ```
``` python node.py --config settings2.toml ```

## 4) Get the recipient public key
When a node starts, it will print nothing by default; you can open node_identity.bin to extract the b64 public key or add a small snippet to print it (future improvement). For now:
  - run a Python REPL and use crypto_utils.load_or_create_identity('node_identity.bin').pub_b64

## 5) Send a message
From Node A terminal:
- python node.py --config settings.toml --send-to <RECIPIENT_PUB_B64> --text "Hello from mesh!" --ttl 4
- Leave the receiving node running; it will deliver via LAN gossip or via server sync when available.

## 6) Safety mode (Tor for server sync)
- Install Tor locally and start the SOCKS proxy (default 9050).
- In settings.toml, set:
  - safety_mode = true
  - tor_socks = "socks5h://127.0.0.1:9050"
- Restart the node. Server sync now goes through Tor. LAN mesh continues to work locally.

## 7) Offline/Low connectivity behavior
- If both nodes are offline from the internet but share the same LAN, messages deliver via mesh gossip only.
- If nodes are separated, each stores outbound messages locally until *either* gains internet; then they sync via the server (direct or Tor).

## 8) Caveats / Next steps
- Proper contact QR exchange, better key UX, and background-friendly mobile builds (Kivy/React Native + native modules) are future work.
- Add message padding, batch sync, proof-of-work for spam resistance, and robust signature checks on the server.
- Replace LAN multicast with libp2p or a DHT for Internet-scale discovery.
- For full Tor P2P, give each node an onion service and swap addresses out-of-band.
