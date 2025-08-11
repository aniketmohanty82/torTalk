import argparse, os, time, msgpack, toml, base64, secrets
from nacl.public import PrivateKey as Curve25519PrivateKey
from nacl.signing import SigningKey as Ed25519SigningKey

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode('ascii')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True, help="logical node name (e.g., node1)")
    ap.add_argument("--settings", default="settings.toml", help="output TOML filename")
    ap.add_argument("--id-path", default=None, help="identity .bin path (default: <name>_identity.bin)")
    ap.add_argument("--db", default=None, help="sqlite path (default: <name>_store.sqlite)")
    ap.add_argument("--port", type=int, required=True, help="mesh TCP port (e.g., 45454)")
    ap.add_argument("--server", default="http://127.0.0.1:8080", help="central sync server URL")
    ap.add_argument("--safety-mode", action="store_true", help="use Tor for server sync")
    ap.add_argument("--tor-socks", default="socks5h://127.0.0.1:9050", help="Tor SOCKS endpoint if safety-mode")
    args = ap.parse_args()

    ident_path = args.id_path or f"{args.name}_identity.bin"
    db_path = args.db or f"{args.name}_store.sqlite"

    if os.path.exists(ident_path):
        raise SystemExit(f"Refusing to overwrite existing identity: {ident_path}")

    # Generate keys
    enc_sk = Curve25519PrivateKey.generate()
    enc_pk = enc_sk.public_key
    sig_sk = Ed25519SigningKey.generate()
    sig_pk = sig_sk.verify_key

    # Pack a binary identity (msgpack)
    ident = {
        "version": 1,
        "created_at": int(time.time()),
        "enc_sk": enc_sk.encode(),     # 32 bytes
        "enc_pk": enc_pk.encode(),     # 32 bytes
        "sig_sk": sig_sk.encode(),     # 32 bytes
        "sig_pk": sig_pk.encode(),     # 32 bytes
        "name": args.name,
        "nonce": secrets.token_bytes(16),
    }
    with open(ident_path, "wb") as f:
        f.write(msgpack.packb(ident, use_bin_type=True))

    # Write TOML
    cfg = {
        "identity": {"path": ident_path},
        "storage": {"path": db_path},
        "network": {"tcp_port": args.port},
        "server": {
            "url": args.server,
            "safety_mode": bool(args.safety_mode),
        }
    }
    if args.safety_mode:
        cfg["server"]["tor_socks"] = args.tor_socks

    with open(args.settings, "w") as f:
        toml.dump(cfg, f)

    # Print shareable info
    print("✅ Created:")
    print(f"  identity: {ident_path}")
    print(f"  config:   {args.settings}")
    print(f"  db:       {db_path}")
    print("\nShare this node’s address with peers:")
    addr = f"mesh:{b64(enc_pk.encode())}.{b64(sig_pk.encode())}"
    print(f"  address:  {addr}")
    print("  enc_pk:   ", b64(enc_pk.encode()))
    print("  sig_pk:   ", b64(sig_pk.encode()))
    print("\nKeep the .bin file secret. Distribute ONLY the public keys or address.")
if __name__ == "__main__":
    main()
