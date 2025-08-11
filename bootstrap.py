# bootstrap.py
import os, io, socket, time, base64, secrets
from pathlib import Path

# pip install toml msgpack pynacl platformdirs
import toml, msgpack
from platformdirs import user_data_dir
from nacl.public import PrivateKey as Curve25519PrivateKey
from nacl.signing import SigningKey as Ed25519SigningKey

APP_NAME = "torTalk"

def _b64(b: bytes) -> str:
    import base64 as b64m
    return b64m.b64encode(b).decode("ascii")

def _find_free_port(start=45454, end=65500):
    for p in range(start, end):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("0.0.0.0", p))
                return p
            except OSError:
                continue
    raise RuntimeError("No free port found")

def _app_dir(profile="default"):
    root = Path(user_data_dir(APP_NAME))
    d = root / profile
    d.mkdir(parents=True, exist_ok=True)
    return d

def _default_cfg(dirpath: Path, port: int, server_url: str, safety_mode: bool, tor_socks: str):
    cfg = {
        "identity": {"path": str(dirpath / "identity.bin")},
        "storage": {"path": str(dirpath / "store.sqlite")},
        "network": {"tcp_port": port},
        "user": {"username": os.getenv("MESH_USERNAME", f"user-{secrets.token_hex(3)}")},
        "server": {
            "url": server_url,
            "safety_mode": bool(safety_mode),
        },
        "node": {"profile": dirpath.name, "created_at": int(time.time())},
        "version": 1
    }
    if safety_mode:
        cfg["server"]["tor_socks"] = tor_socks
    return cfg

def _gen_identity(path: Path, name: str):
    enc_sk = Curve25519PrivateKey.generate()
    sig_sk = Ed25519SigningKey.generate()
    ident = {
        "version": 1,
        "created_at": int(time.time()),
        "name": name,
        "nonce": secrets.token_bytes(16),
        "enc_sk": enc_sk.encode(),
        "enc_pk": enc_sk.public_key.encode(),
        "sig_sk": sig_sk.encode(),
        "sig_pk": sig_sk.verify_key.encode(),
    }
    path.write_bytes(msgpack.packb(ident, use_bin_type=True))

def _load_identity(path: Path):
    return msgpack.unpackb(path.read_bytes(), raw=False)

def _write_toml(path: Path, cfg: dict):
    with io.open(path, "w", encoding="utf-8") as f:
        toml.dump(cfg, f)

def _address_from_ident(ident: dict) -> str:
    return f"mesh:{_b64(ident['enc_pk'])}.{_b64(ident['sig_pk'])}"

def ensure_initialized(
    profile: str | None = None,
    settings_path: str | None = None,
    server_url: str | None = None,
    safety_mode: bool | None = None,
    tor_socks: str | None = None,
    prefer_port: int | None = None,
):
    """
    Auto-creates config + identity on first run.
    Returns (cfg_path, cfg_dict, ident_dict, address_str).
    Env overrides:
      MESH_PROFILE, MESH_SERVER_URL, MESH_SAFETY_MODE, MESH_TOR_SOCKS, MESH_PORT
    """
    profile = profile or os.getenv("MESH_PROFILE", "default")
    server_url = server_url or os.getenv("MESH_SERVER_URL", "http://127.0.0.1:8080")
    safety_mode = (bool(int(os.getenv("MESH_SAFETY_MODE", "0"))) if safety_mode is None else safety_mode)
    tor_socks = tor_socks or os.getenv("MESH_TOR_SOCKS", "socks5h://127.0.0.1:9050")

    d = _app_dir(profile)
    cfg_file = Path(settings_path) if settings_path else (d / "settings.toml")
    ident_file = d / "identity.bin"

    if not cfg_file.exists():
        port = prefer_port or (int(os.getenv("MESH_PORT")) if os.getenv("MESH_PORT") else _find_free_port())
        cfg = _default_cfg(d, port, server_url, safety_mode, tor_socks)
        _write_toml(cfg_file, cfg)
    else:
        cfg = toml.load(cfg_file)

    if not ident_file.exists():
        _gen_identity(ident_file, profile)

    ident = _load_identity(ident_file)
    addr = _address_from_ident(ident)

    print(f"✅ profile: {profile}")
    print(f"  config : {cfg_file}")
    print(f"  db     : {cfg['storage']['path']}")
    print(f"  port   : {cfg['network']['tcp_port']}")
    print(f"  server : {cfg['server']['url']}  (safety_mode={cfg['server'].get('safety_mode', False)})")
    print(f"  address: {addr}")

    return str(cfg_file), cfg, ident, addr
