from __future__ import annotations
import base64
import os
from dataclasses import dataclass
from typing import Tuple
from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.signing import SigningKey, VerifyKey
from nacl.hash import blake2b
from nacl.encoding import RawEncoder


@dataclass
class Identity:
    # Curve25519 keypair for encryption
    priv: PrivateKey
    pub: PublicKey
    # Ed25519 keypair for signatures
    sign_priv: SigningKey
    sign_pub: VerifyKey

    @property
    def pub_b64(self) -> str:
        return base64.b64encode(bytes(self.pub)).decode()

    @property
    def sign_b64(self) -> str:
        return base64.b64encode(bytes(self.sign_pub)).decode()


def load_or_create_identity(path: str) -> Identity:
    if os.path.exists(path):
        with open(path, 'rb') as f:
            blob = f.read()
        enc_sk = PrivateKey(blob[:32])
        sig_sk = SigningKey(blob[32:64])
    else:
        enc_sk = PrivateKey.generate()
        sig_sk = SigningKey.generate()
        with open(path, 'wb') as f:
            f.write(bytes(enc_sk) + bytes(sig_sk))
    return Identity(priv=enc_sk, pub=enc_sk.public_key, sign_priv=sig_sk, sign_pub=sig_sk.verify_key)


def seal_for(recipient_pub_b64: str, plaintext: bytes) -> bytes:
    pub = PublicKey(base64.b64decode(recipient_pub_b64))
    box = SealedBox(pub)
    return box.encrypt(plaintext)


def open_sealed(identity: Identity, ciphertext: bytes) -> bytes:
    box = SealedBox(identity.priv)
    return box.decrypt(ciphertext)


def sign(identity: Identity, payload: bytes) -> bytes:
    return identity.sign_priv.sign(payload).signature


def verify(signature: bytes, payload: bytes, signer_verify_b64: str) -> bool:
    try:
        vk = VerifyKey(base64.b64decode(signer_verify_b64))
        vk.verify(payload, signature)
        return True
    except Exception:
        return False


def msg_id(ciphertext: bytes) -> str:
    # content-address (blake2b) to dedupe across mesh/server
    return blake2b(ciphertext, encoder=RawEncoder).hex()
