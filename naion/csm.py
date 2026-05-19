"""
CSM = client-server-model
Updated runtime secure messaging helper aligned with the C++ and Go protocol.

Model:
- Client holds server Ed25519 public key.
- Server does not know client key material until the first client packet is decrypted.

Packet format:
- outer packet (both directions):
  signature(64) | session_x25519_pk(32) | nonce(24) | mac(16) | ciphertext

- client -> server plaintext before seal:
  client_ed25519_pk(32) | app_plaintext

- server -> client plaintext before seal:
  app_plaintext

Cipher suite:
- Ed25519 detached signature
- X25519 shared key agreement
- XChaCha20-Poly1305-IETF with session_x25519_pk as AAD
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from nacl import bindings
from nacl.exceptions import BadSignatureError, CryptoError
from nacl.utils import random as random_bytes


SIGN_BYTES = bindings.crypto_sign_BYTES
ED_SEED_BYTES = bindings.crypto_sign_SEEDBYTES
ED_PK_BYTES = bindings.crypto_sign_PUBLICKEYBYTES
ED_SK_BYTES = bindings.crypto_sign_SECRETKEYBYTES
X_PK_BYTES = bindings.crypto_box_PUBLICKEYBYTES
X_SK_BYTES = bindings.crypto_box_SECRETKEYBYTES
NONCE_BYTES = bindings.crypto_box_NONCEBYTES
MAC_BYTES = getattr(bindings, "crypto_box_MACBYTES", 16)

MAX_UDP_DATAGRAM_BYTES = 1024
PACKET_FIXED_OVERHEAD_BYTES = SIGN_BYTES + X_PK_BYTES + NONCE_BYTES + MAC_BYTES
CLIENT_PACKET_FIXED_BYTES = PACKET_FIXED_OVERHEAD_BYTES + ED_PK_BYTES
SERVER_PACKET_FIXED_BYTES = PACKET_FIXED_OVERHEAD_BYTES
MAX_CLIENT_PAYLOAD_BYTES = MAX_UDP_DATAGRAM_BYTES - CLIENT_PACKET_FIXED_BYTES
MAX_SERVER_PAYLOAD_BYTES = MAX_UDP_DATAGRAM_BYTES - SERVER_PACKET_FIXED_BYTES
DEFAULT_REPLAY_RETENTION_MS = 5 * 60 * 1000


class CSMError(Exception):
    pass


class VerifyFailed(CSMError):
    pass


class InvalidPacket(CSMError):
    pass


class StateError(CSMError):
    pass


class PayloadTooLarge(CSMError):
    pass


def init() -> int:
    return bindings.sodium_init()


def client_encrypt_size(plaintext_len: int) -> int:
    return 0 if plaintext_len < 0 else CLIENT_PACKET_FIXED_BYTES + plaintext_len


def client_decrypt_max_plaintext_size(packet_len: int) -> int:
    return 0 if packet_len <= SERVER_PACKET_FIXED_BYTES else packet_len - SERVER_PACKET_FIXED_BYTES


def server_encrypt_size(plaintext_len: int) -> int:
    return 0 if plaintext_len < 0 else SERVER_PACKET_FIXED_BYTES + plaintext_len


def server_decrypt_max_plaintext_size(packet_len: int) -> int:
    return 0 if packet_len <= CLIENT_PACKET_FIXED_BYTES else packet_len - CLIENT_PACKET_FIXED_BYTES


def _ensure_size(name: str, value: bytes, expected: int) -> None:
    if len(value) != expected:
        raise CSMError(f"{name} size mismatch: got {len(value)}, expected {expected}")


def _sign_detached(message: bytes, ed_secret_key: bytes) -> bytes:
    _ensure_size("ed_secret_key", ed_secret_key, ED_SK_BYTES)
    signed = bindings.crypto_sign(message, ed_secret_key)
    return signed[:SIGN_BYTES]


def _verify_detached(signature: bytes, message: bytes, ed_public_key: bytes) -> bool:
    _ensure_size("signature", signature, SIGN_BYTES)
    _ensure_size("ed_public_key", ed_public_key, ED_PK_BYTES)
    try:
        opened = bindings.crypto_sign_open(signature + message, ed_public_key)
        return opened == message
    except BadSignatureError:
        return False


def _ed_pk_to_xpk(ed_public_key: bytes) -> bytes:
    _ensure_size("ed_public_key", ed_public_key, ED_PK_BYTES)
    return bindings.crypto_sign_ed25519_pk_to_curve25519(ed_public_key)


def _ed_sk_to_xsk(ed_secret_key: bytes) -> bytes:
    _ensure_size("ed_secret_key", ed_secret_key, ED_SK_BYTES)
    return bindings.crypto_sign_ed25519_sk_to_curve25519(ed_secret_key)


def _x25519_keypair() -> Tuple[bytes, bytes]:
    return bindings.crypto_box_keypair()


def _rotl32(value: int, bits: int) -> int:
    return ((value << bits) & 0xFFFFFFFF) | (value >> (32 - bits))


def _quarterround(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl32(state[b] ^ state[c], 7)


def _hchacha20(key: bytes, nonce16: bytes) -> bytes:
    _ensure_size("hchacha20_key", key, 32)
    _ensure_size("hchacha20_nonce", nonce16, 16)
    constants = b"expand 32-byte k"
    words = [
        int.from_bytes(constants[i : i + 4], "little")
        for i in range(0, 16, 4)
    ]
    words.extend(int.from_bytes(key[i : i + 4], "little") for i in range(0, 32, 4))
    words.extend(int.from_bytes(nonce16[i : i + 4], "little") for i in range(0, 16, 4))
    for _ in range(10):
        _quarterround(words, 0, 4, 8, 12)
        _quarterround(words, 1, 5, 9, 13)
        _quarterround(words, 2, 6, 10, 14)
        _quarterround(words, 3, 7, 11, 15)
        _quarterround(words, 0, 5, 10, 15)
        _quarterround(words, 1, 6, 11, 12)
        _quarterround(words, 2, 7, 8, 13)
        _quarterround(words, 3, 4, 9, 14)
    out_words = words[:4] + words[12:16]
    return b"".join(word.to_bytes(4, "little") for word in out_words)


def _derive_aead_key(peer_xpk: bytes, self_xsk: bytes) -> bytes:
    shared = bindings.crypto_scalarmult(self_xsk, peer_xpk)
    return _hchacha20(shared, b"\x00" * 16)


def _seal(plaintext: bytes, peer_xpk: bytes, self_xsk: bytes, aad: bytes) -> bytes:
    if not plaintext:
        raise CSMError("seal plaintext is empty")
    nonce = random_bytes(NONCE_BYTES)
    _ensure_size("peer_xpk", peer_xpk, X_PK_BYTES)
    _ensure_size("self_xsk", self_xsk, X_SK_BYTES)
    ekey = _derive_aead_key(peer_xpk, self_xsk)
    encrypted = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, ekey)
    return nonce + encrypted[-MAC_BYTES:] + encrypted[:-MAC_BYTES]


def _open(nonce_cipher: bytes, peer_xpk: bytes, self_xsk: bytes, aad: bytes) -> bytes:
    if len(nonce_cipher) <= NONCE_BYTES + MAC_BYTES:
        raise InvalidPacket("ciphertext too short")
    nonce = nonce_cipher[:NONCE_BYTES]
    mac = nonce_cipher[NONCE_BYTES : NONCE_BYTES + MAC_BYTES]
    ciphertext = nonce_cipher[NONCE_BYTES + MAC_BYTES :]
    _ensure_size("peer_xpk", peer_xpk, X_PK_BYTES)
    _ensure_size("self_xsk", self_xsk, X_SK_BYTES)
    try:
        ekey = _derive_aead_key(peer_xpk, self_xsk)
        return bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext + mac, aad, nonce, ekey)
    except CryptoError as e:
        raise CSMError("open failed") from e


@dataclass
class Client:
    ed_seed: bytes
    ed_secret_key: bytes
    ed_public_key: bytes
    server_ed_public_key: bytes

    @classmethod
    def create(cls, ed_seed_client: bytes, ed_public_key_server: bytes) -> "Client":
        _ensure_size("ed_seed_client", ed_seed_client, ED_SEED_BYTES)
        _ensure_size("ed_public_key_server", ed_public_key_server, ED_PK_BYTES)
        ed_public_key, ed_secret_key = bindings.crypto_sign_seed_keypair(ed_seed_client)
        return cls(ed_seed_client, ed_secret_key, ed_public_key, ed_public_key_server)

    def encrypt(self, plaintext: bytes) -> bytes:
        if not plaintext:
            raise CSMError("client encrypt empty data")
        if len(plaintext) > MAX_CLIENT_PAYLOAD_BYTES:
            raise PayloadTooLarge("client payload exceeds UDP budget")
        server_xpk = _ed_pk_to_xpk(self.server_ed_public_key)
        session_xpk, session_xsk = _x25519_keypair()
        payload = self.ed_public_key + plaintext
        nonce_cipher = _seal(payload, server_xpk, session_xsk, session_xpk)
        body = session_xpk + nonce_cipher
        sig = _sign_detached(body, self.ed_secret_key)
        return sig + body

    def decrypt(self, packet: bytes) -> bytes:
        min_size = SERVER_PACKET_FIXED_BYTES
        if len(packet) <= min_size:
            raise InvalidPacket("client decrypt packet too short")
        signature = packet[:SIGN_BYTES]
        body = packet[SIGN_BYTES:]
        if not _verify_detached(signature, body, self.server_ed_public_key):
            raise VerifyFailed("client decrypt signature verify failed")
        session_xpk = body[:X_PK_BYTES]
        nonce_cipher = body[X_PK_BYTES:]
        client_xsk = _ed_sk_to_xsk(self.ed_secret_key)
        plaintext = _open(nonce_cipher, session_xpk, client_xsk, session_xpk)
        if not plaintext:
            raise InvalidPacket("client decrypt payload missing")
        return plaintext


@dataclass
class Server:
    ed_seed: bytes
    ed_secret_key: bytes
    ed_public_key: bytes
    client_ed_public_key: Optional[bytes] = None

    @classmethod
    def create(cls, ed_seed_server: bytes) -> "Server":
        _ensure_size("ed_seed_server", ed_seed_server, ED_SEED_BYTES)
        ed_public_key, ed_secret_key = bindings.crypto_sign_seed_keypair(ed_seed_server)
        return cls(ed_seed_server, ed_secret_key, ed_public_key, None)

    @property
    def client_public_key_initialized(self) -> bool:
        return self.client_ed_public_key is not None

    def decrypt(self, packet: bytes) -> bytes:
        min_size = CLIENT_PACKET_FIXED_BYTES
        if len(packet) <= min_size:
            raise InvalidPacket("server decrypt packet too short")
        signature = packet[:SIGN_BYTES]
        body = packet[SIGN_BYTES:]
        session_xpk = body[:X_PK_BYTES]
        nonce_cipher = body[X_PK_BYTES:]
        server_xsk = _ed_sk_to_xsk(self.ed_secret_key)
        opened = _open(nonce_cipher, session_xpk, server_xsk, session_xpk)
        if len(opened) <= ED_PK_BYTES:
            raise InvalidPacket("server decrypt opened payload too short")
        client_ed_pk = opened[:ED_PK_BYTES]
        plaintext = opened[ED_PK_BYTES:]
        if not _verify_detached(signature, body, client_ed_pk):
            raise VerifyFailed("server decrypt signature verify failed")
        self.client_ed_public_key = client_ed_pk
        return plaintext

    def encrypt(self, plaintext: bytes) -> bytes:
        if not self.client_public_key_initialized:
            raise StateError("server encrypt client public key is not initialized")
        if not plaintext:
            raise CSMError("server encrypt empty data")
        if len(plaintext) > MAX_SERVER_PAYLOAD_BYTES:
            raise PayloadTooLarge("server payload exceeds UDP budget")
        assert self.client_ed_public_key is not None
        client_xpk = _ed_pk_to_xpk(self.client_ed_public_key)
        session_xpk, session_xsk = _x25519_keypair()
        nonce_cipher = _seal(plaintext, client_xpk, session_xsk, session_xpk)
        body = session_xpk + nonce_cipher
        sig = _sign_detached(body, self.ed_secret_key)
        return sig + body
