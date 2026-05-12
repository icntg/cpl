"""
CSM = client-server-model
Updated runtime secure messaging helper aligned with the C++ and Go protocol.

Model:
- Client holds server Ed25519 public key.
- Server does not know client key material until the first client packet is decrypted.

Packet format:
- outer packet (both directions):
  signature(64) | session_x25519_pk(32) | nonce(24) | ciphertext+mac

- client -> server plaintext before seal:
  packet_meta(16) | client_ed25519_pk(32) | app_plaintext

- server -> client plaintext before seal:
  packet_meta(16) | app_plaintext

Cipher suite:
- Ed25519 detached signature
- X25519 shared key agreement
- libsodium-compatible crypto_box / naion_box_easy
"""

from __future__ import annotations

import hashlib
import struct
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional, Protocol, Tuple

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

PACKET_MAGIC = b"IFW1"
PACKET_PROTOCOL_VERSION = 1
PACKET_META_FORMAT = "<4sBBHQ"
PACKET_META_BYTES = struct.calcsize(PACKET_META_FORMAT)
MAX_UDP_DATAGRAM_BYTES = 1024
PACKET_FIXED_OVERHEAD_BYTES = SIGN_BYTES + X_PK_BYTES + NONCE_BYTES + MAC_BYTES
CLIENT_PACKET_FIXED_BYTES = PACKET_FIXED_OVERHEAD_BYTES + PACKET_META_BYTES + ED_PK_BYTES
SERVER_PACKET_FIXED_BYTES = PACKET_FIXED_OVERHEAD_BYTES + PACKET_META_BYTES
MAX_CLIENT_PAYLOAD_BYTES = MAX_UDP_DATAGRAM_BYTES - CLIENT_PACKET_FIXED_BYTES
MAX_SERVER_PAYLOAD_BYTES = MAX_UDP_DATAGRAM_BYTES - SERVER_PACKET_FIXED_BYTES
DEFAULT_REPLAY_RETENTION_MS = 5 * 60 * 1000


class CSMError(Exception):
    pass


class VerifyFailed(CSMError):
    pass


class InvalidPacket(CSMError):
    pass


class InvalidMeta(CSMError):
    pass


class StateError(CSMError):
    pass


class PayloadTooLarge(CSMError):
    pass


class TimestampOutsideWindow(CSMError):
    pass


class ReplayDetected(CSMError):
    pass


class ReplayCache(Protocol):
    def check_and_store(self, client_public_key: bytes, signature: bytes, timestamp_ms: int, now_ms: int) -> None:
        ...


class MemoryReplayCache:
    def __init__(self, retention_ms: int = DEFAULT_REPLAY_RETENTION_MS) -> None:
        self.retention_ms = retention_ms or DEFAULT_REPLAY_RETENTION_MS
        self._entries: dict[bytes, int] = {}
        self._lock = threading.Lock()

    def check_and_store(self, client_public_key: bytes, signature: bytes, timestamp_ms: int, now_ms: int) -> None:
        _ = timestamp_ms
        key = hashlib.sha256(client_public_key + signature).digest()
        with self._lock:
            expired = [entry_key for entry_key, expiry in self._entries.items() if expiry <= now_ms]
            for entry_key in expired:
                self._entries.pop(entry_key, None)
            expiry = self._entries.get(key)
            if expiry is not None and expiry > now_ms:
                raise ReplayDetected("replay detected")
            self._entries[key] = now_ms + self.retention_ms


@dataclass(frozen=True)
class PacketMeta:
    protocol_version: int = PACKET_PROTOCOL_VERSION
    reserved: int = 0
    flags: int = 0
    timestamp_ms: int = 0


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


def _current_timestamp_ms(now_ms_provider: Optional[Callable[[], int]]) -> int:
    if now_ms_provider is None:
        return int(time.time_ns() // 1_000_000)
    return int(now_ms_provider())


def _new_packet_meta(now_ms_provider: Optional[Callable[[], int]]) -> PacketMeta:
    return PacketMeta(timestamp_ms=_current_timestamp_ms(now_ms_provider))


def _pack_packet_meta(meta: PacketMeta) -> bytes:
    return struct.pack(
        PACKET_META_FORMAT,
        PACKET_MAGIC,
        meta.protocol_version,
        meta.reserved,
        meta.flags,
        meta.timestamp_ms,
    )


def _parse_packet_meta(buffer: bytes) -> Tuple[PacketMeta, bytes]:
    if len(buffer) < PACKET_META_BYTES:
        raise InvalidMeta("packet meta too short")
    magic, protocol_version, reserved, flags, timestamp_ms = struct.unpack(
        PACKET_META_FORMAT,
        buffer[:PACKET_META_BYTES],
    )
    if magic != PACKET_MAGIC:
        raise InvalidMeta("packet meta magic invalid")
    if protocol_version != PACKET_PROTOCOL_VERSION:
        raise InvalidMeta("packet meta version invalid")
    return PacketMeta(protocol_version, reserved, flags, timestamp_ms), buffer[PACKET_META_BYTES:]


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


def _seal(plaintext: bytes, peer_xpk: bytes, self_xsk: bytes) -> bytes:
    if not plaintext:
        raise CSMError("seal plaintext is empty")
    nonce = random_bytes(NONCE_BYTES)
    _ensure_size("peer_xpk", peer_xpk, X_PK_BYTES)
    _ensure_size("self_xsk", self_xsk, X_SK_BYTES)
    return nonce + bindings.crypto_box(plaintext, nonce, peer_xpk, self_xsk)


def _open(nonce_cipher: bytes, peer_xpk: bytes, self_xsk: bytes) -> bytes:
    if len(nonce_cipher) <= NONCE_BYTES + MAC_BYTES:
        raise InvalidPacket("ciphertext too short")
    nonce = nonce_cipher[:NONCE_BYTES]
    mac_ciphertext = nonce_cipher[NONCE_BYTES:]
    _ensure_size("peer_xpk", peer_xpk, X_PK_BYTES)
    _ensure_size("self_xsk", self_xsk, X_SK_BYTES)
    try:
        return bindings.crypto_box_open(mac_ciphertext, nonce, peer_xpk, self_xsk)
    except CryptoError as e:
        raise CSMError("open failed") from e


@dataclass
class Client:
    ed_seed: bytes
    ed_secret_key: bytes
    ed_public_key: bytes
    server_ed_public_key: bytes
    now_ms_provider: Optional[Callable[[], int]] = None

    @classmethod
    def create(cls, ed_seed_client: bytes, ed_public_key_server: bytes) -> "Client":
        _ensure_size("ed_seed_client", ed_seed_client, ED_SEED_BYTES)
        _ensure_size("ed_public_key_server", ed_public_key_server, ED_PK_BYTES)
        ed_public_key, ed_secret_key = bindings.crypto_sign_seed_keypair(ed_seed_client)
        return cls(ed_seed_client, ed_secret_key, ed_public_key, ed_public_key_server)

    def set_now_ms_provider(self, now_ms_provider: Optional[Callable[[], int]]) -> None:
        self.now_ms_provider = now_ms_provider

    def encrypt(self, plaintext: bytes) -> bytes:
        if not plaintext:
            raise CSMError("client encrypt empty data")
        if len(plaintext) > MAX_CLIENT_PAYLOAD_BYTES:
            raise PayloadTooLarge("client payload exceeds UDP budget")
        server_xpk = _ed_pk_to_xpk(self.server_ed_public_key)
        session_xpk, session_xsk = _x25519_keypair()
        payload = _pack_packet_meta(_new_packet_meta(self.now_ms_provider)) + self.ed_public_key + plaintext
        nonce_cipher = _seal(payload, server_xpk, session_xsk)
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
        opened = _open(nonce_cipher, session_xpk, client_xsk)
        _meta, plaintext = _parse_packet_meta(opened)
        if not plaintext:
            raise InvalidPacket("client decrypt payload missing")
        return plaintext


@dataclass
class Server:
    ed_seed: bytes
    ed_secret_key: bytes
    ed_public_key: bytes
    client_ed_public_key: Optional[bytes] = None
    timestamp_window_ms: int = 0
    replay_cache: Optional[ReplayCache] = None
    now_ms_provider: Optional[Callable[[], int]] = None

    @classmethod
    def create(cls, ed_seed_server: bytes) -> "Server":
        _ensure_size("ed_seed_server", ed_seed_server, ED_SEED_BYTES)
        ed_public_key, ed_secret_key = bindings.crypto_sign_seed_keypair(ed_seed_server)
        return cls(ed_seed_server, ed_secret_key, ed_public_key, None)

    @property
    def client_public_key_initialized(self) -> bool:
        return self.client_ed_public_key is not None

    def set_now_ms_provider(self, now_ms_provider: Optional[Callable[[], int]]) -> None:
        self.now_ms_provider = now_ms_provider

    def set_timestamp_window_ms(self, timestamp_window_ms: int) -> None:
        self.timestamp_window_ms = max(0, int(timestamp_window_ms))

    def set_replay_cache(self, replay_cache: Optional[ReplayCache]) -> None:
        self.replay_cache = replay_cache

    def _validate_timestamp(self, meta: PacketMeta) -> None:
        if self.timestamp_window_ms <= 0:
            return
        now_ms = _current_timestamp_ms(self.now_ms_provider)
        if abs(now_ms - meta.timestamp_ms) > self.timestamp_window_ms:
            raise TimestampOutsideWindow("timestamp outside validation window")

    def _check_replay(self, client_public_key: bytes, signature: bytes, timestamp_ms: int) -> None:
        if self.replay_cache is None:
            return
        self.replay_cache.check_and_store(
            client_public_key,
            signature,
            timestamp_ms,
            _current_timestamp_ms(self.now_ms_provider),
        )

    def decrypt(self, packet: bytes) -> bytes:
        min_size = CLIENT_PACKET_FIXED_BYTES
        if len(packet) <= min_size:
            raise InvalidPacket("server decrypt packet too short")
        signature = packet[:SIGN_BYTES]
        body = packet[SIGN_BYTES:]
        session_xpk = body[:X_PK_BYTES]
        nonce_cipher = body[X_PK_BYTES:]
        server_xsk = _ed_sk_to_xsk(self.ed_secret_key)
        opened = _open(nonce_cipher, session_xpk, server_xsk)
        meta, payload = _parse_packet_meta(opened)
        if len(payload) <= ED_PK_BYTES:
            raise InvalidPacket("server decrypt opened payload too short")
        client_ed_pk = payload[:ED_PK_BYTES]
        plaintext = payload[ED_PK_BYTES:]
        if not _verify_detached(signature, body, client_ed_pk):
            raise VerifyFailed("server decrypt signature verify failed")
        self._validate_timestamp(meta)
        self._check_replay(client_ed_pk, signature, meta.timestamp_ms)
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
        payload = _pack_packet_meta(_new_packet_meta(self.now_ms_provider)) + plaintext
        nonce_cipher = _seal(payload, client_xpk, session_xsk)
        body = session_xpk + nonce_cipher
        sig = _sign_detached(body, self.ed_secret_key)
        return sig + body
