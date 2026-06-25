"""naion.py — single-file, byte-compatible Python port of naion.h.

Provides BLAKE2b (generichash), XChaCha20 stream/AEAD, secretbox, X25519/Box,
Ed25519, KX and the CSM/CSM-CA secure messaging layers, plus an optional
XSalsa20 family. Output is byte-for-byte interchangeable with the C and Go
versions.

The symmetric box/secretbox engine uses the classic NaCl construction
(poly1305 keyed by the first 32 bytes of an XChaCha20 keystream block, MAC
prepended to the ciphertext), while CSM packets and the explicit
aead_*_ietf_* family use the IETF XChaCha20-Poly1305 construction (padded
lengths Poly1305 input). Both are reproduced exactly.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct

import nacl.bindings
import nacl.exceptions

VERSION_STRING = "naion/0.2 (Python)"

# ===========================================================================
# Constants
# ===========================================================================

GENERICHASH_BYTES = 32
GENERICHASH_BYTES_MIN = 16
GENERICHASH_BYTES_MAX = 64
GENERICHASH_KEYBYTES = 32
GENERICHASH_KEYBYTES_MIN = 16
GENERICHASH_KEYBYTES_MAX = 64
GENERICHASH_SALTBYTES = 16
GENERICHASH_PERSONALBYTES = 16

STREAM_XCHACHA20_KEYBYTES = 32
STREAM_XCHACHA20_NONCEBYTES = 24

AEAD_XCHACHA20POLY1305_IETF_KEYBYTES = 32
AEAD_XCHACHA20POLY1305_IETF_NSECBYTES = 0
AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES = 24
AEAD_XCHACHA20POLY1305_IETF_ABYTES = 16

SECRETBOX_XCHACHA20POLY1305_KEYBYTES = 32
SECRETBOX_XCHACHA20POLY1305_NONCEBYTES = 24
SECRETBOX_XCHACHA20POLY1305_MACBYTES = 16

BOX_CURVE25519XCHACHA20POLY1305_SEEDBYTES = 32
BOX_CURVE25519XCHACHA20POLY1305_PUBLICKEYBYTES = 32
BOX_CURVE25519XCHACHA20POLY1305_SECRETKEYBYTES = 32
BOX_CURVE25519XCHACHA20POLY1305_BEFORENMBYTES = 32
BOX_CURVE25519XCHACHA20POLY1305_NONCEBYTES = 24
BOX_CURVE25519XCHACHA20POLY1305_MACBYTES = 16
BOX_CURVE25519XCHACHA20POLY1305_SEALBYTES = 48

SCALARMULT_CURVE25519_BYTES = 32
SCALARMULT_CURVE25519_SCALARBYTES = 32

KX_PUBLICKEYBYTES = 32
KX_SECRETKEYBYTES = 32
KX_SEEDBYTES = 32
KX_SESSIONKEYBYTES = 32

SIGN_ED25519_BYTES = 64
SIGN_ED25519_SEEDBYTES = 32
SIGN_ED25519_PUBLICKEYBYTES = 32
SIGN_ED25519_SECRETKEYBYTES = 64

BOX_SEEDBYTES_MAX = 32
BOX_PUBLICKEYBYTES_MAX = 32
BOX_SECRETKEYBYTES_MAX = 32
BOX_BEFORENMBYTES_MAX = 32
BOX_NONCEBYTES_MAX = 24
BOX_MACBYTES_MAX = 16
BOX_SEALBYTES_MAX = 48

CSM_PACKET_OVERHEAD = 136
CSM_CLIENT_PK_BYTES = 32
CSM_MAX_UDP_DATAGRAM_BYTES = 1024
CSM_MAX_CLIENT_PAYLOAD_BYTES = 856
CSM_MAX_SERVER_PAYLOAD_BYTES = 888

CSM_CA_CERT_BYTES = 96

# ===========================================================================
# Exception hierarchy
# ===========================================================================


class NaionError(Exception):
    """Base class for all Naion errors."""


class NaionCryptoError(NaionError):
    """A cryptographic operation failed."""


class NaionArgumentError(NaionError, ValueError):
    """An argument was invalid."""


class NaionBufferError(NaionError):
    """A buffer was too small."""


class NaionStateError(NaionError):
    """An invalid state was encountered."""


class NaionRandomProviderError(NaionError):
    """The randomness provider failed."""


class CSMError(NaionError):
    """Base class for CSM errors (carries a C-compatible error code)."""
    code = 0


class CSMInvalidArgumentError(CSMError, NaionArgumentError):
    code = -1


class CSMBufferTooSmallError(CSMError, NaionBufferError):
    code = -2


class CSMCryptoError(CSMError, NaionCryptoError):
    code = -3


class CSMVerifyFailedError(CSMError, NaionCryptoError):
    code = -4


class CSMStateError(CSMError, NaionStateError):
    code = -5


class CSMRandomProviderError(CSMError, NaionRandomProviderError):
    code = -6


class CSMNoDataError(CSMError, NaionArgumentError):
    code = -7


def _csm_error_from_code(code: int) -> CSMError:
    mapping = {
        -1: CSMInvalidArgumentError,
        -2: CSMBufferTooSmallError,
        -3: CSMCryptoError,
        -4: CSMVerifyFailedError,
        -5: CSMStateError,
        -6: CSMRandomProviderError,
        -7: CSMNoDataError,
    }
    cls = mapping.get(code, CSMError)
    return cls(f"csm error {code}")


# ===========================================================================
# Infrastructure
# ===========================================================================

_random_provider = None  # type: ignore[assignment]


def _default_random(buf: bytearray) -> None:
    buf[:] = os.urandom(len(buf))


def set_random_provider(fn) -> None:
    global _random_provider
    _random_provider = fn


def get_random_provider():
    return _random_provider


def init() -> None:
    """libsodium-style core init; currently a no-op."""
    return None


def memzero(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0


def memcmp(a: bytes, b: bytes) -> int:
    if len(a) != len(b):
        return -1
    return 0 if hmac.compare_digest(a, b) else -1


def is_zero(buf) -> bool:
    return all(b == 0 for b in buf)


def verify_32(x: bytes, y: bytes) -> int:
    return 1 if hmac.compare_digest(x, y) else 0


def _fill_random(n: int) -> bytes:
    provider = _random_provider if _random_provider is not None else _default_random
    buf = bytearray(n)
    provider(buf)
    return bytes(buf)


# ===========================================================================
# Little-endian helpers
# ===========================================================================


def _rotl32(x: int, n: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _u32le(b: bytes, i: int = 0) -> int:
    return struct.unpack_from("<I", b, i)[0]


# ===========================================================================
# Salsa20 / HSalsa20 (for XSalsa20 box/secretbox)
# ===========================================================================


def _salsa20_qr(x, a, b, c, d):
    x[b] ^= _rotl32((x[a] + x[d]) & 0xFFFFFFFF, 7)
    x[c] ^= _rotl32((x[b] + x[a]) & 0xFFFFFFFF, 9)
    x[d] ^= _rotl32((x[c] + x[b]) & 0xFFFFFFFF, 13)
    x[a] ^= _rotl32((x[d] + x[c]) & 0xFFFFFFFF, 18)


def _salsa20_block(key: bytes, nonce8: bytes, ctr_low: int, ctr_high: int) -> bytes:
    st = [0] * 16
    st[0] = 0x61707865
    st[1] = _u32le(key, 0)
    st[2] = _u32le(key, 4)
    st[3] = _u32le(key, 8)
    st[4] = _u32le(key, 12)
    st[5] = 0x3320646E
    st[6] = _u32le(nonce8, 0)
    st[7] = _u32le(nonce8, 4)
    st[8] = ctr_low & 0xFFFFFFFF
    st[9] = ctr_high & 0xFFFFFFFF
    st[10] = 0x79622D32
    st[11] = _u32le(key, 16)
    st[12] = _u32le(key, 20)
    st[13] = _u32le(key, 24)
    st[14] = _u32le(key, 28)
    st[15] = 0x6B206574
    x = list(st)
    for _ in range(10):
        _salsa20_qr(x, 0, 4, 8, 12)
        _salsa20_qr(x, 5, 9, 13, 1)
        _salsa20_qr(x, 10, 14, 2, 6)
        _salsa20_qr(x, 15, 3, 7, 11)
        _salsa20_qr(x, 0, 1, 2, 3)
        _salsa20_qr(x, 5, 6, 7, 4)
        _salsa20_qr(x, 10, 11, 8, 9)
        _salsa20_qr(x, 15, 12, 13, 14)
    return struct.pack("<16I", *[(x[i] + st[i]) & 0xFFFFFFFF for i in range(16)])


def _hsalsa20(nonce16: bytes, key: bytes) -> bytes:
    x = [0] * 16
    x[0] = 0x61707865
    x[1] = _u32le(key, 0)
    x[2] = _u32le(key, 4)
    x[3] = _u32le(key, 8)
    x[4] = _u32le(key, 12)
    x[5] = 0x3320646E
    x[6] = _u32le(nonce16, 0)
    x[7] = _u32le(nonce16, 4)
    x[8] = _u32le(nonce16, 8)
    x[9] = _u32le(nonce16, 12)
    x[10] = 0x79622D32
    x[11] = _u32le(key, 16)
    x[12] = _u32le(key, 20)
    x[13] = _u32le(key, 24)
    x[14] = _u32le(key, 28)
    x[15] = 0x6B206574
    for _ in range(10):
        _salsa20_qr(x, 0, 4, 8, 12)
        _salsa20_qr(x, 5, 9, 13, 1)
        _salsa20_qr(x, 10, 14, 2, 6)
        _salsa20_qr(x, 15, 3, 7, 11)
        _salsa20_qr(x, 0, 1, 2, 3)
        _salsa20_qr(x, 5, 6, 7, 4)
        _salsa20_qr(x, 10, 11, 8, 9)
        _salsa20_qr(x, 15, 12, 13, 14)
    out = struct.pack(
        "<8I", x[0], x[5], x[10], x[15], x[6], x[7], x[8], x[9]
    )
    return out


def _xsalsa20_xor_ic(m: bytes, n24: bytes, ic: int, key: bytes) -> bytes:
    subkey = _hsalsa20(n24[:16], key)
    nonce8 = n24[16:24]
    ctr_low = ic & 0xFFFFFFFF
    ctr_high = (ic >> 32) & 0xFFFFFFFF
    out = bytearray(len(m))
    off = 0
    remaining = len(m)
    while remaining > 0:
        block = _salsa20_block(subkey, nonce8, ctr_low, ctr_high)
        ctr_low = (ctr_low + 1) & 0xFFFFFFFF
        if ctr_low == 0:
            ctr_high = (ctr_high + 1) & 0xFFFFFFFF
        take = min(remaining, 64)
        for i in range(take):
            out[off + i] = m[off + i] ^ block[i]
        off += take
        remaining -= take
    return bytes(out)


# ===========================================================================
# HChaCha20 + ChaCha20 (for XChaCha20 stream / box / IETF AEAD)
# ===========================================================================


def _chacha20_qr(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] ^= x[a]
    x[d] = _rotl32(x[d], 16)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] ^= x[c]
    x[b] = _rotl32(x[b], 12)
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] ^= x[a]
    x[d] = _rotl32(x[d], 8)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] ^= x[c]
    x[b] = _rotl32(x[b], 7)


def _hchacha20(key: bytes, nonce16: bytes) -> bytes:
    x = [0] * 16
    x[0] = 0x61707865
    x[1] = 0x3320646E
    x[2] = 0x79622D32
    x[3] = 0x6B206574
    for i in range(8):
        x[4 + i] = _u32le(key, 4 * i)
    x[12] = _u32le(nonce16, 0)
    x[13] = _u32le(nonce16, 4)
    x[14] = _u32le(nonce16, 8)
    x[15] = _u32le(nonce16, 12)
    for _ in range(10):
        _chacha20_qr(x, 0, 4, 8, 12)
        _chacha20_qr(x, 1, 5, 9, 13)
        _chacha20_qr(x, 2, 6, 10, 14)
        _chacha20_qr(x, 3, 7, 11, 15)
        _chacha20_qr(x, 0, 5, 10, 15)
        _chacha20_qr(x, 1, 6, 11, 12)
        _chacha20_qr(x, 2, 7, 8, 13)
        _chacha20_qr(x, 3, 4, 9, 14)
    return struct.pack("<8I", x[0], x[1], x[2], x[3], x[12], x[13], x[14], x[15])


def _chacha20_block_ietf(key: bytes, nonce12: bytes, counter: int) -> bytes:
    st = [0] * 16
    st[0] = 0x61707865
    st[1] = 0x3320646E
    st[2] = 0x79622D32
    st[3] = 0x6B206574
    for i in range(8):
        st[4 + i] = _u32le(key, 4 * i)
    st[12] = counter & 0xFFFFFFFF
    st[13] = _u32le(nonce12, 0)
    st[14] = _u32le(nonce12, 4)
    st[15] = _u32le(nonce12, 8)
    x = list(st)
    for _ in range(10):
        _chacha20_qr(x, 0, 4, 8, 12)
        _chacha20_qr(x, 1, 5, 9, 13)
        _chacha20_qr(x, 2, 6, 10, 14)
        _chacha20_qr(x, 3, 7, 11, 15)
        _chacha20_qr(x, 0, 5, 10, 15)
        _chacha20_qr(x, 1, 6, 11, 12)
        _chacha20_qr(x, 2, 7, 8, 13)
        _chacha20_qr(x, 3, 4, 9, 14)
    return struct.pack("<16I", *[(x[i] + st[i]) & 0xFFFFFFFF for i in range(16)])


def _chacha20_ietf_xor_ic(c_len_or_m, m, nonce12, key, ic):
    """XOR m with the IETF ChaCha20 keystream starting at block ic.

    If m is None, produces a pure keystream of length c_len_or_m.
    """
    if m is None:
        mlen = c_len_or_m
        m = bytes(mlen)
    else:
        mlen = len(m)
    out = bytearray(mlen)
    ctr = ic & 0xFFFFFFFF
    off = 0
    remaining = mlen
    while remaining > 0:
        block = _chacha20_block_ietf(key, nonce12, ctr)
        ctr = (ctr + 1) & 0xFFFFFFFF
        take = min(remaining, 64)
        for i in range(take):
            out[off + i] = m[off + i] ^ block[i]
        off += take
        remaining -= take
    return bytes(out)


def _xchacha20_derive_subkey_nonce(npub: bytes, k: bytes):
    subkey = _hchacha20(k, npub[:16])
    nonce12 = b"\x00\x00\x00\x00" + npub[16:24]
    return subkey, nonce12


def _xchacha20_xor_ic(m: bytes, n24: bytes, ic: int, k: bytes) -> bytes:
    """XChaCha20 stream with a 64-bit block counter (classic box engine)."""
    subkey = _hchacha20(k, n24[:16])
    nonce8 = n24[16:24]
    ctr_low = ic & 0xFFFFFFFF
    ctr_high = (ic >> 32) & 0xFFFFFFFF
    st = [0] * 16
    st[0] = 0x61707865
    st[1] = 0x3320646E
    st[2] = 0x79622D32
    st[3] = 0x6B206574
    for i in range(8):
        st[4 + i] = _u32le(subkey, 4 * i)
    st[14] = _u32le(nonce8, 0)
    st[15] = _u32le(nonce8, 4)
    out = bytearray(len(m))
    off = 0
    remaining = len(m)
    while remaining > 0:
        st[12] = ctr_low
        st[13] = ctr_high
        x = list(st)
        for _ in range(10):
            _chacha20_qr(x, 0, 4, 8, 12)
            _chacha20_qr(x, 1, 5, 9, 13)
            _chacha20_qr(x, 2, 6, 10, 14)
            _chacha20_qr(x, 3, 7, 11, 15)
            _chacha20_qr(x, 0, 5, 10, 15)
            _chacha20_qr(x, 1, 6, 11, 12)
            _chacha20_qr(x, 2, 7, 8, 13)
            _chacha20_qr(x, 3, 4, 9, 14)
        block = struct.pack("<16I", *[(x[i] + st[i]) & 0xFFFFFFFF for i in range(16)])
        ctr_low = (ctr_low + 1) & 0xFFFFFFFF
        if ctr_low == 0:
            ctr_high = (ctr_high + 1) & 0xFFFFFFFF
        take = min(remaining, 64)
        for i in range(take):
            out[off + i] = m[off + i] ^ block[i]
        off += take
        remaining -= take
    return bytes(out)


# ===========================================================================
# Poly1305 (32-bit limbs, matching the C reference)
# ===========================================================================


class _Poly1305State:
    __slots__ = (
        "r0", "r1", "r2", "r3", "r4", "s1", "s2", "s3", "s4",
        "h0", "h1", "h2", "h3", "h4", "pad0", "pad1", "pad2", "pad3",
        "leftover", "buf", "final",
    )

    def __init__(self):
        self.buf = bytearray(16)
        self.leftover = 0
        self.final = False
        for attr in self.__slots__:
            if not hasattr(self, attr) or getattr(self, attr) is None:
                if attr == "buf":
                    continue
                object.__setattr__(self, attr, 0)


_MASK26 = 0x3FFFFFF


def _poly1305_blocks(st: _Poly1305State, m: bytes) -> None:
    hibit = 0 if st.final else (1 << 24)
    r0, r1, r2, r3, r4 = st.r0, st.r1, st.r2, st.r3, st.r4
    s1, s2, s3, s4 = st.s1, st.s2, st.s3, st.s4
    h0, h1, h2, h3, h4 = st.h0, st.h1, st.h2, st.h3, st.h4
    off = 0
    n = len(m)
    while n - off >= 16:
        t0 = _u32le(m, off)
        t1 = _u32le(m, off + 4)
        t2 = _u32le(m, off + 8)
        t3 = _u32le(m, off + 12)

        h0 = (h0 + (t0 & _MASK26)) & 0xFFFFFFFF
        h1 = (h1 + (((t0 >> 26) | (t1 << 6)) & _MASK26)) & 0xFFFFFFFF
        h2 = (h2 + (((t1 >> 20) | (t2 << 12)) & _MASK26)) & 0xFFFFFFFF
        h3 = (h3 + (((t2 >> 14) | (t3 << 18)) & _MASK26)) & 0xFFFFFFFF
        h4 = (h4 + ((t3 >> 8) | hibit)) & 0xFFFFFFFF

        d0 = (h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1)
        d1 = (h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2)
        d2 = (h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3)
        d3 = (h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4)
        d4 = (h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0)

        c = d0 >> 26
        h0 = d0 & _MASK26
        d1 += c
        c = d1 >> 26
        h1 = d1 & _MASK26
        d2 += c
        c = d2 >> 26
        h2 = d2 & _MASK26
        d3 += c
        c = d3 >> 26
        h3 = d3 & _MASK26
        d4 += c
        c = d4 >> 26
        h4 = d4 & _MASK26
        h0 += c * 5
        c = h0 >> 26
        h0 &= _MASK26
        h1 += c

        off += 16
    st.r0, st.r1, st.r2, st.r3, st.r4 = r0, r1, r2, r3, r4
    st.h0, st.h1, st.h2, st.h3, st.h4 = h0, h1, h2, h3, h4


def _poly1305_init(st: _Poly1305State, key: bytes) -> None:
    t0 = _u32le(key, 0)
    t1 = _u32le(key, 4)
    t2 = _u32le(key, 8)
    t3 = _u32le(key, 12)
    st.r0 = t0 & _MASK26
    st.r1 = ((t0 >> 26) | (t1 << 6)) & 0x3FFFF03
    st.r2 = ((t1 >> 20) | (t2 << 12)) & 0x3FFC0FF
    st.r3 = ((t2 >> 14) | (t3 << 18)) & 0x3F03FFF
    st.r4 = (t3 >> 8) & 0x00FFFFF
    st.s1 = st.r1 * 5
    st.s2 = st.r2 * 5
    st.s3 = st.r3 * 5
    st.s4 = st.r4 * 5
    st.h0 = st.h1 = st.h2 = st.h3 = st.h4 = 0
    st.pad0 = _u32le(key, 16)
    st.pad1 = _u32le(key, 20)
    st.pad2 = _u32le(key, 24)
    st.pad3 = _u32le(key, 28)
    st.leftover = 0
    st.final = False


def _poly1305_update(st: _Poly1305State, m: bytes) -> None:
    if st.leftover != 0:
        want = 16 - st.leftover
        if want > len(m):
            want = len(m)
        st.buf[st.leftover:st.leftover + want] = m[:want]
        m = m[want:]
        st.leftover += want
        if st.leftover < 16:
            return
        _poly1305_blocks(st, bytes(st.buf[:16]))
        st.leftover = 0
    if len(m) >= 16:
        want = len(m) & ~0xF
        _poly1305_blocks(st, m[:want])
        m = m[want:]
    if len(m) != 0:
        st.buf[st.leftover:st.leftover + len(m)] = m
        st.leftover += len(m)


def _poly1305_finish(st: _Poly1305State) -> bytes:
    if st.leftover != 0:
        st.buf[st.leftover] = 1
        for i in range(st.leftover + 1, 16):
            st.buf[i] = 0
        st.final = True
        _poly1305_blocks(st, bytes(st.buf[:16]))
    h0, h1, h2, h3, h4 = st.h0, st.h1, st.h2, st.h3, st.h4
    c = h1 >> 26; h1 &= _MASK26; h2 += c
    c = h2 >> 26; h2 &= _MASK26; h3 += c
    c = h3 >> 26; h3 &= _MASK26; h4 += c
    c = h4 >> 26; h4 &= _MASK26; h0 += c * 5
    c = h0 >> 26; h0 &= _MASK26; h1 += c

    g0 = h0 + 5
    c = g0 >> 26; g0 &= _MASK26
    g1 = h1 + c; c = g1 >> 26; g1 &= _MASK26
    g2 = h2 + c; c = g2 >> 26; g2 &= _MASK26
    g3 = h3 + c; c = g3 >> 26; g3 &= _MASK26
    g4 = h4 + c - (1 << 26)

    # mask = 0xFFFFFFFF if g4 >= 0 else 0, computed as in the C reference
    # (uint32: (g4 >> 31) - 1). Python's >> is arithmetic on negative ints,
    # so emulate the unsigned top-bit extraction explicitly.
    negative = g4 < 0
    mask = 0 if negative else 0xFFFFFFFF
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask
    mask = (~mask) & 0xFFFFFFFF
    h0 = (h0 & mask) | g0
    h1 = (h1 & mask) | g1
    h2 = (h2 & mask) | g2
    h3 = (h3 & mask) | g3
    h4 = (h4 & mask) | g4

    h0 = (h0 | (h1 << 26)) & 0xFFFFFFFF
    h1 = ((h1 >> 6) | (h2 << 20)) & 0xFFFFFFFF
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xFFFFFFFF
    h3 = ((h3 >> 18) | (h4 << 8)) & 0xFFFFFFFF

    f = h0 + st.pad0
    h0 = f & 0xFFFFFFFF
    f = h1 + st.pad1 + (f >> 32)
    h1 = f & 0xFFFFFFFF
    f = h2 + st.pad2 + (f >> 32)
    h2 = f & 0xFFFFFFFF
    f = h3 + st.pad3 + (f >> 32)
    h3 = f & 0xFFFFFFFF

    return struct.pack("<4I", h0, h1, h2, h3)


def _poly1305_update_padded(st: _Poly1305State, m: bytes) -> None:
    _poly1305_update(st, m)
    rem = len(m) & 15
    if rem != 0:
        _poly1305_update(st, b"\x00" * (16 - rem))


def _verify16(x: bytes, y: bytes) -> bool:
    return hmac.compare_digest(x, y)


# ===========================================================================
# Layer 1: BLAKE2b (generichash)
# ===========================================================================


def generichash(data: bytes, *, outlen: int = 32, key: bytes = b"") -> bytes:
    if not (GENERICHASH_BYTES_MIN <= outlen <= GENERICHASH_BYTES_MAX):
        raise NaionArgumentError("invalid generichash output length")
    h = hashlib.blake2b(data, key=key, digest_size=outlen)
    return h.digest()


class GenericHashState:
    def __init__(self, *, key: bytes = b"", outlen: int = 32):
        if not (GENERICHASH_BYTES_MIN <= outlen <= GENERICHASH_BYTES_MAX):
            raise NaionArgumentError("invalid generichash output length")
        self._outlen = outlen
        self._key = key
        self._h = hashlib.blake2b(key=key, digest_size=outlen)

    def update(self, data: bytes) -> None:
        self._h.update(data)

    def final(self) -> bytes:
        return self._h.digest()


# ===========================================================================
# Layer 1: XChaCha20 stream
# ===========================================================================


def stream_xchacha20(length: int, nonce: bytes, key: bytes) -> bytes:
    return _xchacha20_xor_ic(bytes(length), nonce, 0, key)


def stream_xchacha20_xor(m: bytes, nonce: bytes, key: bytes) -> bytes:
    if len(m) == 0:
        return b""
    return _xchacha20_xor_ic(m, nonce, 0, key)


def stream_xchacha20_xor_ic(m: bytes, nonce: bytes, ic: int, key: bytes) -> bytes:
    if len(m) == 0:
        return b""
    return _xchacha20_xor_ic(m, nonce, ic, key)


# ===========================================================================
# Layer 2: IETF XChaCha20-Poly1305 AEAD (ciphertext || mac combined)
# ===========================================================================


def _aead_ietf_encrypt_detached(m: bytes, ad: bytes, npub: bytes, key: bytes):
    subkey, nonce12 = _xchacha20_derive_subkey_nonce(npub, key)
    block0 = _chacha20_block_ietf(subkey, nonce12, 0)
    st = _Poly1305State()
    _poly1305_init(st, block0)
    c = _chacha20_ietf_xor_ic(None, m, nonce12, subkey, 1)
    _poly1305_update_padded(st, ad)
    _poly1305_update_padded(st, c)
    lens = struct.pack("<QQ", len(ad), len(m))
    _poly1305_update(st, lens)
    mac = _poly1305_finish(st)
    return c, mac


def _aead_ietf_decrypt_detached(c: bytes, mac: bytes, ad: bytes, npub: bytes, key: bytes) -> bytes:
    subkey, nonce12 = _xchacha20_derive_subkey_nonce(npub, key)
    block0 = _chacha20_block_ietf(subkey, nonce12, 0)
    st = _Poly1305State()
    _poly1305_init(st, block0)
    _poly1305_update_padded(st, ad)
    _poly1305_update_padded(st, c)
    lens = struct.pack("<QQ", len(ad), len(c))
    _poly1305_update(st, lens)
    computed = _poly1305_finish(st)
    if not _verify16(mac, computed):
        raise NaionCryptoError("AEAD verification failed")
    return _chacha20_ietf_xor_ic(None, c, nonce12, subkey, 1)


def aead_xchacha20poly1305_ietf_encrypt(m, ad, npub, key, nsec=b""):
    c, mac = _aead_ietf_encrypt_detached(m, ad, npub, key)
    return c + mac


def aead_xchacha20poly1305_ietf_decrypt(c, ad, npub, key, nsec=b""):
    if len(c) < AEAD_XCHACHA20POLY1305_IETF_ABYTES:
        raise NaionCryptoError("ciphertext too short")
    n = len(c) - AEAD_XCHACHA20POLY1305_IETF_ABYTES
    return _aead_ietf_decrypt_detached(c[:n], c[n:], ad, npub, key)


def aead_xchacha20poly1305_ietf_encrypt_detached(m, ad, npub, key, nsec=b""):
    return _aead_ietf_encrypt_detached(m, ad, npub, key)


def aead_xchacha20poly1305_ietf_decrypt_detached(c, mac, ad, npub, key, nsec=b""):
    return _aead_ietf_decrypt_detached(c, mac, ad, npub, key)


# ===========================================================================
# Layer 2: classic box/secretbox engine (afternm). Layout: mac(16) || ct
# ===========================================================================


def _box_easy_afternm(m: bytes, nonce: bytes, k: bytes) -> bytes:
    out = bytearray(16 + len(m))
    _box_easy_afternm_into(out, m, nonce, k)
    return bytes(out)


def _box_easy_afternm_into(out: bytearray, m: bytes, nonce: bytes, k: bytes) -> None:
    block0 = bytearray(64)
    mlen = len(m)
    first_take = mlen if mlen < 32 else 32
    if first_take > 0:
        block0[32:32 + first_take] = m[:first_take]
    xored = _xchacha20_xor_ic(bytes(block0[:32 + first_take]), nonce, 0, k)
    block0[:32 + first_take] = xored
    st = _Poly1305State()
    _poly1305_init(st, bytes(block0[:32]))  # key = block0[0:32]
    if first_take > 0:
        out[16:16 + first_take] = block0[32:32 + first_take]
    rem = mlen - first_take
    if rem > 0:
        tail = _xchacha20_xor_ic(m[first_take:], nonce, 1, k)
        out[16 + first_take:16 + first_take + rem] = tail
    _poly1305_update(st, bytes(out[16:16 + mlen]))
    mac = _poly1305_finish(st)
    out[:16] = mac


def _box_open_easy_afternm(c: bytes, nonce: bytes, k: bytes) -> bytes:
    if len(c) < 16:
        raise NaionCryptoError("ciphertext too short")
    mlen = len(c) - 16
    cipher = c[16:]
    block0 = bytearray(64)
    first_take = mlen if mlen < 32 else 32
    if first_take > 0:
        block0[32:32 + first_take] = cipher[:first_take]
    xored = _xchacha20_xor_ic(bytes(block0[:64]), nonce, 0, k)
    block0[:64] = xored
    st = _Poly1305State()
    _poly1305_init(st, bytes(block0[:32]))
    _poly1305_update(st, cipher)
    computed = _poly1305_finish(st)
    if not _verify16(c[:16], computed):
        raise NaionCryptoError("box verification failed")
    out = bytearray(mlen)
    if first_take > 0:
        out[:first_take] = block0[32:32 + first_take]
    rem = mlen - first_take
    if rem > 0:
        tail = _xchacha20_xor_ic(cipher[first_take:], nonce, 1, k)
        out[first_take:first_take + rem] = tail
    return bytes(out)


# ===========================================================================
# Layer 2: Secretbox
# ===========================================================================


def secretbox_xchacha20poly1305_easy(m, nonce, key):
    return _box_easy_afternm(m, nonce, key)


def secretbox_xchacha20poly1305_open_easy(c, nonce, key):
    return _box_open_easy_afternm(c, nonce, key)


def secretbox_xchacha20poly1305_detached(m, nonce, key):
    combined = _box_easy_afternm(m, nonce, key)
    return combined[16:], combined[:16]


def secretbox_xchacha20poly1305_open_detached(c, mac, nonce, key):
    combined = mac + c
    return _box_open_easy_afternm(combined, nonce, key)


# ===========================================================================
# Layer 2: Box afternm wrappers
# ===========================================================================


def box_curve25519xchacha20poly1305_easy_afternm(m, nonce, k):
    return _box_easy_afternm(m, nonce, k)


def box_curve25519xchacha20poly1305_open_easy_afternm(c, nonce, k):
    return _box_open_easy_afternm(c, nonce, k)


# ===========================================================================
# Layer 3: X25519
# ===========================================================================

_X25519_SMALL_ORDER = [
    bytes(32),
    bytes([1]) + bytes(31),
    bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
    bytes.fromhex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
    bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    bytes.fromhex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    bytes.fromhex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
]


def _x25519_has_small_order(p: bytes) -> bool:
    c = [0] * 7
    for j in range(31):
        for i in range(7):
            c[i] |= p[j] ^ _X25519_SMALL_ORDER[i][j]
    for i in range(7):
        c[i] |= (p[31] & 0x7F) ^ _X25519_SMALL_ORDER[i][31]
    k = 0
    for i in range(7):
        k |= (c[i] - 1) & 0xFFFFFFFF
    return ((k >> 8) & 1) == 1


def scalarmult_curve25519(n: bytes, p: bytes) -> bytes:
    if _x25519_has_small_order(p):
        raise NaionCryptoError("small-order point rejected")
    return nacl.bindings.crypto_scalarmult(n, p)


def scalarmult_curve25519_base(n: bytes) -> bytes:
    return nacl.bindings.crypto_scalarmult_base(n)


# ===========================================================================
# Layer 3: KX
# ===========================================================================


def kx_keypair():
    sk = _fill_random(KX_SECRETKEYBYTES)
    pk = scalarmult_curve25519_base(sk)
    return pk, sk


def kx_seed_keypair(seed: bytes):
    sk = generichash(seed, outlen=KX_SECRETKEYBYTES)
    pk = scalarmult_curve25519_base(sk)
    return pk, sk


def _kx_derive(q: bytes, client_pk: bytes, server_pk: bytes):
    h = hashlib.blake2b(digest_size=64)
    h.update(q)
    h.update(client_pk)
    h.update(server_pk)
    keys = h.digest()
    return keys[:32], keys[32:]


def kx_client_session_keys(client_pk, client_sk, server_pk):
    q = scalarmult_curve25519(client_sk, server_pk)
    first, second = _kx_derive(q, client_pk, server_pk)
    return first, second


def kx_server_session_keys(server_pk, server_sk, client_pk):
    q = scalarmult_curve25519(server_sk, client_pk)
    first, second = _kx_derive(q, client_pk, server_pk)
    return second, first


# ===========================================================================
# Layer 3: Box (asymmetric)
# ===========================================================================


def box_curve25519xchacha20poly1305_keypair():
    sk = _fill_random(BOX_CURVE25519XCHACHA20POLY1305_SECRETKEYBYTES)
    pk = scalarmult_curve25519_base(sk)
    return pk, sk


def box_curve25519xchacha20poly1305_seed_keypair(seed: bytes):
    sk = generichash(seed, outlen=BOX_CURVE25519XCHACHA20POLY1305_SECRETKEYBYTES)
    pk = scalarmult_curve25519_base(sk)
    return pk, sk


def box_curve25519xchacha20poly1305_beforenm(pk: bytes, sk: bytes) -> bytes:
    s = scalarmult_curve25519(sk, pk)
    return _hchacha20(s, bytes(16))


def box_curve25519xchacha20poly1305_easy(m, nonce, pk, sk):
    k = box_curve25519xchacha20poly1305_beforenm(pk, sk)
    return _box_easy_afternm(m, nonce, k)


def box_curve25519xchacha20poly1305_open_easy(c, nonce, pk, sk):
    k = box_curve25519xchacha20poly1305_beforenm(pk, sk)
    return _box_open_easy_afternm(c, nonce, k)


def box_curve25519xchacha20poly1305_seal(m, pk):
    esk = _fill_random(BOX_CURVE25519XCHACHA20POLY1305_SECRETKEYBYTES)
    epk = scalarmult_curve25519_base(esk)
    h = hashlib.blake2b(digest_size=24)
    h.update(epk)
    h.update(pk)
    nonce = h.digest()
    ct = box_curve25519xchacha20poly1305_easy(m, nonce, pk, esk)
    return epk + ct


def box_curve25519xchacha20poly1305_seal_open(c, pk, sk):
    if len(c) < BOX_CURVE25519XCHACHA20POLY1305_SEALBYTES:
        raise NaionCryptoError("sealed box too short")
    epk = c[:32]
    h = hashlib.blake2b(digest_size=24)
    h.update(epk)
    h.update(pk)
    nonce = h.digest()
    return box_curve25519xchacha20poly1305_open_easy(c[32:], nonce, epk, sk)


# ===========================================================================
# Layer 3: Ed25519
# ===========================================================================


def sign_ed25519_keypair():
    pk, sk = nacl.bindings.crypto_sign_keypair()
    return pk, sk


def sign_ed25519_seed_keypair(seed: bytes):
    pk, sk = nacl.bindings.crypto_sign_seed_keypair(seed)
    return pk, sk


def sign_ed25519(m, sk):
    sig = nacl.bindings.crypto_sign(m, sk)[:SIGN_ED25519_BYTES]
    return sig + m


def sign_ed25519_open(sm, pk):
    if len(sm) < SIGN_ED25519_BYTES:
        raise NaionCryptoError("signed message too short")
    try:
        m = nacl.bindings.crypto_sign_open(sm, pk)
    except nacl.exceptions.BadSignatureError:
        raise NaionCryptoError("Ed25519 verification failed")
    return m


def sign_ed25519_detached(m, sk):
    return nacl.bindings.crypto_sign(m, sk)[:SIGN_ED25519_BYTES]


def sign_ed25519_verify_detached(sig, m, pk):
    try:
        nacl.bindings.crypto_sign_open(sig + m, pk)
        return True
    except nacl.exceptions.BadSignatureError:
        return False


def sign_ed25519_sk_to_seed(sk):
    return sk[:SIGN_ED25519_SEEDBYTES]


def sign_ed25519_sk_to_pk(sk):
    return sk[SIGN_ED25519_SEEDBYTES:]


def sign_ed25519_pk_to_curve25519(ed_pk):
    return nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(ed_pk)


def sign_ed25519_sk_to_curve25519(ed_sk):
    return nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(ed_sk)


# ===========================================================================
# Layer 3: CSM
# ===========================================================================

_SIGN_BYTES = SIGN_ED25519_BYTES
_ED_PK_BYTES = SIGN_ED25519_PUBLICKEYBYTES
_X_PK_BYTES = BOX_PUBLICKEYBYTES_MAX
_X_SK_BYTES = BOX_SECRETKEYBYTES_MAX
_NONCE_BYTES = BOX_NONCEBYTES_MAX
_MAC_BYTES = BOX_MACBYTES_MAX


class CSMClient:
    def __init__(self, ed_seed: bytes, server_ed_pk: bytes):
        self.ed_seed = bytes(ed_seed)
        self.server_ed_public_key = bytes(server_ed_pk)
        self.ed_public_key, self.ed_secret_key = sign_ed25519_seed_keypair(self.ed_seed)

    def wipe(self):
        self.ed_seed = bytes(32)
        self.ed_secret_key = bytes(64)
        self.ed_public_key = bytes(32)
        self.server_ed_public_key = bytes(32)

    def encrypt(self, plaintext: bytes) -> bytes:
        if len(plaintext) == 0:
            raise CSMNoDataError("no data")
        out = bytearray(_csm_client_encrypt_size(len(plaintext)))
        server_xpk = sign_ed25519_pk_to_curve25519(self.server_ed_public_key)
        session_xsk = _fill_random(_X_SK_BYTES)
        session_xpk = scalarmult_curve25519_base(session_xsk)
        body = memoryview(out)[_SIGN_BYTES:]
        body[:32] = session_xpk
        body_payload = body[32:]
        plain_payload = self.ed_public_key + plaintext
        _csm_internal_seal(plain_payload, server_xpk, session_xsk,
                           session_xpk, body_payload)
        body_len = 32 + len(body_payload)
        sig = sign_ed25519_detached(bytes(body[:body_len]), self.ed_secret_key)
        out[:_SIGN_BYTES] = sig
        return bytes(out)

    def decrypt(self, packet: bytes) -> bytes:
        min_size = _SIGN_BYTES + _X_PK_BYTES + _NONCE_BYTES + _MAC_BYTES
        if len(packet) <= min_size:
            raise CSMInvalidArgumentError("packet too short")
        sig = packet[:_SIGN_BYTES]
        body = packet[_SIGN_BYTES:]
        if not sign_ed25519_verify_detached(sig, body, self.server_ed_public_key):
            raise CSMVerifyFailedError("verify failed")
        client_xsk = sign_ed25519_sk_to_curve25519(self.ed_secret_key)
        session_xpk = body[:_X_PK_BYTES]
        nonce_cipher = body[_X_PK_BYTES:]
        pt = _csm_internal_open(nonce_cipher, session_xpk, client_xsk, session_xpk)
        return pt


class CSMServer:
    def __init__(self, ed_seed: bytes):
        self.ed_seed = bytes(ed_seed)
        self.ed_public_key, self.ed_secret_key = sign_ed25519_seed_keypair(self.ed_seed)
        self.client_ed_public_key = None
        self.client_public_key_initialized = False

    def wipe(self):
        self.ed_seed = bytes(32)
        self.ed_secret_key = bytes(64)
        self.ed_public_key = bytes(32)
        self.client_ed_public_key = None
        self.client_public_key_initialized = False

    def decrypt(self, packet: bytes) -> bytes:
        min_size = _SIGN_BYTES + _X_PK_BYTES + _NONCE_BYTES + _MAC_BYTES + _ED_PK_BYTES
        if len(packet) <= min_size:
            raise CSMInvalidArgumentError("packet too short")
        server_xsk = sign_ed25519_sk_to_curve25519(self.ed_secret_key)
        sig = packet[:_SIGN_BYTES]
        body = packet[_SIGN_BYTES:]
        session_xpk = body[:_X_PK_BYTES]
        nonce_cipher = body[_X_PK_BYTES:]
        opened = _csm_internal_open(nonce_cipher, session_xpk, server_xsk, session_xpk)
        if len(opened) <= _ED_PK_BYTES:
            raise CSMCryptoError("decrypted payload too short")
        client_ed_pk = opened[:_ED_PK_BYTES]
        if not sign_ed25519_verify_detached(sig, body, client_ed_pk):
            raise CSMVerifyFailedError("verify failed")
        self.client_ed_public_key = client_ed_pk
        self.client_public_key_initialized = True
        return opened[_ED_PK_BYTES:]

    def encrypt(self, plaintext: bytes) -> bytes:
        if len(plaintext) == 0:
            raise CSMNoDataError("no data")
        if not self.client_public_key_initialized:
            raise CSMStateError("client key not learned")
        out = bytearray(_csm_server_encrypt_size(len(plaintext)))
        client_xpk = sign_ed25519_pk_to_curve25519(self.client_ed_public_key)
        session_xsk = _fill_random(_X_SK_BYTES)
        session_xpk = scalarmult_curve25519_base(session_xsk)
        body = memoryview(out)[_SIGN_BYTES:]
        body[:32] = session_xpk
        body_payload = body[32:]
        _csm_internal_seal(plaintext, client_xpk, session_xsk, session_xpk, body_payload)
        body_len = 32 + len(body_payload)
        sig = sign_ed25519_detached(bytes(body[:body_len]), self.ed_secret_key)
        out[:_SIGN_BYTES] = sig
        return bytes(out)


def _csm_client_encrypt_size(plaintext_len: int) -> int:
    return _SIGN_BYTES + _X_PK_BYTES + _NONCE_BYTES + _MAC_BYTES + _ED_PK_BYTES + plaintext_len


def _csm_client_decrypt_max_plaintext_size(packet_len: int) -> int:
    fixed = _SIGN_BYTES + _X_PK_BYTES + _NONCE_BYTES + _MAC_BYTES
    return packet_len - fixed if packet_len > fixed else 0


def _csm_server_encrypt_size(plaintext_len: int) -> int:
    return _SIGN_BYTES + _X_PK_BYTES + _NONCE_BYTES + _MAC_BYTES + plaintext_len


def _csm_server_decrypt_max_plaintext_size(packet_len: int) -> int:
    fixed = _SIGN_BYTES + _X_PK_BYTES + _NONCE_BYTES + _MAC_BYTES + _ED_PK_BYTES
    return packet_len - fixed if packet_len > fixed else 0


def csm_init():
    return None


def _csm_beforenm(peer_xpk: bytes, self_xsk: bytes) -> bytes:
    s = scalarmult_curve25519(self_xsk, peer_xpk)
    return _hchacha20(s, bytes(16))


def _csm_internal_seal(plaintext, peer_xpk, self_xsk, aad, out) -> None:
    nonce = bytearray(_fill_random(_NONCE_BYTES))
    ekey = _csm_beforenm(peer_xpk, self_xsk)
    out[:_NONCE_BYTES] = nonce
    ct, mac = _aead_ietf_encrypt_detached(plaintext, aad, bytes(nonce), ekey)
    out[_NONCE_BYTES:_NONCE_BYTES + _MAC_BYTES] = mac
    out[_NONCE_BYTES + _MAC_BYTES:] = ct


def _csm_internal_open(nonce_cipher, peer_xpk, self_xsk, aad) -> bytes:
    if len(nonce_cipher) <= _NONCE_BYTES + _MAC_BYTES:
        raise CSMInvalidArgumentError("nonce_cipher too short")
    nonce = nonce_cipher[:_NONCE_BYTES]
    mac = nonce_cipher[_NONCE_BYTES:_NONCE_BYTES + _MAC_BYTES]
    ciphertext = nonce_cipher[_NONCE_BYTES + _MAC_BYTES:]
    ekey = _csm_beforenm(peer_xpk, self_xsk)
    try:
        return _aead_ietf_decrypt_detached(ciphertext, mac, aad, nonce, ekey)
    except NaionCryptoError:
        raise CSMCryptoError("AEAD open failed")


# Module-level size helpers (matching the C/Go API names)
CSMClient.encrypt_size = staticmethod(_csm_client_encrypt_size)  # type: ignore[assignment]
CSMClient.decrypt_max_plaintext_size = staticmethod(_csm_client_decrypt_max_plaintext_size)  # type: ignore[assignment]
CSMServer.encrypt_size = staticmethod(_csm_server_encrypt_size)  # type: ignore[assignment]
CSMServer.decrypt_max_plaintext_size = staticmethod(_csm_server_decrypt_max_plaintext_size)  # type: ignore[assignment]


# ===========================================================================
# Layer 4: CSM-CA
# ===========================================================================


class CSMCAClient:
    def __init__(self, ed_seed: bytes, ca_ed_pk: bytes):
        self.ed_seed = bytes(ed_seed)
        self.ca_ed_public_key = bytes(ca_ed_pk)
        self.ed_public_key, self.ed_secret_key = sign_ed25519_seed_keypair(self.ed_seed)
        self.server_ed_public_key = None
        self.server_key_verified = False

    def wipe(self):
        self.ed_seed = bytes(32)
        self.ed_secret_key = bytes(64)
        self.ed_public_key = bytes(32)
        self.ca_ed_public_key = bytes(32)
        self.server_ed_public_key = None
        self.server_key_verified = False

    def handshake_verify(self, m1: bytes) -> None:
        if len(m1) != CSM_CA_CERT_BYTES:
            raise CSMInvalidArgumentError("bad cert size")
        sig = m1[_ED_PK_BYTES:]
        if not sign_ed25519_verify_detached(sig, m1[:_ED_PK_BYTES], self.ca_ed_public_key):
            raise CSMVerifyFailedError("CA verification failed")
        self.server_ed_public_key = m1[:_ED_PK_BYTES]
        self.server_key_verified = True

    def encrypt(self, plaintext: bytes) -> bytes:
        if len(plaintext) == 0:
            raise CSMNoDataError("no data")
        out = bytearray(_csm_client_encrypt_size(len(plaintext)))
        server_xpk = sign_ed25519_pk_to_curve25519(self.server_ed_public_key)
        session_xsk = _fill_random(_X_SK_BYTES)
        session_xpk = scalarmult_curve25519_base(session_xsk)
        body = memoryview(out)[_SIGN_BYTES:]
        body[:32] = session_xpk
        body_payload = body[32:]
        plain_payload = self.ed_public_key + plaintext
        _csm_internal_seal(plain_payload, server_xpk, session_xsk, session_xpk, body_payload)
        body_len = 32 + len(body_payload)
        sig = sign_ed25519_detached(bytes(body[:body_len]), self.ed_secret_key)
        out[:_SIGN_BYTES] = sig
        return bytes(out)

    def decrypt(self, pkt: bytes) -> bytes:
        min_size = _SIGN_BYTES + _X_PK_BYTES + _NONCE_BYTES + _MAC_BYTES
        if len(pkt) <= min_size:
            raise CSMInvalidArgumentError("packet too short")
        sig = pkt[:_SIGN_BYTES]
        body = pkt[_SIGN_BYTES:]
        if not sign_ed25519_verify_detached(sig, body, self.server_ed_public_key):
            raise CSMVerifyFailedError("verify failed")
        client_xsk = sign_ed25519_sk_to_curve25519(self.ed_secret_key)
        session_xpk = body[:_X_PK_BYTES]
        nonce_cipher = body[_X_PK_BYTES:]
        return _csm_internal_open(nonce_cipher, session_xpk, client_xsk, session_xpk)


class CSMCAServer:
    def __init__(self, ed_seed: bytes, ca_signature: bytes):
        self.ed_seed = bytes(ed_seed)
        self.ca_signature = bytes(ca_signature)
        self.ed_public_key, self.ed_secret_key = sign_ed25519_seed_keypair(self.ed_seed)
        self.client_ed_public_key = None
        self.client_key_verified = False

    def wipe(self):
        self.ed_seed = bytes(32)
        self.ed_secret_key = bytes(64)
        self.ed_public_key = bytes(32)
        self.ca_signature = bytes(64)
        self.client_ed_public_key = None
        self.client_key_verified = False

    def handshake_response(self) -> bytes:
        return self.ed_public_key + self.ca_signature

    def encrypt(self, plaintext: bytes) -> bytes:
        if len(plaintext) == 0:
            raise CSMNoDataError("no data")
        out = bytearray(_csm_server_encrypt_size(len(plaintext)))
        client_xpk = sign_ed25519_pk_to_curve25519(self.client_ed_public_key)
        session_xsk = _fill_random(_X_SK_BYTES)
        session_xpk = scalarmult_curve25519_base(session_xsk)
        body = memoryview(out)[_SIGN_BYTES:]
        body[:32] = session_xpk
        body_payload = body[32:]
        _csm_internal_seal(plaintext, client_xpk, session_xsk, session_xpk, body_payload)
        body_len = 32 + len(body_payload)
        sig = sign_ed25519_detached(bytes(body[:body_len]), self.ed_secret_key)
        out[:_SIGN_BYTES] = sig
        return bytes(out)

    def decrypt(self, pkt: bytes) -> bytes:
        min_size = _SIGN_BYTES + _X_PK_BYTES + _NONCE_BYTES + _MAC_BYTES + _ED_PK_BYTES
        if len(pkt) <= min_size:
            raise CSMInvalidArgumentError("packet too short")
        server_xsk = sign_ed25519_sk_to_curve25519(self.ed_secret_key)
        sig = pkt[:_SIGN_BYTES]
        body = pkt[_SIGN_BYTES:]
        session_xpk = body[:_X_PK_BYTES]
        nonce_cipher = body[_X_PK_BYTES:]
        opened = _csm_internal_open(nonce_cipher, session_xpk, server_xsk, session_xpk)
        if len(opened) <= _ED_PK_BYTES:
            raise CSMCryptoError("decrypted payload too short")
        client_ed_pk = opened[:_ED_PK_BYTES]
        if not sign_ed25519_verify_detached(sig, body, client_ed_pk):
            raise CSMVerifyFailedError("verify failed")
        self.client_ed_public_key = client_ed_pk
        self.client_key_verified = True
        return opened[_ED_PK_BYTES:]


def csm_ca_handshake_response_size() -> int:
    return CSM_CA_CERT_BYTES


CSMCAClient.encrypt_size = staticmethod(_csm_client_encrypt_size)  # type: ignore[assignment]
CSMCAClient.decrypt_max_plaintext_size = staticmethod(_csm_client_decrypt_max_plaintext_size)  # type: ignore[assignment]
CSMCAServer.encrypt_size = staticmethod(_csm_server_encrypt_size)  # type: ignore[assignment]
CSMCAServer.decrypt_max_plaintext_size = staticmethod(_csm_server_decrypt_max_plaintext_size)  # type: ignore[assignment]


# ===========================================================================
# XSalsa20 family + runtime selector
# ===========================================================================

_g_use_xchacha20 = True


def box_set_use_xchacha20(use: bool) -> None:
    global _g_use_xchacha20
    _g_use_xchacha20 = use


def box_get_use_xchacha20() -> bool:
    return _g_use_xchacha20


def set_use_xchacha20(use: bool) -> None:
    box_set_use_xchacha20(use)


def get_use_xchacha20() -> bool:
    return _g_use_xchacha20


def _xsalsa20_box_easy_afternm(m: bytes, nonce: bytes, k: bytes) -> bytes:
    out = bytearray(16 + len(m))
    block0 = bytearray(64)
    mlen = len(m)
    first_take = mlen if mlen < 32 else 32
    if first_take > 0:
        block0[32:32 + first_take] = m[:first_take]
    xored = _xsalsa20_xor_ic(bytes(block0[:32 + first_take]), nonce, 0, k)
    block0[:32 + first_take] = xored
    st = _Poly1305State()
    _poly1305_init(st, bytes(block0[:32]))
    if first_take > 0:
        out[16:16 + first_take] = block0[32:32 + first_take]
    rem = mlen - first_take
    if rem > 0:
        tail = _xsalsa20_xor_ic(m[first_take:], nonce, 1, k)
        out[16 + first_take:16 + first_take + rem] = tail
    _poly1305_update(st, bytes(out[16:16 + mlen]))
    mac = _poly1305_finish(st)
    out[:16] = mac
    return bytes(out)


def _xsalsa20_box_open_easy_afternm(c: bytes, nonce: bytes, k: bytes) -> bytes:
    if len(c) < 16:
        raise NaionCryptoError("ciphertext too short")
    mlen = len(c) - 16
    cipher = c[16:]
    block0 = bytearray(64)
    first_take = mlen if mlen < 32 else 32
    if first_take > 0:
        block0[32:32 + first_take] = cipher[:first_take]
    xored = _xsalsa20_xor_ic(bytes(block0[:64]), nonce, 0, k)
    block0[:64] = xored
    st = _Poly1305State()
    _poly1305_init(st, bytes(block0[:32]))
    _poly1305_update(st, cipher)
    computed = _poly1305_finish(st)
    if not _verify16(c[:16], computed):
        raise NaionCryptoError("box verification failed")
    out = bytearray(mlen)
    if first_take > 0:
        out[:first_take] = block0[32:32 + first_take]
    rem = mlen - first_take
    if rem > 0:
        tail = _xsalsa20_xor_ic(cipher[first_take:], nonce, 1, k)
        out[first_take:first_take + rem] = tail
    return bytes(out)


def secretbox_xsalsa20poly1305_easy(m, nonce, key):
    return _xsalsa20_box_easy_afternm(m, nonce, key)


def secretbox_xsalsa20poly1305_open_easy(c, nonce, key):
    return _xsalsa20_box_open_easy_afternm(c, nonce, key)


def secretbox_xsalsa20poly1305_detached(m, nonce, key):
    combined = _xsalsa20_box_easy_afternm(m, nonce, key)
    return combined[16:], combined[:16]


def secretbox_xsalsa20poly1305_open_detached(c, mac, nonce, key):
    return _xsalsa20_box_open_easy_afternm(mac + c, nonce, key)


def box_curve25519xsalsa20poly1305_beforenm(pk: bytes, sk: bytes) -> bytes:
    s = scalarmult_curve25519(sk, pk)
    return _hsalsa20(bytes(16), s)


def box_curve25519xsalsa20poly1305_keypair():
    return box_curve25519xchacha20poly1305_keypair()


def box_curve25519xsalsa20poly1305_seed_keypair(seed: bytes):
    return box_curve25519xchacha20poly1305_seed_keypair(seed)


def box_curve25519xsalsa20poly1305_easy_afternm(m, nonce, k):
    return _xsalsa20_box_easy_afternm(m, nonce, k)


def box_curve25519xsalsa20poly1305_open_easy_afternm(c, nonce, k):
    return _xsalsa20_box_open_easy_afternm(c, nonce, k)


def box_curve25519xsalsa20poly1305_easy(m, nonce, pk, sk):
    k = box_curve25519xsalsa20poly1305_beforenm(pk, sk)
    return _xsalsa20_box_easy_afternm(m, nonce, k)


def box_curve25519xsalsa20poly1305_open_easy(c, nonce, pk, sk):
    k = box_curve25519xsalsa20poly1305_beforenm(pk, sk)
    return _xsalsa20_box_open_easy_afternm(c, nonce, k)


def box_curve25519xsalsa20poly1305_seal(m, pk):
    esk = _fill_random(BOX_SECRETKEYBYTES_MAX)
    epk = scalarmult_curve25519_base(esk)
    h = hashlib.blake2b(digest_size=24)
    h.update(epk)
    h.update(pk)
    nonce = h.digest()
    ct = box_curve25519xsalsa20poly1305_easy(m, nonce, pk, esk)
    return epk + ct


def box_curve25519xsalsa20poly1305_seal_open(c, pk, sk):
    if len(c) < 48:
        raise NaionCryptoError("sealed box too short")
    epk = c[:32]
    h = hashlib.blake2b(digest_size=24)
    h.update(epk)
    h.update(pk)
    nonce = h.digest()
    return box_curve25519xsalsa20poly1305_open_easy(c[32:], nonce, epk, sk)


# ---- generic box dispatch ----

def box_keypair():
    if _g_use_xchacha20:
        return box_curve25519xchacha20poly1305_keypair()
    return box_curve25519xsalsa20poly1305_keypair()


def box_seed_keypair(seed: bytes):
    if _g_use_xchacha20:
        return box_curve25519xchacha20poly1305_seed_keypair(seed)
    return box_curve25519xsalsa20poly1305_seed_keypair(seed)


def box_beforenm(pk, sk):
    if _g_use_xchacha20:
        return box_curve25519xchacha20poly1305_beforenm(pk, sk)
    return box_curve25519xsalsa20poly1305_beforenm(pk, sk)


def box_easy(m, nonce, pk, sk):
    if _g_use_xchacha20:
        return box_curve25519xchacha20poly1305_easy(m, nonce, pk, sk)
    return box_curve25519xsalsa20poly1305_easy(m, nonce, pk, sk)


def box_open_easy(c, nonce, pk, sk):
    if _g_use_xchacha20:
        return box_curve25519xchacha20poly1305_open_easy(c, nonce, pk, sk)
    return box_curve25519xsalsa20poly1305_open_easy(c, nonce, pk, sk)


def box_easy_afternm(m, nonce, k):
    if _g_use_xchacha20:
        return _box_easy_afternm(m, nonce, k)
    return _xsalsa20_box_easy_afternm(m, nonce, k)


def box_open_easy_afternm(c, nonce, k):
    if _g_use_xchacha20:
        return _box_open_easy_afternm(c, nonce, k)
    return _xsalsa20_box_open_easy_afternm(c, nonce, k)


def box_seal(m, pk):
    if _g_use_xchacha20:
        return box_curve25519xchacha20poly1305_seal(m, pk)
    return box_curve25519xsalsa20poly1305_seal(m, pk)


def box_seal_open(c, pk, sk):
    if _g_use_xchacha20:
        return box_curve25519xchacha20poly1305_seal_open(c, pk, sk)
    return box_curve25519xsalsa20poly1305_seal_open(c, pk, sk)


# query helpers
def box_seedbytes() -> int:
    return BOX_SEEDBYTES_MAX


def box_publickeybytes() -> int:
    return BOX_PUBLICKEYBYTES_MAX


def box_secretkeybytes() -> int:
    return BOX_SECRETKEYBYTES_MAX


def box_beforenmbytes() -> int:
    return BOX_BEFORENMBYTES_MAX


def box_noncebytes() -> int:
    return BOX_NONCEBYTES_MAX


def box_macbytes() -> int:
    return BOX_MACBYTES_MAX


def box_sealbytes() -> int:
    return BOX_SEALBYTES_MAX
