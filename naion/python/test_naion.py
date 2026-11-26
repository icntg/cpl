"""test_naion.py — comprehensive tests for naion.py (unittest, no pytest dep).

Where possible the tests embed the same deterministic seeds as the Go suite so
that the two implementations can be cross-checked byte-for-byte.
"""

import hashlib
import struct
import unittest

import nacl.bindings

import naion
from naion import (
    NaionCryptoError,
    CSMNoDataError,
    CSMStateError,
    CSMVerifyFailedError,
    CSMInvalidArgumentError,
    CSMCryptoError,
)

KEY32 = b"\x42" * 32
NONCE24 = b"\x11" * 24


def seed32(n):
    return bytes((i + n) & 0xFF for i in range(32))


class TestInfra(unittest.TestCase):
    def test_memcmp_iszero_verify(self):
        self.assertEqual(naion.memcmp(b"\x01\x02", b"\x01\x02"), 0)
        self.assertNotEqual(naion.memcmp(b"\x01\x02", b"\x01\x03"), 0)
        self.assertTrue(naion.is_zero(b"\x00\x00"))
        self.assertFalse(naion.is_zero(b"\x00\x01"))
        self.assertEqual(naion.verify_32(b"\x00" * 32, b"\x00" * 32), 1)
        a = bytearray(b"\x01" * 32)
        naion.memzero(a)
        self.assertTrue(naion.is_zero(a))


class TestBlake2b(unittest.TestCase):
    def test_vector(self):
        out = naion.generichash(b"abc", outlen=32)
        self.assertEqual(
            out.hex(),
            "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
        )

    def test_keyed_determinism(self):
        key = b"\x00" * 32
        a = naion.generichash(b"abc", outlen=32, key=key)
        b = naion.generichash(b"abc", outlen=32, key=key)
        self.assertEqual(a, b)

    def test_streaming_eq_oneshot(self):
        st = naion.GenericHashState(outlen=32)
        st.update(b"ab")
        st.update(b"c")
        self.assertEqual(st.final(), naion.generichash(b"abc", outlen=32))

    def test_bad_len(self):
        with self.assertRaises(naion.NaionArgumentError):
            naion.generichash(b"x", outlen=0)
        with self.assertRaises(naion.NaionArgumentError):
            naion.generichash(b"x", outlen=65)


class TestXChaCha20Stream(unittest.TestCase):
    def test_keystream_eq_xor0(self):
        key = bytes(range(32))
        nonce = b"\x00" * 24
        ks = naion.stream_xchacha20(64, nonce, key)
        x0 = naion.stream_xchacha20_xor(b"\x00" * 64, nonce, key)
        self.assertEqual(ks, x0)

    def test_xor_roundtrip(self):
        key = b"\x00" * 32
        nonce = b"\x00" * 24
        msg = b"\xA5" * 100
        ct = naion.stream_xchacha20_xor(msg, nonce, key)
        self.assertEqual(naion.stream_xchacha20_xor(ct, nonce, key), msg)

    def test_xor_ic(self):
        key = b"\x00" * 32
        nonce = b"\x00" * 24
        full = naion.stream_xchacha20_xor(b"\x00" * 128, nonce, key)
        half = naion.stream_xchacha20_xor_ic(b"\x00" * 64, nonce, 1, key)
        self.assertEqual(half, full[64:])


class TestHChaCha20(unittest.TestCase):
    def test_draft_vector(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        nonce = bytes.fromhex("000000090000004a0000000031415927")
        out = naion._hchacha20(key, nonce)
        self.assertEqual(
            out.hex(),
            "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc",
        )


class TestAEAD(unittest.TestCase):
    def test_roundtrip(self):
        c = naion.aead_xchacha20poly1305_ietf_encrypt(b"hello csm world", b"aad", NONCE24, KEY32)
        self.assertEqual(len(c), len(b"hello csm world") + 16)
        m = naion.aead_xchacha20poly1305_ietf_decrypt(c, b"aad", NONCE24, KEY32)
        self.assertEqual(m, b"hello csm world")

    def test_tamper(self):
        c = naion.aead_xchacha20poly1305_ietf_encrypt(b"secret", b"ad", NONCE24, KEY32)
        for i in range(len(c)):
            bad = bytearray(c)
            bad[i] ^= 1
            with self.assertRaises(NaionCryptoError):
                naion.aead_xchacha20poly1305_ietf_decrypt(bytes(bad), b"ad", NONCE24, KEY32)

    def test_wrong_ad(self):
        c = naion.aead_xchacha20poly1305_ietf_encrypt(b"m", b"ad1", NONCE24, KEY32)
        with self.assertRaises(NaionCryptoError):
            naion.aead_xchacha20poly1305_ietf_decrypt(c, b"ad2", NONCE24, KEY32)

    def test_detached(self):
        c, mac = naion.aead_xchacha20poly1305_ietf_encrypt_detached(b"detached test", b"a", NONCE24, KEY32)
        m = naion.aead_xchacha20poly1305_ietf_decrypt_detached(c, mac, b"a", NONCE24, KEY32)
        self.assertEqual(m, b"detached test")


class TestSecretbox(unittest.TestCase):
    def test_roundtrip(self):
        key = b"\x77" * 32
        nonce = b"\x33" * 24
        c = naion.secretbox_xchacha20poly1305_easy(b"secret message", nonce, key)
        self.assertEqual(len(c), len(b"secret message") + 16)
        self.assertEqual(naion.secretbox_xchacha20poly1305_open_easy(c, nonce, key), b"secret message")

    def test_tamper(self):
        key = b"\x77" * 32
        nonce = b"\x33" * 24
        c = naion.secretbox_xchacha20poly1305_easy(b"m", nonce, key)
        bad = bytearray(c)
        bad[0] ^= 1
        with self.assertRaises(NaionCryptoError):
            naion.secretbox_xchacha20poly1305_open_easy(bytes(bad), nonce, key)

    def test_detached(self):
        key = b"\x77" * 32
        nonce = b"\x33" * 24
        c, mac = naion.secretbox_xchacha20poly1305_detached(b"detached", nonce, key)
        self.assertEqual(naion.secretbox_xchacha20poly1305_open_detached(c, mac, nonce, key), b"detached")

    def test_empty(self):
        key = b"\x77" * 32
        nonce = b"\x33" * 24
        c = naion.secretbox_xchacha20poly1305_easy(b"", nonce, key)
        self.assertEqual(naion.secretbox_xchacha20poly1305_open_easy(c, nonce, key), b"")


class TestBoxAfterNM(unittest.TestCase):
    def test_roundtrip(self):
        k = b"\x99" * 32
        nonce = b"\x44" * 24
        c = naion.box_curve25519xchacha20poly1305_easy_afternm(b"afternm", nonce, k)
        self.assertEqual(naion.box_curve25519xchacha20poly1305_open_easy_afternm(c, nonce, k), b"afternm")


class TestX25519(unittest.TestCase):
    def test_rfc7748(self):
        n = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        p = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        want = bytes.fromhex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        self.assertEqual(naion.scalarmult_curve25519(n, p), want)

    def test_dh_agreement(self):
        apk, ask = naion.box_curve25519xchacha20poly1305_keypair()
        bpk, bsk = naion.box_curve25519xchacha20poly1305_keypair()
        s1 = naion.scalarmult_curve25519(ask, bpk)
        s2 = naion.scalarmult_curve25519(bsk, apk)
        self.assertEqual(s1, s2)

    def test_small_order_rejected(self):
        n = b"\x01" + b"\x00" * 31
        with self.assertRaises(NaionCryptoError):
            naion.scalarmult_curve25519(n, bytes(32))


class TestKX(unittest.TestCase):
    def test_seed_keypair_determinism(self):
        seed = bytes(range(32))
        pk1, sk1 = naion.kx_seed_keypair(seed)
        pk2, sk2 = naion.kx_seed_keypair(seed)
        self.assertEqual(pk1, pk2)
        self.assertEqual(sk1, sk2)

    def test_session_key_agreement(self):
        cpk, csk = naion.kx_keypair()
        spk, ssk = naion.kx_keypair()
        crx, ctx = naion.kx_client_session_keys(cpk, csk, spk)
        srx, stx = naion.kx_server_session_keys(spk, ssk, cpk)
        self.assertEqual(ctx, srx)
        self.assertEqual(crx, stx)


class TestBox(unittest.TestCase):
    def test_seed_keypair_determinism(self):
        seed = bytes((i + 1) & 0xFF for i in range(32))
        pk1, sk1 = naion.box_curve25519xchacha20poly1305_seed_keypair(seed)
        pk2, sk2 = naion.box_curve25519xchacha20poly1305_seed_keypair(seed)
        self.assertEqual(pk1, pk2)
        self.assertEqual(sk1, sk2)

    def test_easy_roundtrip(self):
        pk, sk = naion.box_curve25519xchacha20poly1305_keypair()
        pk2, sk2 = naion.box_curve25519xchacha20poly1305_keypair()
        nonce = b"\x55" * 24
        c = naion.box_curve25519xchacha20poly1305_easy(b"box easy", nonce, pk2, sk)
        self.assertEqual(naion.box_curve25519xchacha20poly1305_open_easy(c, nonce, pk, sk2), b"box easy")

    def test_seal_roundtrip(self):
        pk, sk = naion.box_curve25519xchacha20poly1305_keypair()
        c = naion.box_curve25519xchacha20poly1305_seal(b"sealed", pk)
        self.assertEqual(len(c), len(b"sealed") + 48)
        self.assertEqual(naion.box_curve25519xchacha20poly1305_seal_open(c, pk, sk), b"sealed")

    def test_easy_matches_beforenm(self):
        pk, sk = naion.box_curve25519xchacha20poly1305_keypair()
        pk2, sk2 = naion.box_curve25519xchacha20poly1305_keypair()
        nonce = b"\x77" * 24
        k = naion.box_curve25519xchacha20poly1305_beforenm(pk2, sk)
        c1 = naion.box_curve25519xchacha20poly1305_easy_afternm(b"consistency", nonce, k)
        c2 = naion.box_curve25519xchacha20poly1305_easy(b"consistency", nonce, pk2, sk)
        self.assertEqual(c1, c2)


class TestEd25519(unittest.TestCase):
    def test_seed_keypair(self):
        seed = bytes((i) & 0xFF for i in range(32))
        pk, sk = naion.sign_ed25519_seed_keypair(seed)
        self.assertEqual(sk[:32], seed)
        self.assertEqual(sk[32:], pk)
        self.assertEqual(naion.sign_ed25519_sk_to_pk(sk), pk)
        self.assertEqual(naion.sign_ed25519_sk_to_seed(sk), seed)

    def test_detached_and_verify(self):
        seed = b"\xAB" * 32
        pk, sk = naion.sign_ed25519_seed_keypair(seed)
        sig = naion.sign_ed25519_detached(b"sign me", sk)
        self.assertTrue(naion.sign_ed25519_verify_detached(sig, b"sign me", pk))
        self.assertFalse(naion.sign_ed25519_verify_detached(sig, b"sign me!", pk))
        # cross-check with PyNaCl directly
        nacl.bindings.crypto_sign_open(sig + b"sign me", pk)

    def test_combined(self):
        seed = bytes(range(32))
        pk, sk = naion.sign_ed25519_seed_keypair(seed)
        sm = naion.sign_ed25519(b"combined sign", sk)
        self.assertEqual(naion.sign_ed25519_open(sm, pk), b"combined sign")

    def test_ed_to_curve25519(self):
        seed = bytes((i + 7) & 0xFF for i in range(32))
        ed_pk, ed_sk = naion.sign_ed25519_seed_keypair(seed)
        x_pk = naion.sign_ed25519_pk_to_curve25519(ed_pk)
        x_sk = naion.sign_ed25519_sk_to_curve25519(ed_sk)
        base = naion.scalarmult_curve25519_base(x_sk)
        self.assertEqual(x_pk, base)


def csm_setup():
    cs = bytes(i & 0xFF for i in range(32))
    ss = bytes((i + 100) & 0xFF for i in range(32))
    spk, _ = naion.sign_ed25519_seed_keypair(ss)
    return naion.CSMClient(cs, spk), naion.CSMServer(ss)


def ca_setup():
    """A CSM-CA client/server pair that has finished the handshake."""
    ca_pk, ca_sk = naion.sign_ed25519_seed_keypair(b"\x09" * 32)
    ss = bytes((i + 50) & 0xFF for i in range(32))
    spk, _ = naion.sign_ed25519_seed_keypair(ss)
    server = naion.CSMCAServer(ss, naion.sign_ed25519_detached(spk, ca_sk))
    client = naion.CSMCAClient(bytes((i + 1) & 0xFF for i in range(32)), ca_pk)
    client.handshake_verify(server.handshake_response())
    return client, server


# CSM nonce modes (naion.h: NAION_CSM_NONCE_DERIVED / NAION_CSM_NONCE_RANDOM).
CSM_DERIVED = naion.CSM_NONCE_DERIVED  # 0: "compact" packet, per-packet derived nonce
CSM_RANDOM = naion.CSM_NONCE_RANDOM  # 1: random nonce transmitted in the packet
CSM_MODES = (CSM_DERIVED, CSM_RANDOM)
# Fixed overhead per nonce mode:
#   signature(64) | session_x25519_public_key(32) | [nonce(24)] | mac(16)
# The nonce field exists in random mode only.
CSM_OVERHEAD = {CSM_DERIVED: 112, CSM_RANDOM: 136}


def fill_5a(buf) -> None:
    """Random provider of the cross-language vectors: fill the buffer with 0x5A."""
    for i in range(len(buf)):
        buf[i] = 0x5A


# CSM cross-language vectors (build/vectors/vectors.txt, generated by the C
# implementation). Inputs: client seed = 32 x 0x01, server seed = 32 x 0x02,
# random provider fills every request with 0x5A, payload = 00 01 .. 0f.
VECTOR_SERVER_ED_PK = (
    "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394"
)
VECTOR_CLIENT_ED_PK = (
    "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
)
VECTOR_C2S_COMPACT = (
    "676f9b6a8cdfa755841a467b2709b5b3cbe4249665bca1f30922237678aedf6e"
    "714b553b0f27fc4dfff8b1d0ca68d00c8333eaf1c12abf1ce72e8b85bac0100a"
    "b0d08f35b4683381489afb32825e59152d47d19bc9e050d6d5a954984c9d1e2c"
    "1f639c2334f0089bcb0a7d5da997c2016e84fa6a6df29e24e4aa8d4b394b9b98"
    "0e0e11f7bf5b7f4fbce4435ba5d50e4fd432f7121f2b9b97d7fa83a0431d3b5d"
)
VECTOR_S2C_COMPACT = (
    "0c4c0249692bc2852662efe431530e03f94237b589ad2c53ed758101eca18f2c"
    "139ef42b1437b77c775dfd59e93dd1dcc48f44547cd631f4fcbc31f266dc6708"
    "b0d08f35b4683381489afb32825e59152d47d19bc9e050d6d5a954984c9d1e2c"
    "86345b488d8ff6fdec5f09c153d04202f0db445448e1f320021649bb4d717143"
)
VECTOR_C2S_RANDOM = (
    "987f308ffecb2c195194c1f81b1c78db264b1d47073a009853869bb1f5ccfe84"
    "048317f7173b61bc57a91e6bf194221ebcbb6166dc6ccd83d7916ea7246dbd0c"
    "b0d08f35b4683381489afb32825e59152d47d19bc9e050d6d5a954984c9d1e2c"
    "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5afbae93e8305a23e3"
    "a08f3f6d4cec110a364beb3d7e7c30a008b53895752c490bf48fab438eb09a71"
    "e7584cb6b0b7d9f0f6907d93f078090e34e100884d11ca5f"
)
VECTOR_S2C_RANDOM = (
    "82b009cb900f66e2004ad257680ed111c586517cffcaae8cf9c0c020b628c5ea"
    "c8700f4af571821ddf8442e7358f60b221f782aa5b8a6a3f2f2392a0a4365808"
    "b0d08f35b4683381489afb32825e59152d47d19bc9e050d6d5a954984c9d1e2c"
    "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5af77b969223bfbf7e"
    "b79137cb22dad8aba92a7a99f5d08ba76c494c33b0d09b6f"
)
VECTOR_PAYLOAD = bytes(range(16))


def vector_pair():
    """A client/server pair that uses the seeds of the cross-language vectors."""
    server = naion.CSMServer(b"\x02" * 32)
    return naion.CSMClient(b"\x01" * 32, server.ed_public_key), server


class TestCSM(unittest.TestCase):
    def test_roundtrip(self):
        client, server = csm_setup()
        payload = b"client to server"
        pkt = client.encrypt(payload)
        # The default nonce mode is derived (compact): the packet has no nonce field.
        self.assertEqual(len(pkt), naion.CSM_COMPACT_PACKET_OVERHEAD + 32 + len(payload))
        pt = server.decrypt(pkt)
        self.assertEqual(pt, payload)
        self.assertTrue(server.client_public_key_initialized)
        reply = b"server reply"
        rpkt = server.encrypt(reply)
        rpt = client.decrypt(rpkt)
        self.assertEqual(rpt, reply)

    def test_tamper(self):
        client, server = csm_setup()
        pkt = client.encrypt(b"payload")
        for i in range(len(pkt)):
            bad = bytearray(pkt)
            bad[i] ^= 0x80
            with self.assertRaises((NaionCryptoError, CSMVerifyFailedError, CSMCryptoError)):
                server.decrypt(bytes(bad))

    def test_empty_payload(self):
        client, _ = csm_setup()
        with self.assertRaises(CSMNoDataError):
            client.encrypt(b"")
        with self.assertRaises(CSMNoDataError):
            client.encrypt(b"", CSM_RANDOM)

    def test_server_state_guard(self):
        _, server = csm_setup()
        with self.assertRaises(CSMStateError):
            server.encrypt(b"x")
        with self.assertRaises(CSMStateError):
            server.encrypt(b"x", CSM_RANDOM)

    def test_sizes(self):
        # Without an explicit nonce mode the helpers report the derived (compact) sizes.
        self.assertEqual(naion.CSMClient.encrypt_size(10), 64 + 32 + 16 + 32 + 10)
        self.assertEqual(naion.CSMServer.encrypt_size(10), 64 + 32 + 16 + 10)
        self.assertEqual(naion.CSMServer.decrypt_max_plaintext_size(64 + 32 + 16 + 32 + 10), 10)
        # Random mode keeps the legacy sizes (24-byte nonce field).
        self.assertEqual(naion.CSMClient.encrypt_size(10, naion.CSM_NONCE_RANDOM), 64 + 32 + 24 + 16 + 32 + 10)
        self.assertEqual(naion.CSMServer.encrypt_size(10, naion.CSM_NONCE_RANDOM), 64 + 32 + 24 + 16 + 10)
        self.assertEqual(naion.CSMServer.decrypt_max_plaintext_size(64 + 32 + 24 + 16 + 32 + 10, naion.CSM_NONCE_RANDOM), 10)


class TestCSMNonceMode(unittest.TestCase):
    def test_default_mode_is_compact(self):
        client, server = csm_setup()
        for payload in (b"c", b"client to server" * 20):
            pkt = client.encrypt(payload)
            self.assertEqual(len(pkt), 112 + 32 + len(payload))
            self.assertEqual(server.decrypt(pkt), payload)
            reply = b"server reply" * 10
            rpkt = server.encrypt(reply)
            self.assertEqual(len(rpkt), 112 + len(reply))
            self.assertEqual(client.decrypt(rpkt), reply)
        # The default is nonce_mode = 0, also accepted positionally or by keyword.
        naion.set_random_provider(fill_5a)
        try:
            expected = client.encrypt(b"explicit")
            self.assertEqual(client.encrypt(b"explicit", CSM_DERIVED), expected)
            self.assertEqual(client.encrypt(b"explicit", nonce_mode=CSM_DERIVED), expected)
            self.assertEqual(
                client.decrypt(server.encrypt(b"explicit", CSM_DERIVED), CSM_DERIVED),
                b"explicit",
            )
        finally:
            naion.set_random_provider(None)

    def test_random_mode_sizes_and_roundtrip(self):
        client, server = csm_setup()
        for payload in (b"r", b"client to server" * 20):
            pkt = client.encrypt(payload, CSM_RANDOM)
            self.assertEqual(len(pkt), 136 + 32 + len(payload))
            self.assertEqual(server.decrypt(pkt, CSM_RANDOM), payload)
            reply = b"server reply" * 10
            rpkt = server.encrypt(reply, nonce_mode=CSM_RANDOM)
            self.assertEqual(len(rpkt), 136 + len(reply))
            self.assertEqual(client.decrypt(rpkt, CSM_RANDOM), reply)

    def test_random_mode_transmits_random_nonce(self):
        client, server = csm_setup()
        server_xsk = naion.sign_ed25519_sk_to_curve25519(server.ed_secret_key)
        nonces = set()
        for _ in range(4):
            # signature(64) | session_x25519_public_key(32) | nonce(24) | mac(16) | ciphertext
            pkt = client.encrypt(b"nonce check", CSM_RANDOM)
            self.assertEqual(len(pkt), 136 + 32 + len(b"nonce check"))
            _, derived_nonce = naion._csm_internal_derive(pkt[64:96], server_xsk)
            self.assertNotEqual(pkt[96:120], derived_nonce)
            nonces.add(pkt[96:120])
        self.assertEqual(len(nonces), 4)  # a fresh nonce in every packet

    def test_mode_mismatch_fails(self):
        client, server = csm_setup()
        # Longer than 24 bytes, so a compact packet is above the random-mode minimum.
        payload = b"p" * 80
        compact = client.encrypt(payload)
        random_pkt = client.encrypt(payload, CSM_RANDOM)
        # A mismatched mode must fail with a CRYPTO error, and it must not
        # teach the server the client key.
        for pkt, wrong_mode in ((compact, CSM_RANDOM), (random_pkt, CSM_DERIVED)):
            with self.assertRaises(CSMCryptoError) as ctx:
                server.decrypt(pkt, wrong_mode)
            self.assertEqual(ctx.exception.code, -3)
            self.assertFalse(server.client_public_key_initialized)
            self.assertIsNone(server.client_ed_public_key)
        # The matching modes still work afterwards.
        self.assertEqual(server.decrypt(compact), payload)
        self.assertTrue(server.client_public_key_initialized)
        self.assertEqual(server.decrypt(random_pkt, CSM_RANDOM), payload)

        # The server to client direction behaves in the same way.
        reply_compact = server.encrypt(payload)
        reply_random = server.encrypt(payload, CSM_RANDOM)
        for pkt, mode in ((reply_compact, CSM_RANDOM), (reply_random, CSM_DERIVED)):
            with self.assertRaises(CSMCryptoError):
                client.decrypt(pkt, mode)
        self.assertEqual(client.decrypt(reply_compact), payload)
        self.assertEqual(client.decrypt(reply_random, CSM_RANDOM), payload)

    def test_mismatched_compact_packet_not_longer_than_random_minimum(self):
        # Mirrors naion_csm_client_decrypt_ex / naion_csm_server_decrypt_ex: the
        # length check runs first, so a compact packet that is not longer than
        # the random-mode minimum is rejected as too short (INVALID_ARGUMENT)
        # before the AEAD can report the mode mismatch.
        client, server = csm_setup()
        tiny = b"t" * 24
        # client -> server: 112 + 32 + 24 = 168 is not longer than 136 + 32.
        with self.assertRaises(CSMInvalidArgumentError):
            server.decrypt(client.encrypt(tiny), CSM_RANDOM)
        self.assertFalse(server.client_public_key_initialized)
        self.assertEqual(server.decrypt(client.encrypt(tiny)), tiny)
        # server -> client: 112 + 24 = 136 is not longer than 136 + 0.
        with self.assertRaises(CSMInvalidArgumentError):
            client.decrypt(server.encrypt(tiny), CSM_RANDOM)
        # One byte more clears the length check, and the AEAD catches the mismatch.
        with self.assertRaises(CSMCryptoError):
            client.decrypt(server.encrypt(b"t" * 25), CSM_RANDOM)
        with self.assertRaises(CSMCryptoError):
            server.decrypt(client.encrypt(b"t" * 25), CSM_RANDOM)

    def test_compact_tamper_every_field(self):
        def tampered(pkt):
            # signature(64) | session_x25519_public_key(32) | mac(16) | ciphertext
            for lo, hi in ((0, 64), (64, 96), (96, 112), (112, len(pkt))):
                for offset in (lo, (lo + hi) // 2, hi - 1):
                    bad = bytearray(pkt)
                    bad[offset] ^= 0x01
                    yield offset, bytes(bad)

        client, server = csm_setup()
        # The server opens the AEAD first and then verifies the signature with
        # the client key taken from the plaintext. A tampered signature is
        # reported as VERIFY_FAILED here (CRYPTO in naion.h, see the report);
        # every other field is rejected by the AEAD (CRYPTO).
        for offset, bad in tampered(client.encrypt(bytes(range(64)))):
            in_signature = offset < 64
            expected = (CSMVerifyFailedError, CSMCryptoError) if in_signature else (CSMCryptoError,)
            with self.assertRaises(expected) as ctx:
                server.decrypt(bad)
            self.assertIn(ctx.exception.code, (-4, -3) if in_signature else (-3,))
        self.assertFalse(server.client_public_key_initialized)
        self.assertIsNone(server.client_ed_public_key)

        # The client verifies the signature with the known server key before it
        # opens the AEAD, so any tampered byte fails the verification.
        server.decrypt(client.encrypt(bytes(range(64))))
        for _, bad in tampered(server.encrypt(bytes(range(64)))):
            with self.assertRaises(CSMVerifyFailedError) as ctx:
                client.decrypt(bad)
            self.assertEqual(ctx.exception.code, -4)

    def test_random_mode_tamper_every_byte(self):
        client, server = csm_setup()
        pkt = client.encrypt(b"random mode tamper", CSM_RANDOM)
        for i in range(len(pkt)):
            bad = bytearray(pkt)
            bad[i] ^= 0x01
            with self.assertRaises((CSMCryptoError, CSMVerifyFailedError)):
                server.decrypt(bytes(bad), CSM_RANDOM)
        self.assertFalse(server.client_public_key_initialized)

    def test_minimum_packet_size_per_mode(self):
        client, server = csm_setup()
        for mode in CSM_MODES:
            overhead = CSM_OVERHEAD[mode]
            with self.assertRaises(CSMInvalidArgumentError):
                server.decrypt(bytes(overhead + 32), mode)
            with self.assertRaises(CSMInvalidArgumentError):
                client.decrypt(bytes(overhead), mode)

    def test_payload_limits(self):
        self.assertEqual(naion.CSM_PACKET_OVERHEAD, 136)
        self.assertEqual(naion.CSM_COMPACT_PACKET_OVERHEAD, 112)
        self.assertEqual(naion.CSM_MAX_UDP_DATAGRAM_BYTES, 1024)
        self.assertEqual((naion.CSM_MAX_CLIENT_PAYLOAD_BYTES, naion.CSM_MAX_SERVER_PAYLOAD_BYTES), (856, 888))
        self.assertEqual(
            (naion.CSM_COMPACT_MAX_CLIENT_PAYLOAD_BYTES, naion.CSM_COMPACT_MAX_SERVER_PAYLOAD_BYTES),
            (880, 912),
        )
        limits = {CSM_DERIVED: (880, 912), CSM_RANDOM: (856, 888)}
        for mode in CSM_MODES:
            cmax, smax = limits[mode]
            client, server = csm_setup()
            # The largest allowed payload fills the 1024-byte datagram exactly.
            c2s = client.encrypt(b"c" * cmax, mode)
            self.assertEqual(len(c2s), naion.CSM_MAX_UDP_DATAGRAM_BYTES)
            self.assertEqual(server.decrypt(c2s, mode), b"c" * cmax)
            s2c = server.encrypt(b"s" * smax, mode)
            self.assertEqual(len(s2c), naion.CSM_MAX_UDP_DATAGRAM_BYTES)
            self.assertEqual(client.decrypt(s2c, mode), b"s" * smax)
            # One byte more would exceed the datagram budget.
            self.assertEqual(naion.CSMClient.encrypt_size(cmax + 1, mode), naion.CSM_MAX_UDP_DATAGRAM_BYTES + 1)
            self.assertEqual(naion.CSMServer.encrypt_size(smax + 1, mode), naion.CSM_MAX_UDP_DATAGRAM_BYTES + 1)

    def test_size_helpers_per_mode(self):
        for mode in CSM_MODES:
            overhead = CSM_OVERHEAD[mode]
            for n in (0, 1, 32, 856, 880, 1024):
                self.assertEqual(naion.CSMClient.encrypt_size(n, mode), overhead + 32 + n)
                self.assertEqual(naion.CSMServer.encrypt_size(n, mode), overhead + n)
                # The CSM-CA classes expose the same size helpers.
                self.assertEqual(naion.CSMCAClient.encrypt_size(n, mode), overhead + 32 + n)
                self.assertEqual(naion.CSMCAServer.encrypt_size(n, mode), overhead + n)
                # decrypt_max_plaintext_size is the inverse of encrypt_size.
                self.assertEqual(naion.CSMClient.decrypt_max_plaintext_size(overhead + n, mode), n)
                self.assertEqual(naion.CSMServer.decrypt_max_plaintext_size(overhead + 32 + n, mode), n)
            # A packet that is not longer than the fixed overhead carries no plaintext.
            self.assertEqual(naion.CSMClient.decrypt_max_plaintext_size(overhead, mode), 0)
            self.assertEqual(naion.CSMServer.decrypt_max_plaintext_size(overhead + 32, mode), 0)
            self.assertEqual(naion.CSMCAClient.decrypt_max_plaintext_size(overhead - 1, mode), 0)
            self.assertEqual(naion.CSMCAServer.decrypt_max_plaintext_size(overhead + 31, mode), 0)

    def test_derive_matches_spec(self):
        apk, ask = naion.box_curve25519xchacha20poly1305_keypair()
        bpk, bsk = naion.box_curve25519xchacha20poly1305_keypair()
        ekey, nonce = naion._csm_internal_derive(apk, bsk)
        shared = naion.scalarmult_curve25519(bsk, apk)
        # ekey = HChaCha20(key = shared, in = 0x00 * 16): the same as beforenm.
        self.assertEqual(ekey, naion._csm_beforenm(apk, bsk))
        self.assertEqual(ekey, naion.box_curve25519xchacha20poly1305_beforenm(apk, bsk))
        # nonce = HChaCha20(key = shared, in = "naion.csm.nonce.")[0..23]
        self.assertEqual(naion._CSM_NONCE_KDF_INPUT, b"naion.csm.nonce.")
        self.assertEqual(len(naion._CSM_NONCE_KDF_INPUT), 16)
        self.assertEqual(nonce, naion._hchacha20(shared, b"naion.csm.nonce.")[:24])
        self.assertEqual((len(ekey), len(nonce)), (32, 24))
        # Both peers derive the same key and nonce from the shared secret.
        self.assertEqual((ekey, nonce), naion._csm_internal_derive(bpk, ask))

    def test_cross_language_vectors(self):
        naion.set_random_provider(fill_5a)
        try:
            client, server = vector_pair()
            self.assertEqual(server.ed_public_key, bytes.fromhex(VECTOR_SERVER_ED_PK))
            self.assertEqual(client.ed_public_key, bytes.fromhex(VECTOR_CLIENT_ED_PK))

            c2s_compact = client.encrypt(VECTOR_PAYLOAD)
            self.assertEqual(len(c2s_compact), 160)
            self.assertEqual(c2s_compact, bytes.fromhex(VECTOR_C2S_COMPACT))
            self.assertEqual(server.decrypt(c2s_compact), VECTOR_PAYLOAD)
            s2c_compact = server.encrypt(VECTOR_PAYLOAD)
            self.assertEqual(len(s2c_compact), 128)
            self.assertEqual(s2c_compact, bytes.fromhex(VECTOR_S2C_COMPACT))

            c2s_random = client.encrypt(VECTOR_PAYLOAD, CSM_RANDOM)
            self.assertEqual(len(c2s_random), 184)
            self.assertEqual(c2s_random, bytes.fromhex(VECTOR_C2S_RANDOM))
            self.assertEqual(server.decrypt(c2s_random, CSM_RANDOM), VECTOR_PAYLOAD)
            s2c_random = server.encrypt(VECTOR_PAYLOAD, CSM_RANDOM)
            self.assertEqual(len(s2c_random), 152)
            self.assertEqual(s2c_random, bytes.fromhex(VECTOR_S2C_RANDOM))
        finally:
            naion.set_random_provider(None)


class TestCSMCA(unittest.TestCase):
    def test_handshake_and_traffic(self):
        ca_seed = b"\x09" * 32
        ca_pk, ca_sk = naion.sign_ed25519_seed_keypair(ca_seed)
        ss = bytes((i + 50) & 0xFF for i in range(32))
        spk, _ = naion.sign_ed25519_seed_keypair(ss)
        ca_sig = naion.sign_ed25519_detached(spk, ca_sk)
        server = naion.CSMCAServer(ss, ca_sig)
        m1 = server.handshake_response()
        self.assertEqual(len(m1), naion.CSM_CA_CERT_BYTES)
        cs = bytes((i + 1) & 0xFF for i in range(32))
        client = naion.CSMCAClient(cs, ca_pk)
        client.handshake_verify(m1)
        self.assertTrue(client.server_key_verified)
        payload = b"ca traffic"
        pkt = client.encrypt(payload)
        self.assertEqual(server.decrypt(pkt), payload)

    def test_wrong_ca(self):
        ca_seed = b"\x09" * 32
        ca_pk, _ = naion.sign_ed25519_seed_keypair(ca_seed)
        wseed = b"\x08" * 32
        _, wca_sk = naion.sign_ed25519_seed_keypair(wseed)
        ss = bytes((i + 50) & 0xFF for i in range(32))
        spk, _ = naion.sign_ed25519_seed_keypair(ss)
        bad_sig = naion.sign_ed25519_detached(spk, wca_sk)
        server = naion.CSMCAServer(ss, bad_sig)
        m1 = server.handshake_response()
        cs = bytes(range(32))
        client = naion.CSMCAClient(cs, ca_pk)
        with self.assertRaises(CSMVerifyFailedError):
            client.handshake_verify(m1)

    def test_nonce_modes_roundtrip(self):
        for mode in CSM_MODES:
            client, server = ca_setup()
            payload = b"ca traffic" * 20
            pkt = client.encrypt(payload, mode)
            self.assertEqual(len(pkt), CSM_OVERHEAD[mode] + 32 + len(payload))
            self.assertEqual(server.decrypt(pkt, mode), payload)
            self.assertTrue(server.client_key_verified)
            reply = b"ca reply" * 20
            rpkt = server.encrypt(reply, mode)
            self.assertEqual(len(rpkt), CSM_OVERHEAD[mode] + len(reply))
            self.assertEqual(client.decrypt(rpkt, mode), reply)
            # The nonce mode must match on both sides.
            with self.assertRaises(CSMCryptoError):
                server.decrypt(client.encrypt(payload, 1 - mode), mode)
            with self.assertRaises(CSMCryptoError):
                client.decrypt(server.encrypt(reply, 1 - mode), mode)

    def test_packets_match_layer3_vectors(self):
        # CSM-CA traffic uses the Layer 3 packet format, so the seeds and the
        # fixed RNG of the cross-language vectors reproduce the same packets.
        naion.set_random_provider(fill_5a)
        try:
            ca_pk, ca_sk = naion.sign_ed25519_seed_keypair(b"\x09" * 32)
            spk, _ = naion.sign_ed25519_seed_keypair(b"\x02" * 32)
            server = naion.CSMCAServer(b"\x02" * 32, naion.sign_ed25519_detached(spk, ca_sk))
            client = naion.CSMCAClient(b"\x01" * 32, ca_pk)
            client.handshake_verify(server.handshake_response())

            c2s = client.encrypt(VECTOR_PAYLOAD)
            self.assertEqual(c2s, bytes.fromhex(VECTOR_C2S_COMPACT))
            self.assertEqual(server.decrypt(c2s), VECTOR_PAYLOAD)
            self.assertEqual(server.encrypt(VECTOR_PAYLOAD), bytes.fromhex(VECTOR_S2C_COMPACT))

            c2s = client.encrypt(VECTOR_PAYLOAD, CSM_RANDOM)
            self.assertEqual(c2s, bytes.fromhex(VECTOR_C2S_RANDOM))
            self.assertEqual(server.decrypt(c2s, CSM_RANDOM), VECTOR_PAYLOAD)
            self.assertEqual(server.encrypt(VECTOR_PAYLOAD, CSM_RANDOM), bytes.fromhex(VECTOR_S2C_RANDOM))
        finally:
            naion.set_random_provider(None)


class TestXSalsa20(unittest.TestCase):
    def test_secretbox_roundtrip(self):
        key = b"\x12" * 32
        nonce = b"\x34" * 24
        c = naion.secretbox_xsalsa20poly1305_easy(b"xsalsa20 secret", nonce, key)
        self.assertEqual(naion.secretbox_xsalsa20poly1305_open_easy(c, nonce, key), b"xsalsa20 secret")

    def test_box_roundtrip(self):
        pk, sk = naion.box_curve25519xsalsa20poly1305_keypair()
        pk2, sk2 = naion.box_curve25519xsalsa20poly1305_keypair()
        nonce = b"\x66" * 24
        c = naion.box_curve25519xsalsa20poly1305_easy(b"xsalsa box", nonce, pk2, sk)
        self.assertEqual(naion.box_curve25519xsalsa20poly1305_open_easy(c, nonce, pk, sk2), b"xsalsa box")

    def test_selector(self):
        naion.box_set_use_xchacha20(True)
        naion.box_keypair()
        naion.box_set_use_xchacha20(False)
        naion.box_keypair()
        naion.box_set_use_xchacha20(True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
