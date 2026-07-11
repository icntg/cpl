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


class TestCSM(unittest.TestCase):
    def test_roundtrip(self):
        client, server = csm_setup()
        payload = b"client to server"
        pkt = client.encrypt(payload)
        self.assertEqual(len(pkt), naion.CSM_PACKET_OVERHEAD + 32 + len(payload))
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

    def test_server_state_guard(self):
        _, server = csm_setup()
        with self.assertRaises(CSMStateError):
            server.encrypt(b"x")

    def test_sizes(self):
        self.assertEqual(naion.CSMClient.encrypt_size(10), 64 + 32 + 24 + 16 + 32 + 10)
        self.assertEqual(naion.CSMServer.encrypt_size(10), 64 + 32 + 24 + 16 + 10)
        self.assertEqual(naion.CSMServer.decrypt_max_plaintext_size(64 + 32 + 24 + 16 + 32 + 10), 10)


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
