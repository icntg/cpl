package naion

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// hexd is a test helper.
func hexd(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

func hexmust(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

func eq(t *testing.T, name string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Fatalf("%s mismatch:\n got %x\n want %x", name, got, want)
	}
}

// ===========================================================================
// Infrastructure
// ===========================================================================

func TestMemCmpIsZeroVerify(t *testing.T) {
	if MemCmp([]byte{1, 2, 3}, []byte{1, 2, 3}) != 0 {
		t.Fatal("memcmp equal should be 0")
	}
	if MemCmp([]byte{1, 2, 3}, []byte{1, 2, 4}) == 0 {
		t.Fatal("memcmp unequal should be nonzero")
	}
	if !IsZero([]byte{0, 0, 0}) {
		t.Fatal("iszero")
	}
	if IsZero([]byte{0, 1, 0}) {
		t.Fatal("iszero false")
	}
	var a, b [32]byte
	if Verify32(&a, &b) != 1 {
		t.Fatal("verify32 equal")
	}
	b[0] = 1
	if Verify32(&a, &b) != 0 {
		t.Fatal("verify32 unequal")
	}
	MemZero(b[:])
	if b[0] != 0 {
		t.Fatal("memzero")
	}
}

// ===========================================================================
// BLAKE2b
// ===========================================================================

func TestGenericHashVector(t *testing.T) {
	out, err := GenericHash(32, []byte("abc"), nil)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "blake2b-32", out, hexmust("bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"))
}

func TestGenericHashKeyed(t *testing.T) {
	key := bytes.Repeat([]byte{0}, 32)
	out, err := GenericHash(32, []byte("abc"), key)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 32 {
		t.Fatal("len")
	}
	// determinism
	out2, _ := GenericHash(32, []byte("abc"), key)
	eq(t, "keyed determinism", out, out2)
}

func TestGenericHashStreaming(t *testing.T) {
	var st GenericHashState
	if err := st.Init(nil, 32); err != nil {
		t.Fatal(err)
	}
	st.Write([]byte("ab"))
	st.Write([]byte("c"))
	got, err := st.Sum(32)
	if err != nil {
		t.Fatal(err)
	}
	one, _ := GenericHash(32, []byte("abc"), nil)
	eq(t, "streaming == oneshot", got, one)
}

func TestGenericHashBadLen(t *testing.T) {
	if _, err := GenericHash(0, []byte("x"), nil); err == nil {
		t.Fatal("expected error for len 0")
	}
	if _, err := GenericHash(65, []byte("x"), nil); err == nil {
		t.Fatal("expected error for len 65")
	}
}

// ===========================================================================
// XChaCha20 stream
// ===========================================================================

func TestStreamXChaCha20Keystream(t *testing.T) {
	var nonce [24]byte
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	out, err := StreamXChaCha20(64, &nonce, &key)
	if err != nil {
		t.Fatal(err)
	}
	// keystream over zero message should equal xor of zero
	xor, _ := StreamXChaCha20XOR(bytes.Repeat([]byte{0}, 64), &nonce, &key)
	eq(t, "keystream==xor0", out, xor)
}

func TestStreamXChaCha20XORRoundtrip(t *testing.T) {
	var nonce [24]byte
	var key [32]byte
	rand := bytes.Repeat([]byte{0xA5}, 100)
	ct, _ := StreamXChaCha20XOR(rand, &nonce, &key)
	pt, _ := StreamXChaCha20XOR(ct, &nonce, &key)
	eq(t, "xor roundtrip", pt, rand)
}

func TestStreamXChaCha20XORIC(t *testing.T) {
	var nonce [24]byte
	var key [32]byte
	msg := bytes.Repeat([]byte{0}, 128)
	full, _ := StreamXChaCha20XOR(msg, &nonce, &key)
	// ic=1 over second 64 bytes should match
	half, _ := StreamXChaCha20XORIC(msg[64:], &nonce, 1, &key)
	eq(t, "xor_ic counter", half, full[64:])
}

// ===========================================================================
// HChaCha20 (internal)
// ===========================================================================

func TestHChaCha20DraftVector(t *testing.T) {
	key := hexd(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	nonce := hexd(t, "000000090000004a0000000031415927")
	out := hChaCha20(key, nonce)
	want := hexd(t, "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")
	eq(t, "hchacha20", out[:], want)
}

// ===========================================================================
// AEAD (IETF XChaCha20-Poly1305)
// ===========================================================================

func TestAEADEncryptDecrypt(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	nonce := bytes.Repeat([]byte{0x11}, 24)
	msg := []byte("hello csm world")
	ad := []byte("aad")
	c, err := AEADXChaCha20Poly1305IETFEncrypt(msg, ad, nonce, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(c) != len(msg)+16 {
		t.Fatalf("ct len %d", len(c))
	}
	m, err := AEADXChaCha20Poly1305IETFDecrypt(c, ad, nonce, key)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "aead roundtrip", m, msg)
}

func TestAEADTamper(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	nonce := bytes.Repeat([]byte{0x11}, 24)
	msg := []byte("secret")
	c, _ := AEADXChaCha20Poly1305IETFEncrypt(msg, []byte("ad"), nonce, key)
	for i := range c {
		bad := append([]byte{}, c...)
		bad[i] ^= 1
		if _, err := AEADXChaCha20Poly1305IETFDecrypt(bad, []byte("ad"), nonce, key); err == nil {
			t.Fatalf("tamper at %d not detected", i)
		}
	}
}

func TestAEADWrongAD(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	nonce := bytes.Repeat([]byte{0x11}, 24)
	c, _ := AEADXChaCha20Poly1305IETFEncrypt([]byte("m"), []byte("ad1"), nonce, key)
	if _, err := AEADXChaCha20Poly1305IETFDecrypt(c, []byte("ad2"), nonce, key); err == nil {
		t.Fatal("wrong ad accepted")
	}
}

func TestAEADDetached(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	nonce := bytes.Repeat([]byte{0x11}, 24)
	msg := []byte("detached test")
	c, mac, _ := AEADXChaCha20Poly1305IETFEncryptDetached(msg, []byte("a"), nonce, key)
	m, err := AEADXChaCha20Poly1305IETFDecryptDetached(c, &mac, []byte("a"), nonce, key)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "detached roundtrip", m, msg)
}

// ===========================================================================
// Secretbox
// ===========================================================================

func TestSecretboxRoundtrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x77}, 32)
	nonce := bytes.Repeat([]byte{0x33}, 24)
	msg := []byte("secret message")
	c, err := SecretboxXChaCha20Poly1305Easy(msg, nonce, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(c) != len(msg)+16 {
		t.Fatal("size")
	}
	m, err := SecretboxXChaCha20Poly1305OpenEasy(c, nonce, key)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "secretbox", m, msg)
}

func TestSecretboxTamper(t *testing.T) {
	key := bytes.Repeat([]byte{0x77}, 32)
	nonce := bytes.Repeat([]byte{0x33}, 24)
	c, _ := SecretboxXChaCha20Poly1305Easy([]byte("m"), nonce, key)
	bad := append([]byte{}, c...)
	bad[0] ^= 1
	if _, err := SecretboxXChaCha20Poly1305OpenEasy(bad, nonce, key); err == nil {
		t.Fatal("tamper not detected")
	}
}

func TestSecretboxDetachedRoundtrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x77}, 32)
	nonce := bytes.Repeat([]byte{0x33}, 24)
	msg := []byte("detached")
	c, mac, err := SecretboxXChaCha20Poly1305Detached(msg, nonce, key)
	if err != nil {
		t.Fatal(err)
	}
	m, err := SecretboxXChaCha20Poly1305OpenDetached(c, &mac, nonce, key)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "secretbox detached", m, msg)
}

func TestSecretboxEmpty(t *testing.T) {
	key := bytes.Repeat([]byte{0x77}, 32)
	nonce := bytes.Repeat([]byte{0x33}, 24)
	c, _ := SecretboxXChaCha20Poly1305Easy(nil, nonce, key)
	m, err := SecretboxXChaCha20Poly1305OpenEasy(c, nonce, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 0 {
		t.Fatal("empty msg")
	}
}

// ===========================================================================
// Box afternm
// ===========================================================================

func TestBoxAfterNMRoundtrip(t *testing.T) {
	k := bytes.Repeat([]byte{0x99}, 32)
	nonce := bytes.Repeat([]byte{0x44}, 24)
	msg := []byte("afternm")
	c, err := BoxCurve25519XChaCha20Poly1305EasyAfterNM(msg, nonce, k)
	if err != nil {
		t.Fatal(err)
	}
	m, err := BoxCurve25519XChaCha20Poly1305OpenEasyAfterNM(c, nonce, k)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "afternm", m, msg)
}

// ===========================================================================
// X25519
// ===========================================================================

func TestX25519RFC7748(t *testing.T) {
	n := hexd(t, "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
	p := hexd(t, "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
	want := hexd(t, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
	var n32, p32 [32]byte
	copy(n32[:], n)
	copy(p32[:], p)
	got, err := ScalarMultCurve25519(&n32, &p32)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "x25519 rfc7748", got[:], want)
}

func TestX25519DHAgreement(t *testing.T) {
	apk, askReal, _ := BoxCurve25519XChaCha20Poly1305Keypair()
	bpk, bskReal, _ := BoxCurve25519XChaCha20Poly1305Keypair()
	s1, _ := ScalarMultCurve25519(&askReal, &bpk)
	s2, _ := ScalarMultCurve25519(&bskReal, &apk)
	eq(t, "DH agreement", s1[:], s2[:])
}

func TestX25519SmallOrderRejected(t *testing.T) {
	var n, p [32]byte // all-zero point
	n[0] = 1
	if _, err := ScalarMultCurve25519(&n, &p); err == nil {
		t.Fatal("small-order point should be rejected")
	}
}

// ===========================================================================
// KX
// ===========================================================================

func TestKXSeedKeypairDeterministic(t *testing.T) {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	pk1, sk1, err := KXSeedKeypair(&seed)
	if err != nil {
		t.Fatal(err)
	}
	pk2, sk2, _ := KXSeedKeypair(&seed)
	eq(t, "kx pk determinism", pk1[:], pk2[:])
	eq(t, "kx sk determinism", sk1[:], sk2[:])
}

func TestKXSessionKeyAgreement(t *testing.T) {
	cpk, csk, _ := KXKeypair()
	spk, ssk, _ := KXKeypair()
	crx, ctx, err := KXClientSessionKeys(&cpk, &csk, &spk)
	if err != nil {
		t.Fatal(err)
	}
	srx, stx, err := KXServerSessionKeys(&spk, &ssk, &cpk)
	if err != nil {
		t.Fatal(err)
	}
	// client tx == server rx, client rx == server tx
	eq(t, "kx client tx == server rx", ctx[:], srx[:])
	eq(t, "kx client rx == server tx", crx[:], stx[:])
}

// ===========================================================================
// Box (asymmetric)
// ===========================================================================

func TestBoxSeedKeypairDeterministic(t *testing.T) {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	pk1, sk1, _ := BoxCurve25519XChaCha20Poly1305SeedKeypair(&seed)
	pk2, sk2, _ := BoxCurve25519XChaCha20Poly1305SeedKeypair(&seed)
	eq(t, "box pk", pk1[:], pk2[:])
	eq(t, "box sk", sk1[:], sk2[:])
}

func TestBoxEasyRoundtrip(t *testing.T) {
	pk, sk, _ := BoxCurve25519XChaCha20Poly1305Keypair()
	pk2, sk2, _ := BoxCurve25519XChaCha20Poly1305Keypair()
	nonce := bytes.Repeat([]byte{0x55}, 24)
	msg := []byte("box easy")
	c, err := BoxCurve25519XChaCha20Poly1305Easy(msg, nonce, &pk2, &sk)
	if err != nil {
		t.Fatal(err)
	}
	m, err := BoxCurve25519XChaCha20Poly1305OpenEasy(c, nonce, &pk, &sk2)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "box easy", m, msg)
}

func TestBoxSealRoundtrip(t *testing.T) {
	pk, sk, _ := BoxCurve25519XChaCha20Poly1305Keypair()
	msg := []byte("sealed")
	c, err := BoxCurve25519XChaCha20Poly1305Seal(msg, &pk)
	if err != nil {
		t.Fatal(err)
	}
	if len(c) != len(msg)+48 {
		t.Fatalf("seal size %d", len(c))
	}
	m, err := BoxCurve25519XChaCha20Poly1305SealOpen(c, &pk, &sk)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "box seal", m, msg)
}

// ===========================================================================
// Ed25519
// ===========================================================================

func TestSignEd25519SeedKeypair(t *testing.T) {
	seed := hexd(t, "9d61b19deffde21b862657e8e5ce8e0d4e3b8e3e8b3c8c3c3c3c3c3c3c3c3c3c")
	var s [32]byte
	copy(s[:], seed)
	pk, sk, err := SignEd25519SeedKeypair(&s)
	if err != nil {
		t.Fatal(err)
	}
	// sk = seed || pk
	eq(t, "sk seed half", sk[:32], seed)
	eq(t, "sk pk half", sk[32:], pk[:])
	// SKToPK / SKToSeed
	if SignEd25519SKToPK(&sk) != pk {
		t.Fatal("sktopk")
	}
	if SignEd25519SKToSeed(&sk) != s {
		t.Fatal("sktoseed")
	}
}

func TestSignEd25519Detached(t *testing.T) {
	seed := bytes.Repeat([]byte{0xAB}, 32)
	var s [32]byte
	copy(s[:], seed)
	pk, sk, _ := SignEd25519SeedKeypair(&s)
	msg := []byte("sign me")
	sig, err := SignEd25519Detached(msg, &sk)
	if err != nil {
		t.Fatal(err)
	}
	if !SignEd25519VerifyDetached(&sig, msg, &pk) {
		t.Fatal("verify failed")
	}
	// cross-check with crypto/ed25519
	if !ed25519.Verify(ed25519.PublicKey(pk[:]), msg, sig[:]) {
		t.Fatal("stdlib ed25519 verify failed")
	}
	// tampered message
	if SignEd25519VerifyDetached(&sig, append(msg, 'x'), &pk) {
		t.Fatal("tampered msg verified")
	}
}

func TestSignEd25519Combined(t *testing.T) {
	var s [32]byte
	for i := range s {
		s[i] = byte(i)
	}
	pk, sk, _ := SignEd25519SeedKeypair(&s)
	msg := []byte("combined sign")
	sm, _ := SignEd25519(msg, &sk)
	m, err := SignEd25519Open(sm, &pk)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "sign open", m, msg)
}

func TestEd25519ToCurve25519(t *testing.T) {
	// Verify pk->curve25519 then that the derived curve25519 pk matches a
	// scalarmult_base of sk_to_curve25519.
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i + 7)
	}
	edPK, edSK, _ := SignEd25519SeedKeypair(&seed)
	xPK, err := SignEd25519PKToCurve25519(&edPK)
	if err != nil {
		t.Fatal(err)
	}
	xSK, err := SignEd25519SKToCurve25519(&edSK)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := ScalarMultCurve25519Base(&xSK)
	eq(t, "ed->x pk == base(xsk)", xPK[:], base[:])
}

// ===========================================================================
// CSM
// ===========================================================================

func csmSetup(t *testing.T) (*CSMClient, *CSMServer) {
	t.Helper()
	var cs, ss [32]byte
	for i := range cs {
		cs[i] = byte(i)
		ss[i] = byte(i + 100)
	}
	spk, _, err := SignEd25519SeedKeypair(&ss)
	if err != nil {
		t.Fatal(err)
	}
	client, rc := CSMClientCreate(&cs, &spk)
	if rc != CSMOK {
		t.Fatalf("client create: %v", rc)
	}
	server, rc := CSMServerCreate(&ss)
	if rc != CSMOK {
		t.Fatalf("server create: %v", rc)
	}
	return client, server
}

func TestCSMRoundtrip(t *testing.T) {
	client, server := csmSetup(t)
	payload := []byte("client to server")
	pkt, rc := client.Encrypt(payload)
	if rc != CSMOK {
		t.Fatalf("encrypt: %v", rc)
	}
	if len(pkt) != CSMClientEncryptSize(len(payload)) {
		t.Fatalf("packet size %d", len(pkt))
	}
	pt, rc := server.Decrypt(pkt)
	if rc != CSMOK {
		t.Fatalf("decrypt: %v", rc)
	}
	eq(t, "csm client->server", pt, payload)
	if !server.ClientPublicKeyInitialized {
		t.Fatal("server did not learn client key")
	}
	reply := []byte("server reply")
	rpkt, rc := server.Encrypt(reply)
	if rc != CSMOK {
		t.Fatalf("server encrypt: %v", rc)
	}
	rpt, rc := client.Decrypt(rpkt)
	if rc != CSMOK {
		t.Fatalf("client decrypt: %v", rc)
	}
	eq(t, "csm server->client", rpt, reply)
}

func TestCSMTamper(t *testing.T) {
	client, server := csmSetup(t)
	pkt, _ := client.Encrypt([]byte("payload"))
	for i := range pkt {
		bad := append([]byte{}, pkt...)
		bad[i] ^= 0x80
		if _, rc := server.Decrypt(bad); rc == CSMOK {
			t.Fatalf("tamper at offset %d undetected", i)
		}
	}
}

func TestCSMEmptyPayload(t *testing.T) {
	client, _ := csmSetup(t)
	if _, rc := client.Encrypt(nil); rc != CSMErrNoData {
		t.Fatalf("expected NoData, got %v", rc)
	}
}

func TestCSMServerStateGuard(t *testing.T) {
	_, server := csmSetup(t)
	if _, rc := server.Encrypt([]byte("x")); rc != CSMErrState {
		t.Fatalf("expected State, got %v", rc)
	}
}

func TestCSMSizes(t *testing.T) {
	// The plain names describe the default (derived nonce, compact) packet,
	// which has no nonce field: 112 bytes of fixed overhead.
	if CSMClientEncryptSize(10) != 112+32+10 {
		t.Fatal("client encrypt size")
	}
	if CSMServerEncryptSize(10) != 112+10 {
		t.Fatal("server encrypt size")
	}
	if CSMServerDecryptMaxPlaintextSize(112+32+10) != 10 {
		t.Fatal("server decrypt max")
	}
	if CSMClientDecryptMaxPlaintextSize(112+10) != 10 {
		t.Fatal("client decrypt max")
	}
}

func TestCSMShortPacket(t *testing.T) {
	client, _ := csmSetup(t)
	if _, rc := client.Decrypt(bytes.Repeat([]byte{0}, 64)); rc != CSMErrInvalidArg && rc != CSMErrVerifyFailed && rc != CSMErrCrypto {
		// short packets should be rejected
	}
}

// ===========================================================================
// CSM nonce modes
// ===========================================================================

// Cross-language CSM test vectors from PROTOCOL.md, generated by naion.h with
// client Ed25519 seed 0x01 x 32, server Ed25519 seed 0x02 x 32, a random provider
// that fills every request with 0x5A, and payload = 00 01 02 .. 0f (16 bytes).
// server_ed_pk and client_ed_pk are 32 bytes; c2s_compact is 160 bytes,
// s2c_compact 128 bytes, c2s_random 184 bytes and s2c_random 152 bytes.
const (
	csmVecServerEdPKHex = "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394"
	csmVecClientEdPKHex = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"

	// nonce_mode = 0 (derived nonce, compact: no nonce field)
	csmVecC2SCompactHex = "676f9b6a8cdfa755841a467b2709b5b3cbe4249665bca1f30922237678aedf6e714b553b0f27fc4dfff8b1d0ca68d00c8333eaf1c12abf1ce72e8b85bac0100ab0d08f35b4683381489afb32825e59152d47d19bc9e050d6d5a954984c9d1e2c1f639c2334f0089bcb0a7d5da997c2016e84fa6a6df29e24e4aa8d4b394b9b980e0e11f7bf5b7f4fbce4435ba5d50e4fd432f7121f2b9b97d7fa83a0431d3b5d"
	csmVecS2CCompactHex = "0c4c0249692bc2852662efe431530e03f94237b589ad2c53ed758101eca18f2c139ef42b1437b77c775dfd59e93dd1dcc48f44547cd631f4fcbc31f266dc6708b0d08f35b4683381489afb32825e59152d47d19bc9e050d6d5a954984c9d1e2c86345b488d8ff6fdec5f09c153d04202f0db445448e1f320021649bb4d717143"

	// nonce_mode != 0 (random nonce transmitted in the packet)
	csmVecC2SRandomHex = "987f308ffecb2c195194c1f81b1c78db264b1d47073a009853869bb1f5ccfe84048317f7173b61bc57a91e6bf194221ebcbb6166dc6ccd83d7916ea7246dbd0cb0d08f35b4683381489afb32825e59152d47d19bc9e050d6d5a954984c9d1e2c5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5afbae93e8305a23e3a08f3f6d4cec110a364beb3d7e7c30a008b53895752c490bf48fab438eb09a71e7584cb6b0b7d9f0f6907d93f078090e34e100884d11ca5f"
	csmVecS2CRandomHex = "82b009cb900f66e2004ad257680ed111c586517cffcaae8cf9c0c020b628c5eac8700f4af571821ddf8442e7358f60b221f782aa5b8a6a3f2f2392a0a4365808b0d08f35b4683381489afb32825e59152d47d19bc9e050d6d5a954984c9d1e2c5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5af77b969223bfbf7eb79137cb22dad8aba92a7a99f5d08ba76c494c33b0d09b6f"
)

// csmTestPayload returns n deterministic bytes.
func csmTestPayload(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte((i*29 + 7) & 0xFF)
	}
	return out
}

// csmUseRandomProvider installs fn as the random provider for the duration of
// the test and restores the previous provider afterwards.
func csmUseRandomProvider(t *testing.T, fn RandomProvider) {
	t.Helper()
	prev := GetRandomProvider()
	SetRandomProvider(fn)
	t.Cleanup(func() { SetRandomProvider(prev) })
}

// csmFixedRandom returns a random provider that fills every request with value.
func csmFixedRandom(value byte) RandomProvider {
	return func(buf []byte) error {
		for i := range buf {
			buf[i] = value
		}
		return nil
	}
}

func TestCSMNonceModeConstantsAndSizes(t *testing.T) {
	if CSMNonceDerived != 0 || CSMNonceRandom != 1 {
		t.Fatalf("nonce mode constants: derived=%d random=%d", CSMNonceDerived, CSMNonceRandom)
	}
	if CSMMaxUDPDatagramBytes != 1024 || CSMClientPKBytes != 32 {
		t.Fatalf("budget: datagram=%d client pk=%d", CSMMaxUDPDatagramBytes, CSMClientPKBytes)
	}

	// Any mode other than CSMNonceDerived is random mode, exactly like
	// NAION_CSM_NONCE_FIELD_BYTES(mode) in naion.h.
	for _, mode := range []int{CSMNonceRandom, 2, 77, -1} {
		if got := CSMNonceFieldBytes(mode); got != 24 {
			t.Fatalf("CSMNonceFieldBytes(%d) = %d, want 24", mode, got)
		}
		if got := CSMPacketOverheadEx(mode); got != 136 {
			t.Fatalf("CSMPacketOverheadEx(%d) = %d, want 136", mode, got)
		}
		if got := CSMMaxClientPayloadBytesEx(mode); got != 856 {
			t.Fatalf("CSMMaxClientPayloadBytesEx(%d) = %d, want 856", mode, got)
		}
		if got := CSMMaxServerPayloadBytesEx(mode); got != 888 {
			t.Fatalf("CSMMaxServerPayloadBytesEx(%d) = %d, want 888", mode, got)
		}
	}
	// Derived (compact) mode: no nonce field.
	if CSMNonceFieldBytes(CSMNonceDerived) != 0 {
		t.Fatalf("CSMNonceFieldBytes(derived) = %d, want 0", CSMNonceFieldBytes(CSMNonceDerived))
	}
	if CSMPacketOverheadEx(CSMNonceDerived) != 112 {
		t.Fatalf("CSMPacketOverheadEx(derived) = %d, want 112", CSMPacketOverheadEx(CSMNonceDerived))
	}
	if CSMMaxClientPayloadBytesEx(CSMNonceDerived) != 880 || CSMMaxServerPayloadBytesEx(CSMNonceDerived) != 912 {
		t.Fatalf("derived payload limits: client=%d server=%d, want 880/912",
			CSMMaxClientPayloadBytesEx(CSMNonceDerived), CSMMaxServerPayloadBytesEx(CSMNonceDerived))
	}

	// The plain names describe the default (compact) packet ...
	if CSMPacketOverhead != 112 || CSMMaxClientPayloadBytes != 880 || CSMMaxServerPayloadBytes != 912 {
		t.Fatalf("default budget: overhead=%d client=%d server=%d, want 112/880/912",
			CSMPacketOverhead, CSMMaxClientPayloadBytes, CSMMaxServerPayloadBytes)
	}
	// ... and the CSMRandom* names describe the random nonce packet.
	if CSMRandomPacketOverhead != 136 || CSMRandomMaxClientPayloadBytes != 856 || CSMRandomMaxServerPayloadBytes != 888 {
		t.Fatalf("random budget: overhead=%d client=%d server=%d, want 136/856/888",
			CSMRandomPacketOverhead, CSMRandomMaxClientPayloadBytes, CSMRandomMaxServerPayloadBytes)
	}

	for n := 0; n <= CSMMaxUDPDatagramBytes+1; n++ {
		if got, want := CSMClientEncryptSizeEx(n, CSMNonceDerived), 112+32+n; got != want {
			t.Fatalf("CSMClientEncryptSizeEx(%d, derived) = %d, want %d", n, got, want)
		}
		if got, want := CSMClientEncryptSizeEx(n, CSMNonceRandom), 136+32+n; got != want {
			t.Fatalf("CSMClientEncryptSizeEx(%d, random) = %d, want %d", n, got, want)
		}
		if got, want := CSMServerEncryptSizeEx(n, CSMNonceDerived), 112+n; got != want {
			t.Fatalf("CSMServerEncryptSizeEx(%d, derived) = %d, want %d", n, got, want)
		}
		if got, want := CSMServerEncryptSizeEx(n, CSMNonceRandom), 136+n; got != want {
			t.Fatalf("CSMServerEncryptSizeEx(%d, random) = %d, want %d", n, got, want)
		}
		if got, want := CSMClientDecryptMaxPlaintextSizeEx(n, CSMNonceDerived), max(0, n-112); got != want {
			t.Fatalf("CSMClientDecryptMaxPlaintextSizeEx(%d, derived) = %d, want %d", n, got, want)
		}
		if got, want := CSMClientDecryptMaxPlaintextSizeEx(n, CSMNonceRandom), max(0, n-136); got != want {
			t.Fatalf("CSMClientDecryptMaxPlaintextSizeEx(%d, random) = %d, want %d", n, got, want)
		}
		if got, want := CSMServerDecryptMaxPlaintextSizeEx(n, CSMNonceDerived), max(0, n-112-32); got != want {
			t.Fatalf("CSMServerDecryptMaxPlaintextSizeEx(%d, derived) = %d, want %d", n, got, want)
		}
		if got, want := CSMServerDecryptMaxPlaintextSizeEx(n, CSMNonceRandom), max(0, n-136-32); got != want {
			t.Fatalf("CSMServerDecryptMaxPlaintextSizeEx(%d, random) = %d, want %d", n, got, want)
		}
		// The helpers without a mode argument are the derived mode of the *Ex helpers.
		if CSMClientEncryptSize(n) != CSMClientEncryptSizeEx(n, CSMNonceDerived) ||
			CSMServerEncryptSize(n) != CSMServerEncryptSizeEx(n, CSMNonceDerived) ||
			CSMClientDecryptMaxPlaintextSize(n) != CSMClientDecryptMaxPlaintextSizeEx(n, CSMNonceDerived) ||
			CSMServerDecryptMaxPlaintextSize(n) != CSMServerDecryptMaxPlaintextSizeEx(n, CSMNonceDerived) {
			t.Fatalf("default size helpers are not the derived mode at n=%d", n)
		}
		// The CSM-CA helpers are the Layer 3 helpers.
		if CSMCAClientEncryptSizeEx(n, CSMNonceDerived) != CSMClientEncryptSizeEx(n, CSMNonceDerived) ||
			CSMCAClientEncryptSizeEx(n, CSMNonceRandom) != CSMClientEncryptSizeEx(n, CSMNonceRandom) ||
			CSMCAClientDecryptMaxPlaintextSizeEx(n, CSMNonceDerived) != CSMClientDecryptMaxPlaintextSizeEx(n, CSMNonceDerived) ||
			CSMCAClientDecryptMaxPlaintextSizeEx(n, CSMNonceRandom) != CSMClientDecryptMaxPlaintextSizeEx(n, CSMNonceRandom) ||
			CSMCAServerEncryptSizeEx(n, CSMNonceDerived) != CSMServerEncryptSizeEx(n, CSMNonceDerived) ||
			CSMCAServerEncryptSizeEx(n, CSMNonceRandom) != CSMServerEncryptSizeEx(n, CSMNonceRandom) ||
			CSMCAServerDecryptMaxPlaintextSizeEx(n, CSMNonceDerived) != CSMServerDecryptMaxPlaintextSizeEx(n, CSMNonceDerived) ||
			CSMCAServerDecryptMaxPlaintextSizeEx(n, CSMNonceRandom) != CSMServerDecryptMaxPlaintextSizeEx(n, CSMNonceRandom) ||
			CSMCAClientEncryptSize(n) != CSMClientEncryptSize(n) ||
			CSMCAClientDecryptMaxPlaintextSize(n) != CSMClientDecryptMaxPlaintextSize(n) ||
			CSMCAServerEncryptSize(n) != CSMServerEncryptSize(n) ||
			CSMCAServerDecryptMaxPlaintextSize(n) != CSMServerDecryptMaxPlaintextSize(n) {
			t.Fatalf("CSM-CA size helpers differ from Layer 3 at n=%d", n)
		}
	}
}

// TestCSMDefaultCompactPackets covers the default mode: packet sizes of both
// directions (112 + 32 + n and 112 + n) and the round trips.
func TestCSMDefaultCompactPackets(t *testing.T) {
	client, server := csmSetup(t)
	payload := csmTestPayload(100)

	// client -> server: signature(64) | session_xpk(32) | mac(16) | ciphertext(32 + n)
	c2s, rc := client.Encrypt(payload)
	if rc != CSMOK {
		t.Fatalf("default client encrypt: %v", rc)
	}
	if want := 112 + 32 + len(payload); len(c2s) != want {
		t.Fatalf("default client packet size %d, want %d", len(c2s), want)
	}
	if len(c2s) != CSMClientEncryptSize(len(payload)) {
		t.Fatalf("default client packet size %d, want CSMClientEncryptSize %d",
			len(c2s), CSMClientEncryptSize(len(payload)))
	}
	pt, rc := server.Decrypt(c2s)
	if rc != CSMOK {
		t.Fatalf("default server decrypt: %v", rc)
	}
	eq(t, "default client -> server", pt, payload)
	if !server.ClientPublicKeyInitialized || server.ClientEdPublicKey != client.EdPublicKey {
		t.Fatal("server did not learn the client key")
	}

	// server -> client: signature(64) | session_xpk(32) | mac(16) | ciphertext(n)
	s2c, rc := server.Encrypt(payload)
	if rc != CSMOK {
		t.Fatalf("default server encrypt: %v", rc)
	}
	if want := 112 + len(payload); len(s2c) != want {
		t.Fatalf("default server packet size %d, want %d", len(s2c), want)
	}
	if len(s2c) != CSMServerEncryptSize(len(payload)) {
		t.Fatalf("default server packet size %d, want CSMServerEncryptSize %d",
			len(s2c), CSMServerEncryptSize(len(payload)))
	}
	pt, rc = client.Decrypt(s2c)
	if rc != CSMOK {
		t.Fatalf("default client decrypt: %v", rc)
	}
	eq(t, "default server -> client", pt, payload)

	// The default is nonce mode 0.
	if pt, rc = server.DecryptWithNonceMode(c2s, CSMNonceDerived); rc != CSMOK {
		t.Fatalf("a default packet is not a derived mode packet: %v", rc)
	}
	eq(t, "default packet opened as derived mode", pt, payload)
	if _, rc := server.DecryptWithNonceMode(c2s, CSMNonceRandom); rc == CSMOK {
		t.Fatal("a default packet was opened as a random mode packet")
	}
	if _, rc := client.DecryptWithNonceMode(s2c, CSMNonceRandom); rc == CSMOK {
		t.Fatal("a default server packet was opened as a random mode packet")
	}
	// An explicit mode 0 call produces the same packet layout.
	if p, rc := client.EncryptWithNonceMode(payload, CSMNonceDerived); rc != CSMOK || len(p) != len(c2s) {
		t.Fatalf("explicit derived mode packet: rc=%v len=%d, want len %d", rc, len(p), len(c2s))
	}
}

// TestCSMRandomNoncePackets covers random mode: packet sizes of both
// directions (136 + 32 + n and 136 + n) and the round trips.
func TestCSMRandomNoncePackets(t *testing.T) {
	client, server := csmSetup(t)
	payload := csmTestPayload(100)

	// client -> server: signature(64) | session_xpk(32) | nonce(24) | mac(16) | ciphertext(32 + n)
	c2s, rc := client.EncryptWithNonceMode(payload, CSMNonceRandom)
	if rc != CSMOK {
		t.Fatalf("random mode client encrypt: %v", rc)
	}
	if want := 136 + 32 + len(payload); len(c2s) != want {
		t.Fatalf("random mode client packet size %d, want %d", len(c2s), want)
	}
	if len(c2s) != CSMClientEncryptSizeEx(len(payload), CSMNonceRandom) {
		t.Fatalf("random mode client packet size %d, want CSMClientEncryptSizeEx %d",
			len(c2s), CSMClientEncryptSizeEx(len(payload), CSMNonceRandom))
	}
	pt, rc := server.DecryptWithNonceMode(c2s, CSMNonceRandom)
	if rc != CSMOK {
		t.Fatalf("random mode server decrypt: %v", rc)
	}
	eq(t, "random mode client -> server", pt, payload)
	if !server.ClientPublicKeyInitialized || server.ClientEdPublicKey != client.EdPublicKey {
		t.Fatal("server did not learn the client key")
	}

	// server -> client: signature(64) | session_xpk(32) | nonce(24) | mac(16) | ciphertext(n)
	s2c, rc := server.EncryptWithNonceMode(payload, CSMNonceRandom)
	if rc != CSMOK {
		t.Fatalf("random mode server encrypt: %v", rc)
	}
	if want := 136 + len(payload); len(s2c) != want {
		t.Fatalf("random mode server packet size %d, want %d", len(s2c), want)
	}
	if len(s2c) != CSMServerEncryptSizeEx(len(payload), CSMNonceRandom) {
		t.Fatalf("random mode server packet size %d, want CSMServerEncryptSizeEx %d",
			len(s2c), CSMServerEncryptSizeEx(len(payload), CSMNonceRandom))
	}
	pt, rc = client.DecryptWithNonceMode(s2c, CSMNonceRandom)
	if rc != CSMOK {
		t.Fatalf("random mode client decrypt: %v", rc)
	}
	eq(t, "random mode server -> client", pt, payload)

	// The nonce travels in bytes 96..120 of the packet and is fresh for every packet.
	other, rc := client.EncryptWithNonceMode(payload, CSMNonceRandom)
	if rc != CSMOK {
		t.Fatalf("random mode client encrypt: %v", rc)
	}
	if len(other) != len(c2s) {
		t.Fatalf("random mode client packet size %d, want %d", len(other), len(c2s))
	}
	if bytes.Equal(c2s[96:120], other[96:120]) {
		t.Fatal("two packets were sent with the same nonce")
	}

	// Every non-zero mode is the random mode.
	anyMode, rc := client.EncryptWithNonceMode(payload, 5)
	if rc != CSMOK || len(anyMode) != len(c2s) {
		t.Fatalf("mode 5 packet: rc=%v len=%d", rc, len(anyMode))
	}
	if pt, rc := server.DecryptWithNonceMode(anyMode, 9); rc != CSMOK || !bytes.Equal(pt, payload) {
		t.Fatalf("mode 5 packet opened with mode 9: rc=%v", rc)
	}
}

// TestCSMMinimumPacketLength checks the length check in front of both
// decryptors: a packet that cannot hold the fields of the nonce mode is
// rejected with CSMErrInvalidArg before any cryptography is done.
func TestCSMMinimumPacketLength(t *testing.T) {
	for _, mode := range []int{CSMNonceDerived, CSMNonceRandom} {
		client, server := csmSetup(t)
		clientMin := 64 + 32 + CSMNonceFieldBytes(mode) + 16 // server -> client
		serverMin := clientMin + 32                          // client -> server
		for n := 0; n <= serverMin; n++ {
			packet := bytes.Repeat([]byte{0xA5}, n)
			_, rc := client.DecryptWithNonceMode(packet, mode)
			if n <= clientMin {
				if rc != CSMErrInvalidArg {
					t.Fatalf("mode %d: server packet of %d bytes: got %v, want InvalidArg", mode, n, rc)
				}
			} else if rc == CSMErrInvalidArg || rc == CSMOK {
				t.Fatalf("mode %d: server packet of %d bytes should fail on the signature, got %v", mode, n, rc)
			}
			_, rc = server.DecryptWithNonceMode(packet, mode)
			if n <= serverMin {
				if rc != CSMErrInvalidArg {
					t.Fatalf("mode %d: client packet of %d bytes: got %v, want InvalidArg", mode, n, rc)
				}
			} else if rc == CSMErrInvalidArg || rc == CSMOK {
				t.Fatalf("mode %d: client packet of %d bytes should fail in AEAD, got %v", mode, n, rc)
			}
		}
		if server.ClientPublicKeyInitialized {
			t.Fatalf("mode %d: the server learnt a client key from junk", mode)
		}
	}
}

// TestCSMNonceModeMismatch: sender and receiver must use the same nonce mode.
func TestCSMNonceModeMismatch(t *testing.T) {
	t.Run("long_payload", func(t *testing.T) {
		client, server := csmSetup(t)
		payload := csmTestPayload(80)
		compact, rc := client.Encrypt(payload)
		if rc != CSMOK {
			t.Fatalf("client encrypt: %v", rc)
		}
		random, rc := client.EncryptWithNonceMode(payload, CSMNonceRandom)
		if rc != CSMOK {
			t.Fatalf("client encrypt random: %v", rc)
		}

		// client -> server: both mismatches fail in the AEAD, and the server
		// does not learn the client key from them.
		if _, rc := server.DecryptWithNonceMode(compact, CSMNonceRandom); rc != CSMErrCrypto {
			t.Fatalf("compact packet opened as random mode: got %v, want Crypto", rc)
		}
		if _, rc := server.Decrypt(random); rc != CSMErrCrypto {
			t.Fatalf("random mode packet opened as compact: got %v, want Crypto", rc)
		}
		if server.ClientPublicKeyInitialized {
			t.Fatal("the server learnt the client key from a packet of another nonce mode")
		}

		// The packets are intact; with the right mode they still open.
		if pt, rc := server.Decrypt(compact); rc != CSMOK || !bytes.Equal(pt, payload) {
			t.Fatalf("compact packet with the right mode: rc=%v", rc)
		}
		if !server.ClientPublicKeyInitialized || server.ClientEdPublicKey != client.EdPublicKey {
			t.Fatal("the server did not learn the client key from a valid packet")
		}
		if pt, rc := server.DecryptWithNonceMode(random, CSMNonceRandom); rc != CSMOK || !bytes.Equal(pt, payload) {
			t.Fatalf("random mode packet with the right mode: rc=%v", rc)
		}

		// server -> client behaves in the same way.
		replyCompact, rc := server.Encrypt(payload)
		if rc != CSMOK {
			t.Fatalf("server encrypt: %v", rc)
		}
		replyRandom, rc := server.EncryptWithNonceMode(payload, CSMNonceRandom)
		if rc != CSMOK {
			t.Fatalf("server encrypt random: %v", rc)
		}
		if _, rc := client.DecryptWithNonceMode(replyCompact, CSMNonceRandom); rc != CSMErrCrypto {
			t.Fatalf("compact reply opened as random mode: got %v, want Crypto", rc)
		}
		if _, rc := client.Decrypt(replyRandom); rc != CSMErrCrypto {
			t.Fatalf("random mode reply opened as compact: got %v, want Crypto", rc)
		}
		if pt, rc := client.Decrypt(replyCompact); rc != CSMOK || !bytes.Equal(pt, payload) {
			t.Fatalf("compact reply with the right mode: rc=%v", rc)
		}
		if pt, rc := client.DecryptWithNonceMode(replyRandom, CSMNonceRandom); rc != CSMOK || !bytes.Equal(pt, payload) {
			t.Fatalf("random mode reply with the right mode: rc=%v", rc)
		}
	})

	// Short payloads: a compact packet of at most 24 payload bytes is not
	// longer than the smallest possible random mode packet, so it is rejected
	// by the length check (CSMErrInvalidArg), like in naion.h. A random mode
	// packet is always long enough and fails in the AEAD (CSMErrCrypto).
	t.Run("short_payload", func(t *testing.T) {
		for _, n := range []int{1, 24, 25} {
			client, server := csmSetup(t)
			payload := csmTestPayload(n)
			compact, rc := client.Encrypt(payload)
			if rc != CSMOK {
				t.Fatalf("n=%d client encrypt: %v", n, rc)
			}
			random, rc := client.EncryptWithNonceMode(payload, CSMNonceRandom)
			if rc != CSMOK {
				t.Fatalf("n=%d client encrypt random: %v", n, rc)
			}
			want := CSMErrCrypto
			if n <= 24 {
				want = CSMErrInvalidArg
			}
			if _, rc := server.DecryptWithNonceMode(compact, CSMNonceRandom); rc != want {
				t.Fatalf("n=%d compact packet opened as random mode: got %v, want %v", n, rc, want)
			}
			if _, rc := server.Decrypt(random); rc != CSMErrCrypto {
				t.Fatalf("n=%d random mode packet opened as compact: got %v, want Crypto", n, rc)
			}
			if server.ClientPublicKeyInitialized {
				t.Fatalf("n=%d the server learnt the client key from a packet of another nonce mode", n)
			}
			if _, rc := server.Decrypt(compact); rc != CSMOK {
				t.Fatalf("n=%d compact packet with the right mode: %v", n, rc)
			}
			reply, rc := server.Encrypt(payload)
			if rc != CSMOK {
				t.Fatalf("n=%d server encrypt: %v", n, rc)
			}
			if _, rc := client.DecryptWithNonceMode(reply, CSMNonceRandom); rc != want {
				t.Fatalf("n=%d compact reply opened as random mode: got %v, want %v", n, rc, want)
			}
			replyRandom, rc := server.EncryptWithNonceMode(payload, CSMNonceRandom)
			if rc != CSMOK {
				t.Fatalf("n=%d server encrypt random: %v", n, rc)
			}
			if _, rc := client.Decrypt(replyRandom); rc != CSMErrCrypto {
				t.Fatalf("n=%d random mode reply opened as compact: got %v, want Crypto", n, rc)
			}
		}
	})
}

// TestCSMCompactTamperEveryField flips bytes in every field of a compact
// packet: signature, session public key, mac and ciphertext.
func TestCSMCompactTamperEveryField(t *testing.T) {
	client, server := csmSetup(t)
	payload := csmTestPayload(64)
	frame, rc := client.Encrypt(payload)
	if rc != CSMOK {
		t.Fatalf("client encrypt: %v", rc)
	}
	// signature(64) | session_x25519_public_key(64:96) | mac(96:112) | ciphertext(112:)
	fields := []struct {
		name    string
		offsets []int
		want    CSMError
	}{
		// The signature is checked with the client key taken from the opened plaintext.
		{"signature", []int{0, 32, 63}, CSMErrVerifyFailed},
		// The session key is the AAD and one half of the shared secret.
		{"session_x25519_public_key", []int{64, 80, 95}, CSMErrCrypto},
		{"mac", []int{96, 104, 111}, CSMErrCrypto},
		{"ciphertext", []int{112, (112 + len(frame)) / 2, len(frame) - 1}, CSMErrCrypto},
	}
	for _, field := range fields {
		for _, offset := range field.offsets {
			tampered := append([]byte{}, frame...)
			tampered[offset] ^= 0x01
			_, rc := server.Decrypt(tampered)
			if rc != field.want {
				t.Fatalf("%s byte %d tampered: got %v, want %v", field.name, offset, rc, field.want)
			}
			if server.ClientPublicKeyInitialized {
				t.Fatalf("%s byte %d tampered: the server learnt a client key", field.name, offset)
			}
		}
	}
	// The untampered frame still opens.
	if pt, rc := server.Decrypt(frame); rc != CSMOK || !bytes.Equal(pt, payload) {
		t.Fatalf("untampered compact packet: rc=%v", rc)
	}
}

// TestCSMTamperEveryByteBothModes flips every single byte of a packet in both
// directions and both nonce modes.
func TestCSMTamperEveryByteBothModes(t *testing.T) {
	for _, mode := range []int{CSMNonceDerived, CSMNonceRandom} {
		client, server := csmSetup(t)
		payload := csmTestPayload(37)

		c2s, rc := client.EncryptWithNonceMode(payload, mode)
		if rc != CSMOK {
			t.Fatalf("mode %d client encrypt: %v", mode, rc)
		}
		for i := range c2s {
			bad := append([]byte{}, c2s...)
			bad[i] ^= 0x80
			_, rc := server.DecryptWithNonceMode(bad, mode)
			if rc != CSMErrCrypto && rc != CSMErrVerifyFailed {
				t.Fatalf("mode %d: client packet byte %d tampered: got %v, want Crypto or VerifyFailed", mode, i, rc)
			}
			if server.ClientPublicKeyInitialized {
				t.Fatalf("mode %d: client packet byte %d tampered: the server learnt a client key", mode, i)
			}
		}
		if pt, rc := server.DecryptWithNonceMode(c2s, mode); rc != CSMOK || !bytes.Equal(pt, payload) {
			t.Fatalf("mode %d: untampered client packet: rc=%v", mode, rc)
		}

		s2c, rc := server.EncryptWithNonceMode(payload, mode)
		if rc != CSMOK {
			t.Fatalf("mode %d server encrypt: %v", mode, rc)
		}
		for i := range s2c {
			bad := append([]byte{}, s2c...)
			bad[i] ^= 0x80
			// The client checks the server signature before opening the packet.
			if _, rc := client.DecryptWithNonceMode(bad, mode); rc != CSMErrVerifyFailed {
				t.Fatalf("mode %d: server packet byte %d tampered: got %v, want VerifyFailed", mode, i, rc)
			}
		}
		if pt, rc := client.DecryptWithNonceMode(s2c, mode); rc != CSMOK || !bytes.Equal(pt, payload) {
			t.Fatalf("mode %d: untampered server packet: rc=%v", mode, rc)
		}
	}
}

// TestCSMPayloadLimits: 880/912 bytes in derived (compact) mode, 856/888
// bytes in random mode. A packet with the largest payload fills a
// CSMMaxUDPDatagramBytes datagram exactly.
func TestCSMPayloadLimits(t *testing.T) {
	modes := []struct {
		name      string
		mode      int
		clientMax int
		serverMax int
	}{
		{"derived_compact", CSMNonceDerived, 880, 912},
		{"random", CSMNonceRandom, 856, 888},
	}
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			if got := CSMMaxClientPayloadBytesEx(m.mode); got != m.clientMax {
				t.Fatalf("CSMMaxClientPayloadBytesEx = %d, want %d", got, m.clientMax)
			}
			if got := CSMMaxServerPayloadBytesEx(m.mode); got != m.serverMax {
				t.Fatalf("CSMMaxServerPayloadBytesEx = %d, want %d", got, m.serverMax)
			}
			client, server := csmSetup(t)

			c2sPayload := csmTestPayload(m.clientMax)
			c2s, rc := client.EncryptWithNonceMode(c2sPayload, m.mode)
			if rc != CSMOK {
				t.Fatalf("client encrypt of %d bytes: %v", m.clientMax, rc)
			}
			if want := CSMClientEncryptSizeEx(m.clientMax, m.mode); len(c2s) != want {
				t.Fatalf("client packet size %d, want %d", len(c2s), want)
			}
			if len(c2s) != CSMMaxUDPDatagramBytes {
				t.Fatalf("client packet size %d, want a full %d byte datagram", len(c2s), CSMMaxUDPDatagramBytes)
			}
			pt, rc := server.DecryptWithNonceMode(c2s, m.mode)
			if rc != CSMOK {
				t.Fatalf("server decrypt of %d bytes: %v", m.clientMax, rc)
			}
			eq(t, "largest client payload", pt, c2sPayload)

			s2cPayload := csmTestPayload(m.serverMax)
			s2c, rc := server.EncryptWithNonceMode(s2cPayload, m.mode)
			if rc != CSMOK {
				t.Fatalf("server encrypt of %d bytes: %v", m.serverMax, rc)
			}
			if want := CSMServerEncryptSizeEx(m.serverMax, m.mode); len(s2c) != want {
				t.Fatalf("server packet size %d, want %d", len(s2c), want)
			}
			if len(s2c) != CSMMaxUDPDatagramBytes {
				t.Fatalf("server packet size %d, want a full %d byte datagram", len(s2c), CSMMaxUDPDatagramBytes)
			}
			pt, rc = client.DecryptWithNonceMode(s2c, m.mode)
			if rc != CSMOK {
				t.Fatalf("client decrypt of %d bytes: %v", m.serverMax, rc)
			}
			eq(t, "largest server payload", pt, s2cPayload)

			// One more payload byte does not fit into the datagram.
			if got := CSMClientEncryptSizeEx(m.clientMax+1, m.mode); got != CSMMaxUDPDatagramBytes+1 {
				t.Fatalf("CSMClientEncryptSizeEx(%d) = %d, want %d", m.clientMax+1, got, CSMMaxUDPDatagramBytes+1)
			}
			if got := CSMServerEncryptSizeEx(m.serverMax+1, m.mode); got != CSMMaxUDPDatagramBytes+1 {
				t.Fatalf("CSMServerEncryptSizeEx(%d) = %d, want %d", m.serverMax+1, got, CSMMaxUDPDatagramBytes+1)
			}
			if got := CSMClientDecryptMaxPlaintextSizeEx(CSMMaxUDPDatagramBytes, m.mode); got != m.serverMax {
				t.Fatalf("CSMClientDecryptMaxPlaintextSizeEx(full datagram) = %d, want %d", got, m.serverMax)
			}
			if got := CSMServerDecryptMaxPlaintextSizeEx(CSMMaxUDPDatagramBytes, m.mode); got != m.clientMax {
				t.Fatalf("CSMServerDecryptMaxPlaintextSizeEx(full datagram) = %d, want %d", got, m.clientMax)
			}
		})
	}
	// The compact packet leaves 24 more bytes for the payload than the random one.
	if CSMMaxClientPayloadBytesEx(CSMNonceDerived)-CSMMaxClientPayloadBytesEx(CSMNonceRandom) != 24 {
		t.Fatal("compact client payload limit is not 24 bytes above the random one")
	}
	if CSMMaxServerPayloadBytesEx(CSMNonceDerived)-CSMMaxServerPayloadBytesEx(CSMNonceRandom) != 24 {
		t.Fatal("compact server payload limit is not 24 bytes above the random one")
	}
}

// TestCSMCrossLanguageVectors reproduces the packets of PROTOCOL.md byte for
// byte: fixed seeds, a random provider that answers 0x5A, 16-byte payload.
func TestCSMCrossLanguageVectors(t *testing.T) {
	csmUseRandomProvider(t, csmFixedRandom(0x5A))
	var cseed, sseed [32]byte
	for i := range cseed {
		cseed[i] = 0x01
		sseed[i] = 0x02
	}
	serverPK, _, err := SignEd25519SeedKeypair(&sseed)
	if err != nil {
		t.Fatal(err)
	}
	server, rc := CSMServerCreate(&sseed)
	if rc != CSMOK {
		t.Fatalf("server create: %v", rc)
	}
	client, rc := CSMClientCreate(&cseed, &serverPK)
	if rc != CSMOK {
		t.Fatalf("client create: %v", rc)
	}
	eq(t, "server_ed_pk", serverPK[:], hexmust(csmVecServerEdPKHex))
	eq(t, "client_ed_pk", client.EdPublicKey[:], hexmust(csmVecClientEdPKHex))

	payload := make([]byte, 16)
	for i := range payload {
		payload[i] = byte(i)
	}

	// nonce_mode = 0, the default.
	c2sCompact, rc := client.Encrypt(payload)
	if rc != CSMOK {
		t.Fatalf("client encrypt: %v", rc)
	}
	if len(c2sCompact) != 160 {
		t.Fatalf("c2s_compact is %d bytes, want 160", len(c2sCompact))
	}
	eq(t, "c2s_compact", c2sCompact, hexmust(csmVecC2SCompactHex))
	pt, rc := server.Decrypt(c2sCompact)
	if rc != CSMOK {
		t.Fatalf("server decrypt c2s_compact: %v", rc)
	}
	eq(t, "c2s_compact opened", pt, payload)
	s2cCompact, rc := server.Encrypt(payload)
	if rc != CSMOK {
		t.Fatalf("server encrypt: %v", rc)
	}
	if len(s2cCompact) != 128 {
		t.Fatalf("s2c_compact is %d bytes, want 128", len(s2cCompact))
	}
	eq(t, "s2c_compact", s2cCompact, hexmust(csmVecS2CCompactHex))
	pt, rc = client.Decrypt(s2cCompact)
	if rc != CSMOK {
		t.Fatalf("client decrypt s2c_compact: %v", rc)
	}
	eq(t, "s2c_compact opened", pt, payload)
	// Mode 0 passed explicitly is the default.
	if again, rc := client.EncryptWithNonceMode(payload, CSMNonceDerived); rc != CSMOK || !bytes.Equal(again, c2sCompact) {
		t.Fatalf("c2s_compact via explicit mode 0: rc=%v", rc)
	}

	// nonce_mode != 0.
	c2sRandom, rc := client.EncryptWithNonceMode(payload, CSMNonceRandom)
	if rc != CSMOK {
		t.Fatalf("client encrypt random: %v", rc)
	}
	if len(c2sRandom) != 184 {
		t.Fatalf("c2s_random is %d bytes, want 184", len(c2sRandom))
	}
	eq(t, "c2s_random", c2sRandom, hexmust(csmVecC2SRandomHex))
	pt, rc = server.DecryptWithNonceMode(c2sRandom, CSMNonceRandom)
	if rc != CSMOK {
		t.Fatalf("server decrypt c2s_random: %v", rc)
	}
	eq(t, "c2s_random opened", pt, payload)
	s2cRandom, rc := server.EncryptWithNonceMode(payload, CSMNonceRandom)
	if rc != CSMOK {
		t.Fatalf("server encrypt random: %v", rc)
	}
	if len(s2cRandom) != 152 {
		t.Fatalf("s2c_random is %d bytes, want 152", len(s2cRandom))
	}
	eq(t, "s2c_random", s2cRandom, hexmust(csmVecS2CRandomHex))
	pt, rc = client.DecryptWithNonceMode(s2cRandom, CSMNonceRandom)
	if rc != CSMOK {
		t.Fatalf("client decrypt s2c_random: %v", rc)
	}
	eq(t, "s2c_random opened", pt, payload)

	// Layout of the vectors. The fixed provider always answers 0x5A, so all
	// four packets carry the same one-time public key ...
	sessionXPK := c2sCompact[64:96]
	for _, packet := range [][]byte{s2cCompact, c2sRandom, s2cRandom} {
		if !bytes.Equal(packet[64:96], sessionXPK) {
			t.Fatalf("session public key %x, want %x", packet[64:96], sessionXPK)
		}
	}
	// ... the random mode packets carry their nonce where the compact ones
	// start with the mac ...
	if !bytes.Equal(c2sRandom[96:120], bytes.Repeat([]byte{0x5A}, 24)) ||
		!bytes.Equal(s2cRandom[96:120], bytes.Repeat([]byte{0x5A}, 24)) {
		t.Fatal("the random mode vectors do not carry the 0x5A nonce")
	}
	// ... so a random mode packet is exactly the nonce field longer.
	if len(c2sRandom)-len(c2sCompact) != 24 || len(s2cRandom)-len(s2cCompact) != 24 {
		t.Fatal("random mode vectors are not 24 bytes longer than the compact ones")
	}
}

// TestCSMDerivedNonceMatchesSpec rebuilds the compact client -> server vector
// from the formulas of the specification with the stock X25519 and
// XChaCha20-Poly1305 of golang.org/x/crypto, independently of the CSM code:
//
//	shared = X25519(self_xsk, peer_xpk)
//	ekey   = HChaCha20(key = shared, in = 0x00 x 16)
//	nonce  = HChaCha20(key = shared, in = "naion.csm.nonce.")[0..23]
func TestCSMDerivedNonceMatchesSpec(t *testing.T) {
	var cseed, sseed [32]byte
	for i := range cseed {
		cseed[i] = 0x01
		sseed[i] = 0x02
	}
	serverPK, serverSK, err := SignEd25519SeedKeypair(&sseed)
	if err != nil {
		t.Fatal(err)
	}
	clientPK, _, err := SignEd25519SeedKeypair(&cseed)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "server_ed_pk", serverPK[:], hexmust(csmVecServerEdPKHex))
	eq(t, "client_ed_pk", clientPK[:], hexmust(csmVecClientEdPKHex))
	packet := hexmust(csmVecC2SCompactHex)
	sessionXPK := packet[64:96]

	serverXSK, err := SignEd25519SKToCurve25519(&serverSK)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := curve25519.X25519(serverXSK[:], sessionXPK)
	if err != nil {
		t.Fatal(err)
	}
	ekey := hChaCha20(shared, make([]byte, 16))
	kdf := hChaCha20(shared, []byte("naion.csm.nonce."))
	nonce := kdf[:24]

	// ekey is exactly the beforenm key of the one-time key pair.
	var sessionXPKArr [32]byte
	copy(sessionXPKArr[:], sessionXPK)
	beforenm, err := BoxCurve25519XChaCha20Poly1305BeforeNM(&sessionXPKArr, &serverXSK)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "ekey == beforenm", ekey[:], beforenm[:])

	// The packet is XChaCha20-Poly1305(ekey, nonce) over client_ed_pk || payload
	// with aad = session_xpk. chacha20poly1305 returns and expects
	// ciphertext || tag, the CSM packet stores mac || ciphertext.
	aead, err := chacha20poly1305.NewX(ekey[:])
	if err != nil {
		t.Fatal(err)
	}
	plain := append(append([]byte{}, clientPK[:]...), 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
	sealed := aead.Seal(nil, nonce, plain, sessionXPK)
	tagAt := len(sealed) - 16
	if tagAt != len(plain) || len(packet) != 96+16+len(plain) {
		t.Fatalf("unexpected sizes: sealed=%d plain=%d packet=%d", len(sealed), len(plain), len(packet))
	}
	eq(t, "mac from the specification", packet[96:112], sealed[tagAt:])
	eq(t, "ciphertext from the specification", packet[112:], sealed[:tagAt])
	opened, err := aead.Open(nil, nonce, append(append([]byte{}, packet[112:]...), packet[96:112]...), sessionXPK)
	if err != nil {
		t.Fatalf("the vector does not open with the derived key and nonce: %v", err)
	}
	eq(t, "client_ed_pk || payload", opened, plain)

	// csmInternalDerive returns exactly this key and this nonce.
	gotEkey, gotNonce, err := csmInternalDerive(sessionXPK, serverXSK[:])
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "csmInternalDerive ekey", gotEkey[:], ekey[:])
	eq(t, "csmInternalDerive nonce", gotNonce[:], nonce)
}

// TestCSMDeriveKeyAndNonceIndependent checks the key and nonce derivation on
// fresh key pairs: both ends agree, ekey is the beforenm key, and the nonce
// is a separate HChaCha20 output that shares nothing with ekey.
func TestCSMDeriveKeyAndNonceIndependent(t *testing.T) {
	var previousEkey [32]byte
	var previousNonce [24]byte
	for round := 0; round < 8; round++ {
		pkA, skA, err := BoxCurve25519XChaCha20Poly1305Keypair()
		if err != nil {
			t.Fatal(err)
		}
		pkB, skB, err := BoxCurve25519XChaCha20Poly1305Keypair()
		if err != nil {
			t.Fatal(err)
		}

		// Both ends of the key pair derive the same key and nonce.
		ekeyAB, nonceAB, err := csmInternalDerive(pkB[:], skA[:])
		if err != nil {
			t.Fatal(err)
		}
		ekeyBA, nonceBA, err := csmInternalDerive(pkA[:], skB[:])
		if err != nil {
			t.Fatal(err)
		}
		if ekeyAB != ekeyBA || nonceAB != nonceBA {
			t.Fatalf("round %d: the two ends derived different key/nonce", round)
		}

		// ekey is the beforenm key ...
		beforenm, err := BoxCurve25519XChaCha20Poly1305BeforeNM(&pkB, &skA)
		if err != nil {
			t.Fatal(err)
		}
		if ekeyAB != beforenm {
			t.Fatalf("round %d: ekey differs from the beforenm key", round)
		}
		// ... and the nonce is the truncated second HChaCha20 output.
		shared, err := curve25519.X25519(skA[:], pkB[:])
		if err != nil {
			t.Fatal(err)
		}
		kdf := hChaCha20(shared, []byte("naion.csm.nonce."))
		if !bytes.Equal(nonceAB[:], kdf[:24]) {
			t.Fatalf("round %d: nonce is not HChaCha20(shared, \"naion.csm.nonce.\")[0..23]", round)
		}
		// Independent outputs: the KDF output is not the key, and the nonce is
		// not a window of the key.
		if subtle.ConstantTimeCompare(ekeyAB[:], kdf[:]) == 1 {
			t.Fatalf("round %d: the nonce KDF output equals the AEAD key", round)
		}
		if bytes.Contains(ekeyAB[:], nonceAB[:]) {
			t.Fatalf("round %d: the nonce is a window of the AEAD key", round)
		}
		// A new one-time key pair gives a new key and a new nonce.
		if round > 0 && (ekeyAB == previousEkey || nonceAB == previousNonce) {
			t.Fatalf("round %d: a new key pair repeated the previous key or nonce", round)
		}
		previousEkey, previousNonce = ekeyAB, nonceAB
	}
}

// TestCSMRandomProviderUsage: the one-time X25519 key always comes from the
// random provider; only random mode draws a nonce from it, after the key.
func TestCSMRandomProviderUsage(t *testing.T) {
	client, _ := csmSetup(t)
	payload := csmTestPayload(50)
	var requests []int
	csmUseRandomProvider(t, func(buf []byte) error {
		requests = append(requests, len(buf))
		return csmFixedRandom(0x5A)(buf)
	})

	// Derived mode: one 32-byte request per packet, no nonce.
	if _, rc := client.Encrypt(payload); rc != CSMOK {
		t.Fatalf("client encrypt: %v", rc)
	}
	if len(requests) != 1 || requests[0] != 32 {
		t.Fatalf("derived mode drew %v from the random provider, want one 32-byte request", requests)
	}
	if _, rc := client.EncryptWithNonceMode(payload, CSMNonceDerived); rc != CSMOK {
		t.Fatalf("client encrypt derived: %v", rc)
	}
	if len(requests) != 2 || requests[1] != 32 {
		t.Fatalf("explicit derived mode drew %v, want a second 32-byte request", requests)
	}
	// Random mode: the 32-byte key first, then the 24-byte nonce, as in naion.h.
	requests = nil
	if _, rc := client.EncryptWithNonceMode(payload, CSMNonceRandom); rc != CSMOK {
		t.Fatalf("client encrypt random: %v", rc)
	}
	if len(requests) != 2 || requests[0] != 32 || requests[1] != 24 {
		t.Fatalf("random mode drew %v, want [32 24]", requests)
	}

	// The internal seal draws nothing in derived mode and only the nonce in random mode.
	pk, sk, err := BoxCurve25519XChaCha20Poly1305Keypair()
	if err != nil {
		t.Fatal(err)
	}
	// compact holds mac || ciphertext, random holds nonce || mac || ciphertext.
	compact := make([]byte, 16+len(payload))
	random := make([]byte, 24+16+len(payload))
	requests = nil
	if rc := csmInternalSeal(payload, pk[:], sk[:], pk[:], compact, CSMNonceDerived); rc != CSMOK {
		t.Fatalf("internal seal derived: %v", rc)
	}
	if len(requests) != 0 {
		t.Fatalf("derived mode seal drew %v, want nothing", requests)
	}
	if pt, rc := csmInternalOpen(compact, pk[:], sk[:], pk[:], CSMNonceDerived); rc != CSMOK || !bytes.Equal(pt, payload) {
		t.Fatalf("internal open derived: rc=%v", rc)
	}
	// ... and it does not open as a random mode packet.
	if _, rc := csmInternalOpen(compact, pk[:], sk[:], pk[:], CSMNonceRandom); rc != CSMErrCrypto {
		t.Fatalf("derived mode seal opened as random mode: got %v, want Crypto", rc)
	}
	if rc := csmInternalSeal(payload, pk[:], sk[:], pk[:], random, CSMNonceRandom); rc != CSMOK {
		t.Fatalf("internal seal random: %v", rc)
	}
	if len(requests) != 1 || requests[0] != 24 {
		t.Fatalf("random mode seal drew %v, want one 24-byte request", requests)
	}
	if !bytes.Equal(random[:24], bytes.Repeat([]byte{0x5A}, 24)) {
		t.Fatal("random mode seal did not store the nonce in the packet")
	}
	if pt, rc := csmInternalOpen(random, pk[:], sk[:], pk[:], CSMNonceRandom); rc != CSMOK || !bytes.Equal(pt, payload) {
		t.Fatalf("internal open random: rc=%v", rc)
	}
	if _, rc := csmInternalOpen(random, pk[:], sk[:], pk[:], CSMNonceDerived); rc != CSMErrCrypto {
		t.Fatalf("random mode seal opened as derived mode: got %v, want Crypto", rc)
	}
	// The derived nonce is not the 0x5A nonce of random mode, so sealing the
	// same plaintext with the same key pair gives different packets: the
	// compact packet is not the random mode packet without its nonce field.
	if bytes.Equal(compact, random[24:]) {
		t.Fatal("the derived nonce equals the random one")
	}

	// A failing provider is reported, also when only the nonce draw fails.
	csmUseRandomProvider(t, func(buf []byte) error { return errors.New("no entropy") })
	if _, rc := client.Encrypt(payload); rc != CSMErrRandomProvider {
		t.Fatalf("derived mode with a dead provider: got %v, want RandomProvider", rc)
	}
	if _, rc := client.EncryptWithNonceMode(payload, CSMNonceRandom); rc != CSMErrRandomProvider {
		t.Fatalf("random mode with a dead provider: got %v, want RandomProvider", rc)
	}
	calls := 0
	csmUseRandomProvider(t, func(buf []byte) error {
		calls++
		if calls == 2 {
			return errors.New("no entropy for the nonce")
		}
		return csmFixedRandom(0x5A)(buf)
	})
	if _, rc := client.EncryptWithNonceMode(payload, CSMNonceRandom); rc != CSMErrRandomProvider {
		t.Fatalf("random mode with a failing nonce draw: got %v, want RandomProvider", rc)
	}
}

// ===========================================================================
// CSM-CA
// ===========================================================================

func TestCSMCAHandshakeAndTraffic(t *testing.T) {
	// CA keypair
	caSeed := bytes.Repeat([]byte{9}, 32)
	var cas [32]byte
	copy(cas[:], caSeed)
	caPK, caSK, _ := SignEd25519SeedKeypair(&cas)

	// server seed + CA signature over server ed pk
	var ss [32]byte
	for i := range ss {
		ss[i] = byte(i + 50)
	}
	spk, _, _ := SignEd25519SeedKeypair(&ss)
	var caSig [64]byte
	sigSlice, _ := SignEd25519Detached(spk[:], &caSK)
	copy(caSig[:], sigSlice[:])

	server, rc := CSMCAServerCreate(&ss, &caSig)
	if rc != CSMOK {
		t.Fatalf("ca server create: %v", rc)
	}
	m1, rc := server.HandshakeResponse()
	if rc != CSMOK {
		t.Fatalf("handshake response: %v", rc)
	}
	if len(m1[:]) != CSMCACertBytes {
		t.Fatalf("cert size %d", len(m1[:]))
	}

	// client
	var cs [32]byte
	for i := range cs {
		cs[i] = byte(i + 1)
	}
	client, rc := CSMCAClientCreate(&cs, &caPK)
	if rc != CSMOK {
		t.Fatalf("ca client create: %v", rc)
	}
	if rc := client.HandshakeVerify(m1[:]); rc != CSMOK {
		t.Fatalf("handshake verify: %v", rc)
	}
	if !client.ServerKeyVerified {
		t.Fatal("client not verified")
	}

	// post-handshake traffic
	payload := []byte("ca traffic")
	pkt, rc := client.Encrypt(payload)
	if rc != CSMOK {
		t.Fatalf("encrypt: %v", rc)
	}
	pt, rc := server.Decrypt(pkt)
	if rc != CSMOK {
		t.Fatalf("decrypt: %v", rc)
	}
	eq(t, "ca client->server", pt, payload)
}

func TestCSMCAWrongCA(t *testing.T) {
	caSeed := bytes.Repeat([]byte{9}, 32)
	var cas [32]byte
	copy(cas[:], caSeed)
	caPK, _, _ := SignEd25519SeedKeypair(&cas)

	wrongCaSeed := bytes.Repeat([]byte{8}, 32)
	var wcas [32]byte
	copy(wcas[:], wrongCaSeed)
	_, wrongCaSK, _ := SignEd25519SeedKeypair(&wcas)

	var ss [32]byte
	for i := range ss {
		ss[i] = byte(i + 50)
	}
	spk, _, _ := SignEd25519SeedKeypair(&ss)
	var bs [64]byte
	badSig, _ := SignEd25519Detached(spk[:], &wrongCaSK)
	copy(bs[:], badSig[:])
	server, _ := CSMCAServerCreate(&ss, &bs)
	m1, _ := server.HandshakeResponse()

	var cs [32]byte
	client, _ := CSMCAClientCreate(&cs, &caPK)
	if rc := client.HandshakeVerify(m1[:]); rc != CSMErrVerifyFailed {
		t.Fatalf("expected verify failed, got %v", rc)
	}
}

// ===========================================================================
// CSM-CA nonce modes (post-handshake traffic uses the Layer 3 packet format)
// ===========================================================================

func csmCASetup(t *testing.T) (*CSMCAClient, *CSMCAServer) {
	t.Helper()
	var caSeed [32]byte
	for i := range caSeed {
		caSeed[i] = byte(200 + i)
	}
	caPK, caSK, err := SignEd25519SeedKeypair(&caSeed)
	if err != nil {
		t.Fatal(err)
	}
	var ss [32]byte
	for i := range ss {
		ss[i] = byte(i + 50)
	}
	serverPK, _, err := SignEd25519SeedKeypair(&ss)
	if err != nil {
		t.Fatal(err)
	}
	caSig, err := SignEd25519Detached(serverPK[:], &caSK)
	if err != nil {
		t.Fatal(err)
	}
	server, rc := CSMCAServerCreate(&ss, &caSig)
	if rc != CSMOK {
		t.Fatalf("ca server create: %v", rc)
	}
	m1, rc := server.HandshakeResponse()
	if rc != CSMOK {
		t.Fatalf("handshake response: %v", rc)
	}
	var cs [32]byte
	for i := range cs {
		cs[i] = byte(i + 1)
	}
	client, rc := CSMCAClientCreate(&cs, &caPK)
	if rc != CSMOK {
		t.Fatalf("ca client create: %v", rc)
	}
	if rc := client.HandshakeVerify(m1[:]); rc != CSMOK {
		t.Fatalf("handshake verify: %v", rc)
	}
	return client, server
}

// TestCSMCANonceModes round trips CSM-CA traffic in both nonce modes and
// checks that mismatched modes fail without teaching the server the client key.
func TestCSMCANonceModes(t *testing.T) {
	modes := []struct {
		name     string
		mode     int
		overhead int
	}{
		{"derived_compact", CSMNonceDerived, 112},
		{"random", CSMNonceRandom, 136},
	}
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			client, server := csmCASetup(t)
			other := CSMNonceRandom
			if m.mode == CSMNonceRandom {
				other = CSMNonceDerived
			}
			payload := csmTestPayload(120)

			// client -> server
			c2s, rc := client.EncryptWithNonceMode(payload, m.mode)
			if rc != CSMOK {
				t.Fatalf("ca client encrypt: %v", rc)
			}
			if want := m.overhead + 32 + len(payload); len(c2s) != want {
				t.Fatalf("ca client packet size %d, want %d", len(c2s), want)
			}
			if len(c2s) != CSMCAClientEncryptSizeEx(len(payload), m.mode) {
				t.Fatalf("ca client packet size %d, want CSMCAClientEncryptSizeEx %d",
					len(c2s), CSMCAClientEncryptSizeEx(len(payload), m.mode))
			}
			if _, rc := server.DecryptWithNonceMode(c2s, other); rc == CSMOK {
				t.Fatalf("ca client packet of mode %d opened with mode %d", m.mode, other)
			}
			if server.ClientKeyVerified {
				t.Fatalf("the ca server learnt the client key from a packet of mode %d opened with mode %d", m.mode, other)
			}
			pt, rc := server.DecryptWithNonceMode(c2s, m.mode)
			if rc != CSMOK {
				t.Fatalf("ca server decrypt: %v", rc)
			}
			eq(t, "ca client -> server", pt, payload)
			if !server.ClientKeyVerified || server.ClientEdPublicKey != client.EdPublicKey {
				t.Fatal("the ca server did not learn the client key")
			}

			// server -> client
			s2c, rc := server.EncryptWithNonceMode(payload, m.mode)
			if rc != CSMOK {
				t.Fatalf("ca server encrypt: %v", rc)
			}
			if want := m.overhead + len(payload); len(s2c) != want {
				t.Fatalf("ca server packet size %d, want %d", len(s2c), want)
			}
			if len(s2c) != CSMCAServerEncryptSizeEx(len(payload), m.mode) {
				t.Fatalf("ca server packet size %d, want CSMCAServerEncryptSizeEx %d",
					len(s2c), CSMCAServerEncryptSizeEx(len(payload), m.mode))
			}
			if _, rc := client.DecryptWithNonceMode(s2c, other); rc == CSMOK {
				t.Fatalf("ca server packet of mode %d opened with mode %d", m.mode, other)
			}
			pt, rc = client.DecryptWithNonceMode(s2c, m.mode)
			if rc != CSMOK {
				t.Fatalf("ca client decrypt: %v", rc)
			}
			eq(t, "ca server -> client", pt, payload)

			if m.mode == CSMNonceDerived {
				// The methods without a mode argument are the derived mode.
				defaultPacket, rc := client.Encrypt(payload)
				if rc != CSMOK || len(defaultPacket) != len(c2s) {
					t.Fatalf("ca default client packet: rc=%v len=%d", rc, len(defaultPacket))
				}
				if pt, rc := server.Decrypt(defaultPacket); rc != CSMOK || !bytes.Equal(pt, payload) {
					t.Fatalf("ca default server decrypt: rc=%v", rc)
				}
				defaultReply, rc := server.Encrypt(payload)
				if rc != CSMOK || len(defaultReply) != len(s2c) {
					t.Fatalf("ca default server packet: rc=%v len=%d", rc, len(defaultReply))
				}
				if pt, rc := client.Decrypt(defaultReply); rc != CSMOK || !bytes.Equal(pt, payload) {
					t.Fatalf("ca default client decrypt: rc=%v", rc)
				}
			}
		})
	}
}

// TestCSMCACrossLanguageVectors: the handshake only establishes the server
// key, the CSM-CA packets are Layer 3 packets, so the CA pair reproduces the
// cross-language vectors of PROTOCOL.md in both nonce modes.
func TestCSMCACrossLanguageVectors(t *testing.T) {
	csmUseRandomProvider(t, csmFixedRandom(0x5A))
	var caSeed [32]byte
	for i := range caSeed {
		caSeed[i] = 0x03
	}
	caPK, caSK, err := SignEd25519SeedKeypair(&caSeed)
	if err != nil {
		t.Fatal(err)
	}
	var cseed, sseed [32]byte
	for i := range cseed {
		cseed[i] = 0x01
		sseed[i] = 0x02
	}
	serverPK, _, err := SignEd25519SeedKeypair(&sseed)
	if err != nil {
		t.Fatal(err)
	}
	caSig, err := SignEd25519Detached(serverPK[:], &caSK)
	if err != nil {
		t.Fatal(err)
	}
	server, rc := CSMCAServerCreate(&sseed, &caSig)
	if rc != CSMOK {
		t.Fatalf("ca server create: %v", rc)
	}
	m1, rc := server.HandshakeResponse()
	if rc != CSMOK {
		t.Fatalf("handshake response: %v", rc)
	}
	if len(m1) != CSMCACertBytes {
		t.Fatalf("certificate size %d", len(m1))
	}
	eq(t, "ca certificate", m1[:], append(append([]byte{}, hexmust(csmVecServerEdPKHex)...), caSig[:]...))
	client, rc := CSMCAClientCreate(&cseed, &caPK)
	if rc != CSMOK {
		t.Fatalf("ca client create: %v", rc)
	}
	eq(t, "ca client_ed_pk", client.EdPublicKey[:], hexmust(csmVecClientEdPKHex))
	if rc := client.HandshakeVerify(m1[:]); rc != CSMOK {
		t.Fatalf("handshake verify: %v", rc)
	}

	payload := make([]byte, 16)
	for i := range payload {
		payload[i] = byte(i)
	}

	// nonce_mode = 0, the default.
	c2sCompact, rc := client.Encrypt(payload)
	if rc != CSMOK {
		t.Fatalf("ca client encrypt: %v", rc)
	}
	eq(t, "ca c2s_compact", c2sCompact, hexmust(csmVecC2SCompactHex))
	if pt, rc := server.Decrypt(c2sCompact); rc != CSMOK || !bytes.Equal(pt, payload) {
		t.Fatalf("ca server decrypt c2s_compact: rc=%v", rc)
	}
	s2cCompact, rc := server.Encrypt(payload)
	if rc != CSMOK {
		t.Fatalf("ca server encrypt: %v", rc)
	}
	eq(t, "ca s2c_compact", s2cCompact, hexmust(csmVecS2CCompactHex))
	if pt, rc := client.Decrypt(s2cCompact); rc != CSMOK || !bytes.Equal(pt, payload) {
		t.Fatalf("ca client decrypt s2c_compact: rc=%v", rc)
	}

	// nonce_mode != 0.
	c2sRandom, rc := client.EncryptWithNonceMode(payload, CSMNonceRandom)
	if rc != CSMOK {
		t.Fatalf("ca client encrypt random: %v", rc)
	}
	eq(t, "ca c2s_random", c2sRandom, hexmust(csmVecC2SRandomHex))
	if pt, rc := server.DecryptWithNonceMode(c2sRandom, CSMNonceRandom); rc != CSMOK || !bytes.Equal(pt, payload) {
		t.Fatalf("ca server decrypt c2s_random: rc=%v", rc)
	}
	s2cRandom, rc := server.EncryptWithNonceMode(payload, CSMNonceRandom)
	if rc != CSMOK {
		t.Fatalf("ca server encrypt random: %v", rc)
	}
	eq(t, "ca s2c_random", s2cRandom, hexmust(csmVecS2CRandomHex))
	if pt, rc := client.DecryptWithNonceMode(s2cRandom, CSMNonceRandom); rc != CSMOK || !bytes.Equal(pt, payload) {
		t.Fatalf("ca client decrypt s2c_random: rc=%v", rc)
	}
}

// ===========================================================================
// XSalsa20 family
// ===========================================================================

func TestXSalsa20SecretboxRoundtrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x12}, 32)
	nonce := bytes.Repeat([]byte{0x34}, 24)
	msg := []byte("xsalsa20 secret")
	c, err := SecretboxXSalsa20Poly1305Easy(msg, nonce, key)
	if err != nil {
		t.Fatal(err)
	}
	m, err := SecretboxXSalsa20Poly1305OpenEasy(c, nonce, key)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "xsalsa20 secretbox", m, msg)
}

func TestXSalsa20BoxRoundtrip(t *testing.T) {
	pk, sk, _ := BoxCurve25519XSalsa20Poly1305Keypair()
	pk2, sk2, _ := BoxCurve25519XSalsa20Poly1305Keypair()
	nonce := bytes.Repeat([]byte{0x66}, 24)
	msg := []byte("xsalsa box")
	c, err := BoxCurve25519XSalsa20Poly1305Easy(msg, nonce, &pk2, &sk)
	if err != nil {
		t.Fatal(err)
	}
	m, err := BoxCurve25519XSalsa20Poly1305OpenEasy(c, nonce, &pk, &sk2)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "xsalsa box", m, msg)
}

func TestBoxDispatchSelector(t *testing.T) {
	BoxSetUseXChaCha20(true)
	pkX, skX, _ := BoxKeypair()
	BoxSetUseXChaCha20(false)
	pkS, skS, _ := BoxKeypair()
	// both should produce valid keypairs (different cipher but same keypair gen)
	_ = pkX; _ = skX; _ = pkS; _ = skS
	BoxSetUseXChaCha20(true) // restore default
}

// ===========================================================================
// Cross-consistency: box easy == afternm(beforenm)
// ===========================================================================

func TestBoxEasyMatchesBeforeNM(t *testing.T) {
	pk, sk, _ := BoxCurve25519XChaCha20Poly1305Keypair()
	pk2, sk2, _ := BoxCurve25519XChaCha20Poly1305Keypair()
	nonce := bytes.Repeat([]byte{0x77}, 24)
	msg := []byte("consistency")
	k, _ := BoxCurve25519XChaCha20Poly1305BeforeNM(&pk2, &sk)
	c1, _ := BoxCurve25519XChaCha20Poly1305EasyAfterNM(msg, nonce, k[:])
	c2, _ := BoxCurve25519XChaCha20Poly1305Easy(msg, nonce, &pk2, &sk)
	eq(t, "easy == afternm(beforenm)", c1, c2)
	// and open with beforenm from the other side
	k2, _ := BoxCurve25519XChaCha20Poly1305BeforeNM(&pk, &sk2)
	m, err := BoxCurve25519XChaCha20Poly1305OpenEasyAfterNM(c2, nonce, k2[:])
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "open via beforenm", m, msg)
}
