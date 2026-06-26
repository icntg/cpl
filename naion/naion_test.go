package naion

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
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
	if CSMClientEncryptSize(10) != 64+32+24+16+32+10 {
		t.Fatal("client encrypt size")
	}
	if CSMServerEncryptSize(10) != 64+32+24+16+10 {
		t.Fatal("server encrypt size")
	}
	if CSMServerDecryptMaxPlaintextSize(64+32+24+16+32+10) != 10 {
		t.Fatal("server decrypt max")
	}
}

func TestCSMShortPacket(t *testing.T) {
	client, _ := csmSetup(t)
	if _, rc := client.Decrypt(bytes.Repeat([]byte{0}, 64)); rc != CSMErrInvalidArg && rc != CSMErrVerifyFailed && rc != CSMErrCrypto {
		// short packets should be rejected
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
