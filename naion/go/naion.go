// Package naion is a single-file, byte-compatible Go reimplementation of the
// C reference in naion.h. It provides BLAKE2b, XChaCha20 stream/AEAD,
// secretbox, X25519/Box, Ed25519, KX and the CSM/CSM-CA secure messaging
// layers, plus an optional XSalsa20 family.
//
// The symmetric box/secretbox engine uses the classic NaCl construction
// (poly1305 keyed by the first 32 bytes of a ChaCha20 keystream block, MAC
// prepended to the ciphertext), while the CSM packets and the explicit
// aead_*_ietf_* family use the IETF XChaCha20-Poly1305 construction
// (padded lengths Poly1305 input). Both are reproduced exactly so that Go
// output is byte-for-byte interchangeable with the C and Python versions.
package naion

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"hash"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/curve25519"
)

const VersionString = "naion/0.2 (Go)"

// ===========================================================================
// Constants
// ===========================================================================

const (
	GenericHashBytes         = 32
	GenericHashBytesMin      = 16
	GenericHashBytesMax      = 64
	GenericHashKeyBytes      = 32
	GenericHashKeyBytesMin   = 16
	GenericHashKeyBytesMax   = 64
	GenericHashSaltBytes     = 16
	GenericHashPersonalBytes = 16
)

const (
	StreamXChaCha20KeyBytes   = 32
	StreamXChaCha20NonceBytes = 24
)

const (
	AEADXChaCha20Poly1305IETFKeyBytes  = 32
	AEADXChaCha20Poly1305IETFNSecBytes = 0
	AEADXChaCha20Poly1305IETFNPubBytes = 24
	AEADXChaCha20Poly1305IETFABytes    = 16
)

const (
	SecretboxXChaCha20Poly1305KeyBytes   = 32
	SecretboxXChaCha20Poly1305NonceBytes = 24
	SecretboxXChaCha20Poly1305MacBytes   = 16
)

const (
	BoxCurve25519XChaCha20Poly1305SeedBytes      = 32
	BoxCurve25519XChaCha20Poly1305PublicKeyBytes  = 32
	BoxCurve25519XChaCha20Poly1305SecretKeyBytes  = 32
	BoxCurve25519XChaCha20Poly1305BeforeNMBytes   = 32
	BoxCurve25519XChaCha20Poly1305NonceBytes      = 24
	BoxCurve25519XChaCha20Poly1305MacBytes        = 16
	BoxCurve25519XChaCha20Poly1305SealBytes       = 48
)

const (
	ScalarMultCurve25519Bytes       = 32
	ScalarMultCurve25519ScalarBytes = 32
)

const (
	KXPublicKeyBytes  = 32
	KXSecretKeyBytes  = 32
	KXSeedBytes       = 32
	KXSessionKeyBytes = 32
)

const (
	SignEd25519Bytes          = 64
	SignEd25519SeedBytes      = 32
	SignEd25519PublicKeyBytes = 32
	SignEd25519SecretKeyBytes = 64
)

const (
	BoxSeedBytesMax      = 32
	BoxPublicKeyBytesMax = 32
	BoxSecretKeyBytesMax = 32
	BoxBeforeNMBytesMax  = 32
	BoxNonceBytesMax     = 24
	BoxMacBytesMax       = 16
	BoxSealBytesMax      = 48
)

const (
	CSMPacketOverhead        = 136
	CSMClientPKBytes         = 32
	CSMMaxUDPDatagramBytes   = 1024
	CSMMaxClientPayloadBytes = 856
	CSMMaxServerPayloadBytes = 888
)

const CSMCACertBytes = 96

// ===========================================================================
// CSM error type
// ===========================================================================

type CSMError int

const (
	CSMOK                CSMError = 0
	CSMErrInvalidArg     CSMError = -1
	CSMErrBufferTooSmall CSMError = -2
	CSMErrCrypto         CSMError = -3
	CSMErrVerifyFailed   CSMError = -4
	CSMErrState          CSMError = -5
	CSMErrRandomProvider CSMError = -6
	CSMErrNoData         CSMError = -7
)

func (e CSMError) Error() string {
	switch e {
	case CSMOK:
		return "naion: ok"
	case CSMErrInvalidArg:
		return "naion: invalid argument"
	case CSMErrBufferTooSmall:
		return "naion: buffer too small"
	case CSMErrCrypto:
		return "naion: crypto failure"
	case CSMErrVerifyFailed:
		return "naion: verification failed"
	case CSMErrState:
		return "naion: invalid state"
	case CSMErrRandomProvider:
		return "naion: random provider failure"
	case CSMErrNoData:
		return "naion: no data"
	default:
		return fmt.Sprintf("naion: error %d", int(e))
	}
}

// ===========================================================================
// Infrastructure
// ===========================================================================

// RandomProvider fills buf with cryptographically secure random bytes.
type RandomProvider func(buf []byte) error

var defaultRandomProvider RandomProvider = func(buf []byte) error {
	_, err := rand.Read(buf)
	return err
}

var gRandomProvider = defaultRandomProvider

// SetRandomProvider overrides the global randomness source.
func SetRandomProvider(fn RandomProvider) { gRandomProvider = fn }

// GetRandomProvider returns the current randomness source.
func GetRandomProvider() RandomProvider { return gRandomProvider }

// Init is a libsodium-style core init. Currently a no-op that always succeeds.
func Init() error { return nil }

// MemZero overwrites p with zeros.
func MemZero(p []byte) {
	for i := range p {
		p[i] = 0
	}
}

// MemCmp is a constant-time comparison; returns 0 if equal.
func MemCmp(a, b []byte) int {
	return subtle.ConstantTimeCompare(a, b) - 1
}

// IsZero reports whether all bytes of p are zero (constant-time-ish).
func IsZero(p []byte) bool {
	var v byte
	for _, b := range p {
		v |= b
	}
	return v == 0
}

// Verify32 returns 1 if x == y (constant time), else 0.
func Verify32(x, y *[32]byte) int {
	return subtle.ConstantTimeCompare(x[:], y[:])
}

func fillRandom(buf []byte) error {
	if gRandomProvider == nil {
		return errors.New("naion: no random provider")
	}
	return gRandomProvider(buf)
}

// ===========================================================================
// Little-endian helpers
// ===========================================================================

func load32LE(b []byte) uint32 {
	return binary.LittleEndian.Uint32(b)
}

func store32LE(b []byte, v uint32) {
	binary.LittleEndian.PutUint32(b, v)
}

func store64LE(b []byte, v uint64) {
	binary.LittleEndian.PutUint64(b, v)
}

func rotl32(x uint32, n uint) uint32 { return (x << n) | (x >> (32 - n)) }

// ===========================================================================
// Salsa20 / HSalsa20 (for XSalsa20 box/secretbox)
// ===========================================================================

func salsa20QR(a, b, c, d *uint32) {
	*b ^= rotl32(*a+*d, 7)
	*c ^= rotl32(*b+*a, 9)
	*d ^= rotl32(*c+*b, 13)
	*a ^= rotl32(*d+*c, 18)
}

func salsa20Block(out, key, nonce8 []byte, ctrLow, ctrHigh uint32) {
	var st, x [16]uint32
	st[0] = 0x61707865
	st[1] = load32LE(key[0:])
	st[2] = load32LE(key[4:])
	st[3] = load32LE(key[8:])
	st[4] = load32LE(key[12:])
	st[5] = 0x3320646e
	st[6] = load32LE(nonce8[0:])
	st[7] = load32LE(nonce8[4:])
	st[8] = ctrLow
	st[9] = ctrHigh
	st[10] = 0x79622d32
	st[11] = load32LE(key[16:])
	st[12] = load32LE(key[20:])
	st[13] = load32LE(key[24:])
	st[14] = load32LE(key[28:])
	st[15] = 0x6b206574
	x = st
	for i := 0; i < 10; i++ {
		salsa20QR(&x[0], &x[4], &x[8], &x[12])
		salsa20QR(&x[5], &x[9], &x[13], &x[1])
		salsa20QR(&x[10], &x[14], &x[2], &x[6])
		salsa20QR(&x[15], &x[3], &x[7], &x[11])

		salsa20QR(&x[0], &x[1], &x[2], &x[3])
		salsa20QR(&x[5], &x[6], &x[7], &x[4])
		salsa20QR(&x[10], &x[11], &x[8], &x[9])
		salsa20QR(&x[15], &x[12], &x[13], &x[14])
	}
	for i := 0; i < 16; i++ {
		store32LE(out[4*i:], x[i]+st[i])
	}
}

// hsalsa20 derives a 32-byte subkey: the classic NaCl "HSalsa20" used by
// XSalsa20 box beforenm. nonce is 16 bytes.
func hsalsa20(out, nonce, key []byte) {
	var x [16]uint32
	x[0] = 0x61707865
	x[1] = load32LE(key[0:])
	x[2] = load32LE(key[4:])
	x[3] = load32LE(key[8:])
	x[4] = load32LE(key[12:])
	x[5] = 0x3320646e
	x[6] = load32LE(nonce[0:])
	x[7] = load32LE(nonce[4:])
	x[8] = load32LE(nonce[8:])
	x[9] = load32LE(nonce[12:])
	x[10] = 0x79622d32
	x[11] = load32LE(key[16:])
	x[12] = load32LE(key[20:])
	x[13] = load32LE(key[24:])
	x[14] = load32LE(key[28:])
	x[15] = 0x6b206574
	for i := 0; i < 10; i++ {
		salsa20QR(&x[0], &x[4], &x[8], &x[12])
		salsa20QR(&x[5], &x[9], &x[13], &x[1])
		salsa20QR(&x[10], &x[14], &x[2], &x[6])
		salsa20QR(&x[15], &x[3], &x[7], &x[11])

		salsa20QR(&x[0], &x[1], &x[2], &x[3])
		salsa20QR(&x[5], &x[6], &x[7], &x[4])
		salsa20QR(&x[10], &x[11], &x[8], &x[9])
		salsa20QR(&x[15], &x[12], &x[13], &x[14])
	}
	store32LE(out[0:], x[0])
	store32LE(out[4:], x[5])
	store32LE(out[8:], x[10])
	store32LE(out[12:], x[15])
	store32LE(out[16:], x[6])
	store32LE(out[20:], x[7])
	store32LE(out[24:], x[8])
	store32LE(out[28:], x[9])
}

func xsalsa20XORIC(c, m []byte, n24 []byte, ic uint64, key []byte) {
	var subKey [32]byte
	var nonce8 [8]byte
	var block [64]byte
	hsalsa20(subKey[:], n24[:16], key)
	copy(nonce8[:], n24[16:24])
	ctrLow := uint32(ic & 0xffffffff)
	ctrHigh := uint32(ic >> 32)
	off := 0
	mlen := len(c)
	var mptr []byte
	if m != nil {
		mlen = len(m)
	}
	for remaining := mlen; remaining > 0; {
		salsa20Block(block[:], subKey[:], nonce8[:], ctrLow, ctrHigh)
		ctrLow++
		if ctrLow == 0 {
			ctrHigh++
		}
		take := remaining
		if take > 64 {
			take = 64
		}
		if m == nil {
			for i := 0; i < take; i++ {
				c[off+i] = block[i]
			}
		} else {
			mptr = m
			for i := 0; i < take; i++ {
				c[off+i] = mptr[off+i] ^ block[i]
			}
		}
		off += take
		remaining -= take
	}
}

// ===========================================================================
// HChaCha20 + ChaCha20 (for XChaCha20 stream / box / IETF AEAD)
// ===========================================================================

func chacha20QR(a, b, c, d *uint32) {
	*a += *b
	*d ^= *a
	*d = rotl32(*d, 16)
	*c += *d
	*b ^= *c
	*b = rotl32(*b, 12)
	*a += *b
	*d ^= *a
	*d = rotl32(*d, 8)
	*c += *d
	*b ^= *c
	*b = rotl32(*b, 7)
}

// hChaCha20(key[32], nonce[16]) → out[32]. Matches the HChaCha20 primitive.
func hChaCha20(key, nonce []byte) [32]byte {
	var x [16]uint32
	x[0] = 0x61707865
	x[1] = 0x3320646e
	x[2] = 0x79622d32
	x[3] = 0x6b206574
	for i := 0; i < 8; i++ {
		x[4+i] = load32LE(key[4*i:])
	}
	x[12] = load32LE(nonce[0:])
	x[13] = load32LE(nonce[4:])
	x[14] = load32LE(nonce[8:])
	x[15] = load32LE(nonce[12:])
	for i := 0; i < 10; i++ {
		chacha20QR(&x[0], &x[4], &x[8], &x[12])
		chacha20QR(&x[1], &x[5], &x[9], &x[13])
		chacha20QR(&x[2], &x[6], &x[10], &x[14])
		chacha20QR(&x[3], &x[7], &x[11], &x[15])
		chacha20QR(&x[0], &x[5], &x[10], &x[15])
		chacha20QR(&x[1], &x[6], &x[11], &x[12])
		chacha20QR(&x[2], &x[7], &x[8], &x[13])
		chacha20QR(&x[3], &x[4], &x[9], &x[14])
	}
	var out [32]byte
	store32LE(out[0:], x[0])
	store32LE(out[4:], x[1])
	store32LE(out[8:], x[2])
	store32LE(out[12:], x[3])
	store32LE(out[16:], x[12])
	store32LE(out[20:], x[13])
	store32LE(out[24:], x[14])
	store32LE(out[28:], x[15])
	return out
}

// chacha20Block writes one 64-byte ChaCha20 block (IETF: 32-bit counter + 32-bit
// counter-position, 12-byte nonce). Used for both IETF AEAD and the box stream.
func chacha20BlockIETF(out, key, nonce12 []byte, counter uint32) {
	var st, x [16]uint32
	st[0] = 0x61707865
	st[1] = 0x3320646e
	st[2] = 0x79622d32
	st[3] = 0x6b206574
	for i := 0; i < 8; i++ {
		st[4+i] = load32LE(key[4*i:])
	}
	st[12] = counter
	st[13] = load32LE(nonce12[0:])
	st[14] = load32LE(nonce12[4:])
	st[15] = load32LE(nonce12[8:])
	x = st
	for i := 0; i < 10; i++ {
		chacha20QR(&x[0], &x[4], &x[8], &x[12])
		chacha20QR(&x[1], &x[5], &x[9], &x[13])
		chacha20QR(&x[2], &x[6], &x[10], &x[14])
		chacha20QR(&x[3], &x[7], &x[11], &x[15])
		chacha20QR(&x[0], &x[5], &x[10], &x[15])
		chacha20QR(&x[1], &x[6], &x[11], &x[12])
		chacha20QR(&x[2], &x[7], &x[8], &x[13])
		chacha20QR(&x[3], &x[4], &x[9], &x[14])
	}
	for i := 0; i < 16; i++ {
		store32LE(out[4*i:], x[i]+st[i])
	}
}

// chacha20IETFXORIC XORs m with the IETF ChaCha20 keystream starting at block
// counter ic. m may be nil to produce a pure keystream.
func chacha20IETFXORIC(c, m, nonce12, key []byte, ic uint32) {
	var block [64]byte
	ctr := ic
	off := 0
	mlen := len(c)
	if m != nil {
		mlen = len(m)
	}
	for remaining := mlen; remaining > 0; {
		chacha20BlockIETF(block[:], key, nonce12, ctr)
		ctr++
		take := remaining
		if take > 64 {
			take = 64
		}
		if m == nil {
			for i := 0; i < take; i++ {
				c[off+i] = block[i]
			}
		} else {
			for i := 0; i < take; i++ {
				c[off+i] = m[off+i] ^ block[i]
			}
		}
		off += take
		remaining -= take
	}
}

// xchacha20DeriveSubKeyNonce splits a 24-byte X nonce into a HChaCha20 subkey
// and an IETF 12-byte nonce (4 zero bytes + nonce[16:24]).
func xchacha20DeriveSubKeyNonce(subKey, nonce12 []byte, npub, k []byte) {
	sk := hChaCha20(k, npub[:16])
	copy(subKey, sk[:])
	nonce12[0] = 0
	nonce12[1] = 0
	nonce12[2] = 0
	nonce12[3] = 0
	copy(nonce12[4:12], npub[16:24])
}

// xchacha20XORIC is the XChaCha20 stream with a 64-bit block counter (used by
// the classic box/secretbox engine). m may be nil to produce a pure keystream.
func xchacha20XORIC(c, m, n24 []byte, ic uint64, k []byte) {
	subKey := hChaCha20(k, n24[:16])
	var nonce8 [8]byte
	copy(nonce8[:], n24[16:24])
	ctrLow := uint32(ic & 0xffffffff)
	ctrHigh := uint32(ic >> 32)
	var st, x [16]uint32
	st[0] = 0x61707865
	st[1] = 0x3320646e
	st[2] = 0x79622d32
	st[3] = 0x6b206574
	for i := 0; i < 8; i++ {
		st[4+i] = load32LE(subKey[4*i:])
	}
	st[14] = load32LE(nonce8[0:])
	st[15] = load32LE(nonce8[4:])
	var block [64]byte
	off := 0
	mlen := len(c)
	if m != nil {
		mlen = len(m)
	}
	for remaining := mlen; remaining > 0; {
		st[12] = ctrLow
		st[13] = ctrHigh
		x = st
		for i := 0; i < 10; i++ {
			chacha20QR(&x[0], &x[4], &x[8], &x[12])
			chacha20QR(&x[1], &x[5], &x[9], &x[13])
			chacha20QR(&x[2], &x[6], &x[10], &x[14])
			chacha20QR(&x[3], &x[7], &x[11], &x[15])
			chacha20QR(&x[0], &x[5], &x[10], &x[15])
			chacha20QR(&x[1], &x[6], &x[11], &x[12])
			chacha20QR(&x[2], &x[7], &x[8], &x[13])
			chacha20QR(&x[3], &x[4], &x[9], &x[14])
		}
		for i := 0; i < 16; i++ {
			store32LE(block[4*i:], x[i]+st[i])
		}
		ctrLow++
		if ctrLow == 0 {
			ctrHigh++
		}
		take := remaining
		if take > 64 {
			take = 64
		}
		if m == nil {
			for i := 0; i < take; i++ {
				c[off+i] = block[i]
			}
		} else {
			for i := 0; i < take; i++ {
				c[off+i] = m[off+i] ^ block[i]
			}
		}
		off += take
		remaining -= take
	}
}

// ===========================================================================
// Poly1305 (32-bit limbs, matching the C reference)
// ===========================================================================

type poly1305State struct {
	r0, r1, r2, r3, r4 uint32
	s1, s2, s3, s4     uint32
	h0, h1, h2, h3, h4 uint32
	pad0, pad1, pad2, pad3 uint32
	leftover           int
	buf                [16]byte
	final              bool
}

func poly1305Blocks(st *poly1305State, m []byte) {
	hibit := uint32(0)
	if !st.final {
		hibit = 1 << 24
	}
	r0, r1, r2, r3, r4 := st.r0, st.r1, st.r2, st.r3, st.r4
	s1, s2, s3, s4 := st.s1, st.s2, st.s3, st.s4
	h0, h1, h2, h3, h4 := st.h0, st.h1, st.h2, st.h3, st.h4
	for len(m) >= 16 {
		t0 := load32LE(m[0:])
		t1 := load32LE(m[4:])
		t2 := load32LE(m[8:])
		t3 := load32LE(m[12:])

		h0 += t0 & 0x3ffffff
		h1 += ((t0 >> 26) | (t1 << 6)) & 0x3ffffff
		h2 += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff
		h3 += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff
		h4 += (t3 >> 8) | hibit

		d0 := uint64(h0)*uint64(r0) + uint64(h1)*uint64(s4) + uint64(h2)*uint64(s3) + uint64(h3)*uint64(s2) + uint64(h4)*uint64(s1)
		d1 := uint64(h0)*uint64(r1) + uint64(h1)*uint64(r0) + uint64(h2)*uint64(s4) + uint64(h3)*uint64(s3) + uint64(h4)*uint64(s2)
		d2 := uint64(h0)*uint64(r2) + uint64(h1)*uint64(r1) + uint64(h2)*uint64(r0) + uint64(h3)*uint64(s4) + uint64(h4)*uint64(s3)
		d3 := uint64(h0)*uint64(r3) + uint64(h1)*uint64(r2) + uint64(h2)*uint64(r1) + uint64(h3)*uint64(r0) + uint64(h4)*uint64(s4)
		d4 := uint64(h0)*uint64(r4) + uint64(h1)*uint64(r3) + uint64(h2)*uint64(r2) + uint64(h3)*uint64(r1) + uint64(h4)*uint64(r0)

		c := uint32(d0 >> 26); h0 = uint32(d0) & 0x3ffffff; d1 += uint64(c)
		c = uint32(d1 >> 26); h1 = uint32(d1) & 0x3ffffff; d2 += uint64(c)
		c = uint32(d2 >> 26); h2 = uint32(d2) & 0x3ffffff; d3 += uint64(c)
		c = uint32(d3 >> 26); h3 = uint32(d3) & 0x3ffffff; d4 += uint64(c)
		c = uint32(d4 >> 26); h4 = uint32(d4) & 0x3ffffff
		h0 += c * 5
		c = h0 >> 26; h0 &= 0x3ffffff
		h1 += c

		m = m[16:]
	}
	st.r0, st.r1, st.r2, st.r3, st.r4 = r0, r1, r2, r3, r4
	st.h0, st.h1, st.h2, st.h3, st.h4 = h0, h1, h2, h3, h4
}

func poly1305Init(st *poly1305State, key []byte) {
	t0 := load32LE(key[0:])
	t1 := load32LE(key[4:])
	t2 := load32LE(key[8:])
	t3 := load32LE(key[12:])
	st.r0 = t0 & 0x3ffffff
	st.r1 = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03
	st.r2 = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff
	st.r3 = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff
	st.r4 = (t3 >> 8) & 0x00fffff
	st.s1 = st.r1 * 5
	st.s2 = st.r2 * 5
	st.s3 = st.r3 * 5
	st.s4 = st.r4 * 5
	st.h0, st.h1, st.h2, st.h3, st.h4 = 0, 0, 0, 0, 0
	st.pad0 = load32LE(key[16:])
	st.pad1 = load32LE(key[20:])
	st.pad2 = load32LE(key[24:])
	st.pad3 = load32LE(key[28:])
	st.leftover = 0
	st.final = false
}

func poly1305Update(st *poly1305State, m []byte) {
	if st.leftover != 0 {
		want := 16 - st.leftover
		if want > len(m) {
			want = len(m)
		}
		copy(st.buf[st.leftover:], m[:want])
		m = m[want:]
		st.leftover += want
		if st.leftover < 16 {
			return
		}
		poly1305Blocks(st, st.buf[:16])
		st.leftover = 0
	}
	if len(m) >= 16 {
		want := len(m) &^ 0xf
		poly1305Blocks(st, m[:want])
		m = m[want:]
	}
	if len(m) != 0 {
		copy(st.buf[st.leftover:], m)
		st.leftover += len(m)
	}
}

func poly1305Finish(st *poly1305State, mac []byte) {
	if st.leftover != 0 {
		st.buf[st.leftover] = 1
		for i := st.leftover + 1; i < 16; i++ {
			st.buf[i] = 0
		}
		st.final = true
		poly1305Blocks(st, st.buf[:16])
	}
	h0, h1, h2, h3, h4 := st.h0, st.h1, st.h2, st.h3, st.h4
	c := h1 >> 26; h1 &= 0x3ffffff; h2 += c
	c = h2 >> 26; h2 &= 0x3ffffff; h3 += c
	c = h3 >> 26; h3 &= 0x3ffffff; h4 += c
	c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5
	c = h0 >> 26; h0 &= 0x3ffffff; h1 += c

	g0 := h0 + 5
	c = g0 >> 26; g0 &= 0x3ffffff
	g1 := h1 + c; c = g1 >> 26; g1 &= 0x3ffffff
	g2 := h2 + c; c = g2 >> 26; g2 &= 0x3ffffff
	g3 := h3 + c; c = g3 >> 26; g3 &= 0x3ffffff
	g4 := h4 + c - (1 << 26)

	mask := (g4 >> 31) - 1
	g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask
	mask = ^mask
	h0 = (h0 & mask) | g0
	h1 = (h1 & mask) | g1
	h2 = (h2 & mask) | g2
	h3 = (h3 & mask) | g3
	h4 = (h4 & mask) | g4

	h0 = h0 | (h1 << 26)
	h1 = (h1 >> 6) | (h2 << 20)
	h2 = (h2 >> 12) | (h3 << 14)
	h3 = (h3 >> 18) | (h4 << 8)

	f := uint64(h0) + uint64(st.pad0)
	h0 = uint32(f)
	f = uint64(h1) + uint64(st.pad1) + (f >> 32)
	h1 = uint32(f)
	f = uint64(h2) + uint64(st.pad2) + (f >> 32)
	h2 = uint32(f)
	f = uint64(h3) + uint64(st.pad3) + (f >> 32)
	h3 = uint32(f)

	store32LE(mac[0:], h0)
	store32LE(mac[4:], h1)
	store32LE(mac[8:], h2)
	store32LE(mac[12:], h3)
}

// poly1305UpdatePadded appends m followed by zero padding to a 16-byte
// boundary (IETF AEAD construction).
func poly1305UpdatePadded(st *poly1305State, m []byte) {
	poly1305Update(st, m)
	if rem := len(m) & 15; rem != 0 {
		var zero [16]byte
		poly1305Update(st, zero[:16-rem])
	}
}

// verify16 is a constant-time 16-byte comparison; returns 1 if equal.
func verify16(x, y []byte) int {
	var d uint32
	for i := 0; i < 16; i++ {
		d |= uint32(x[i] ^ y[i])
	}
	d = (d | (0 - d)) >> 31
	return int(1 ^ d)
}

// ===========================================================================
// Layer 1: BLAKE2b (generichash)
// ===========================================================================

// GenericHashState is a streaming BLAKE2b hasher.
type GenericHashState struct {
	h      hash.Hash
	outLen int
}

// GenericHash computes a one-shot BLAKE2b digest of in, optionally keyed.
func GenericHash(outLen int, in, key []byte) ([]byte, error) {
	if outLen < GenericHashBytesMin || outLen > GenericHashBytesMax {
		return nil, errors.New("naion: invalid generichash output length")
	}
	h, err := blake2b.New(outLen, key)
	if err != nil {
		return nil, err
	}
	h.Write(in)
	return h.Sum(nil), nil
}

// Init initializes the streaming BLAKE2b state.
func (st *GenericHashState) Init(key []byte, outLen int) error {
	if outLen < GenericHashBytesMin || outLen > GenericHashBytesMax {
		return errors.New("naion: invalid generichash output length")
	}
	h, err := blake2b.New(outLen, key)
	if err != nil {
		return err
	}
	st.h = h
	st.outLen = outLen
	return nil
}

// Write feeds data into the hasher.
func (st *GenericHashState) Write(p []byte) error {
	if st.h == nil {
		return errors.New("naion: generichash state not initialized")
	}
	_, err := st.h.Write(p)
	return err
}

// Sum finalizes and returns the digest.
func (st *GenericHashState) Sum(outLen int) ([]byte, error) {
	if st.h == nil {
		return nil, errors.New("naion: generichash state not initialized")
	}
	return st.h.Sum(nil), nil
}

// ===========================================================================
// Layer 1: XChaCha20 stream
// ===========================================================================

// StreamXChaCha20 generates outLen bytes of XChaCha20 keystream.
func StreamXChaCha20(outLen int, nonce *[24]byte, key *[32]byte) ([]byte, error) {
	out := make([]byte, outLen)
	xchacha20XORIC(out, nil, nonce[:], 0, key[:])
	return out, nil
}

// StreamXChaCha20XOR XORs m with the keystream starting at counter 0.
func StreamXChaCha20XOR(m []byte, nonce *[24]byte, key *[32]byte) ([]byte, error) {
	out := make([]byte, len(m))
	if len(m) > 0 {
		xchacha20XORIC(out, m, nonce[:], 0, key[:])
	}
	return out, nil
}

// StreamXChaCha20XORIC XORs m with the keystream starting at block counter ic.
func StreamXChaCha20XORIC(m []byte, nonce *[24]byte, ic uint64, key *[32]byte) ([]byte, error) {
	out := make([]byte, len(m))
	if len(m) > 0 {
		xchacha20XORIC(out, m, nonce[:], ic, key[:])
	}
	return out, nil
}

// ===========================================================================
// Layer 2: IETF XChaCha20-Poly1305 AEAD
// (ciphertext || mac for the combined variants)
// ===========================================================================

// aeadIETFXChaCha20Poly1305EncryptDetached returns (ciphertext, mac).
func aeadIETFXChaCha20Poly1305EncryptDetached(m, ad, npub, key []byte) ([]byte, [16]byte, error) {
	var subKey [32]byte
	var nonce12 [12]byte
	var block0 [64]byte
	var lens [16]byte
	xchacha20DeriveSubKeyNonce(subKey[:], nonce12[:], npub, key)
	chacha20BlockIETF(block0[:], subKey[:], nonce12[:], 0)

	var st poly1305State
	poly1305Init(&st, block0[:])

	c := make([]byte, len(m))
	chacha20IETFXORIC(c, m, nonce12[:], subKey[:], 1)

	poly1305UpdatePadded(&st, ad)
	poly1305UpdatePadded(&st, c)
	store64LE(lens[0:], uint64(len(ad)))
	store64LE(lens[8:], uint64(len(m)))
	poly1305Update(&st, lens[:])
	var mac [16]byte
	poly1305Finish(&st, mac[:])
	MemZero(block0[:])
	MemZero(subKey[:])
	return c, mac, nil
}

func aeadIETFXChaCha20Poly1305DecryptDetached(c, mac, ad, npub, key []byte) ([]byte, error) {
	var subKey [32]byte
	var nonce12 [12]byte
	var block0 [64]byte
	var lens [16]byte
	xchacha20DeriveSubKeyNonce(subKey[:], nonce12[:], npub, key)
	chacha20BlockIETF(block0[:], subKey[:], nonce12[:], 0)

	var st poly1305State
	poly1305Init(&st, block0[:])
	poly1305UpdatePadded(&st, ad)
	poly1305UpdatePadded(&st, c)
	store64LE(lens[0:], uint64(len(ad)))
	store64LE(lens[8:], uint64(len(c)))
	poly1305Update(&st, lens[:])
	var computed [16]byte
	poly1305Finish(&st, computed[:])
	MemZero(block0[:])
	if verify16(mac, computed[:]) != 1 {
		MemZero(subKey[:])
		return nil, errors.New("naion: AEAD verification failed")
	}
	m := make([]byte, len(c))
	chacha20IETFXORIC(m, c, nonce12[:], subKey[:], 1)
	MemZero(subKey[:])
	return m, nil
}

// AEADXChaCha20Poly1305IETFEncrypt returns ciphertext || mac.
func AEADXChaCha20Poly1305IETFEncrypt(m, ad, npub, key []byte) ([]byte, error) {
	c, mac, err := aeadIETFXChaCha20Poly1305EncryptDetached(m, ad, npub, key)
	if err != nil {
		return nil, err
	}
	return append(c, mac[:]...), nil
}

// AEADXChaCha20Poly1305IETFDecrypt expects ciphertext || mac.
func AEADXChaCha20Poly1305IETFDecrypt(c, ad, npub, key []byte) ([]byte, error) {
	if len(c) < AEADXChaCha20Poly1305IETFABytes {
		return nil, errors.New("naion: ciphertext too short")
	}
	n := len(c) - AEADXChaCha20Poly1305IETFABytes
	var mac [16]byte
	copy(mac[:], c[n:])
	return aeadIETFXChaCha20Poly1305DecryptDetached(c[:n], mac[:], ad, npub, key)
}

// AEADXChaCha20Poly1305IETFEncryptDetached returns (ciphertext, mac).
func AEADXChaCha20Poly1305IETFEncryptDetached(m, ad, npub, key []byte) ([]byte, [16]byte, error) {
	return aeadIETFXChaCha20Poly1305EncryptDetached(m, ad, npub, key)
}

// AEADXChaCha20Poly1305IETFDecryptDetached decrypts a detached (c, mac).
func AEADXChaCha20Poly1305IETFDecryptDetached(c []byte, mac *[16]byte, ad, npub, key []byte) ([]byte, error) {
	return aeadIETFXChaCha20Poly1305DecryptDetached(c, mac[:], ad, npub, key)
}

// ===========================================================================
// Layer 2: classic box/secretbox symmetric engine (afternm)
// Layout: mac(16) || ciphertext
// ===========================================================================

func boxEasyAfterNM(m, nonce, k []byte) ([]byte, error) {
	out := make([]byte, 16+len(m))
	if err := boxEasyAfterNMInto(out, m, nonce, k); err != nil {
		return nil, err
	}
	return out, nil
}

func boxEasyAfterNMInto(out, m, nonce, k []byte) error {
	var block0 [64]byte
	mlen := len(m)
	firstTake := mlen
	if firstTake > 32 {
		firstTake = 32
	}
	if firstTake > 0 {
		copy(block0[32:], m[:firstTake])
	}
	xchacha20XORIC(block0[:], block0[:32+firstTake], nonce, 0, k)
	var st poly1305State
	poly1305Init(&st, block0[:])
	if firstTake > 0 {
		copy(out[16:], block0[32:32+firstTake])
	}
	rem := mlen - firstTake
	if rem > 0 {
		xchacha20XORIC(out[16+firstTake:], m[firstTake:], nonce, 1, k)
	}
	poly1305Update(&st, out[16:16+mlen])
	poly1305Finish(&st, out[:16])
	MemZero(block0[:])
	return nil
}

func boxOpenEasyAfterNM(c, nonce, k []byte) ([]byte, error) {
	if len(c) < BoxMacBytesMax {
		return nil, errors.New("naion: ciphertext too short")
	}
	mlen := len(c) - 16
	cipher := c[16:]
	out := make([]byte, mlen)
	var block0 [64]byte
	firstTake := mlen
	if firstTake > 32 {
		firstTake = 32
	}
	if firstTake > 0 {
		copy(block0[32:], cipher[:firstTake])
	}
	xchacha20XORIC(block0[:], block0[:64], nonce, 0, k)
	var st poly1305State
	poly1305Init(&st, block0[:])
	poly1305Update(&st, cipher)
	var computed [16]byte
	poly1305Finish(&st, computed[:])
	if verify16(c[:16], computed[:]) != 1 {
		MemZero(block0[:])
		return nil, errors.New("naion: box verification failed")
	}
	if firstTake > 0 {
		copy(out, block0[32:32+firstTake])
	}
	rem := mlen - firstTake
	if rem > 0 {
		xchacha20XORIC(out[firstTake:], cipher[firstTake:], nonce, 1, k)
	}
	MemZero(block0[:])
	return out, nil
}

// ===========================================================================
// Layer 2: Secretbox (delegates to box afternm)
// ===========================================================================

func SecretboxXChaCha20Poly1305Easy(m, nonce, key []byte) ([]byte, error) {
	return boxEasyAfterNM(m, nonce, key)
}

func SecretboxXChaCha20Poly1305OpenEasy(c, nonce, key []byte) ([]byte, error) {
	return boxOpenEasyAfterNM(c, nonce, key)
}

func SecretboxXChaCha20Poly1305Detached(m, nonce, key []byte) ([]byte, [16]byte, error) {
	combined, err := boxEasyAfterNM(m, nonce, key)
	if err != nil {
		return nil, [16]byte{}, err
	}
	var mac [16]byte
	copy(mac[:], combined[:16])
	ct := make([]byte, len(m))
	copy(ct, combined[16:])
	return ct, mac, nil
}

func SecretboxXChaCha20Poly1305OpenDetached(c []byte, mac *[16]byte, nonce, key []byte) ([]byte, error) {
	combined := make([]byte, 16+len(c))
	copy(combined[:16], mac[:])
	copy(combined[16:], c)
	return boxOpenEasyAfterNM(combined, nonce, key)
}

// ===========================================================================
// Layer 2: Box afternm wrappers
// ===========================================================================

func BoxCurve25519XChaCha20Poly1305EasyAfterNM(m, nonce, k []byte) ([]byte, error) {
	return boxEasyAfterNM(m, nonce, k)
}

func BoxCurve25519XChaCha20Poly1305OpenEasyAfterNM(c, nonce, k []byte) ([]byte, error) {
	return boxOpenEasyAfterNM(c, nonce, k)
}

// ===========================================================================
// Layer 3: X25519
// ===========================================================================

// x25519 small-order rejection list (RFC 7748 contributor check).
var x25519SmallOrder = [7][32]byte{
	{0},
	{0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
		0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00},
	{0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
		0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57},
	{0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	{0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	{0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
}

func x25519HasSmallOrder(p *[32]byte) bool {
	var c [7]byte
	for j := 0; j < 31; j++ {
		for i := 0; i < 7; i++ {
			c[i] |= p[j] ^ x25519SmallOrder[i][j]
		}
	}
	for i := 0; i < 7; i++ {
		c[i] |= (p[31] & 0x7f) ^ x25519SmallOrder[i][31]
	}
	var k uint
	for i := 0; i < 7; i++ {
		k |= uint(c[i] - 1)
	}
	return (k>>8)&1 == 1
}

// ScalarMultCurve25519 computes n*P on Curve25519.
func ScalarMultCurve25519(n, p *[32]byte) (*[32]byte, error) {
	if x25519HasSmallOrder(p) {
		return nil, errors.New("naion: small-order point rejected")
	}
	out, err := curve25519.X25519(n[:], p[:])
	if err != nil {
		return nil, err
	}
	var r [32]byte
	copy(r[:], out)
	return &r, nil
}

// ScalarMultCurve25519Base computes n*basepoint.
func ScalarMultCurve25519Base(n *[32]byte) (*[32]byte, error) {
	out, err := curve25519.X25519(n[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	var r [32]byte
	copy(r[:], out)
	return &r, nil
}

// ===========================================================================
// Layer 3: KX
// ===========================================================================

func KXKeypair() (pk, sk [32]byte, err error) {
	if _, err := rand.Read(sk[:]); err != nil {
		return pk, sk, err
	}
	out, err := ScalarMultCurve25519Base(&sk)
	if err != nil {
		return pk, sk, err
	}
	pk = *out
	return pk, sk, nil
}

func KXSeedKeypair(seed *[32]byte) (pk, sk [32]byte, err error) {
	skBytes, err := GenericHash(KXSecretKeyBytes, seed[:], nil)
	if err != nil {
		return pk, sk, err
	}
	copy(sk[:], skBytes)
	out, err := ScalarMultCurve25519Base(&sk)
	if err != nil {
		return pk, sk, err
	}
	pk = *out
	return pk, sk, nil
}

// kxDerive computes the 64-byte BLAKE2b digest over q || client_pk || server_pk
// (note: digest order is always client-then-server regardless of caller) and
// returns the two 32-byte halves.
func kxDerive(q, clientPK, serverPK *[32]byte) (first, second [32]byte, err error) {
	h, err := blake2b.New(64, nil)
	if err != nil {
		return first, second, err
	}
	h.Write(q[:])
	h.Write(clientPK[:])
	h.Write(serverPK[:])
	var keys [64]byte
	copy(keys[:], h.Sum(nil))
	copy(first[:], keys[:32])
	copy(second[:], keys[32:])
	return first, second, nil
}

// KXClientSessionKeys derives (rx, tx) for the client.
func KXClientSessionKeys(clientPK, clientSK, serverPK *[32]byte) (rx, tx [32]byte, err error) {
	q, err := ScalarMultCurve25519(clientSK, serverPK)
	if err != nil {
		return rx, tx, err
	}
	// client: rx = digest[0:32], tx = digest[32:64]
	return kxDerive(q, clientPK, serverPK)
}

// KXServerSessionKeys derives (rx, tx) for the server; rx/tx swapped vs client.
func KXServerSessionKeys(serverPK, serverSK, clientPK *[32]byte) (rx, tx [32]byte, err error) {
	q, err := ScalarMultCurve25519(serverSK, clientPK)
	if err != nil {
		return rx, tx, err
	}
	first, second, err := kxDerive(q, clientPK, serverPK)
	if err != nil {
		return rx, tx, err
	}
	// server: tx = digest[0:32], rx = digest[32:64]
	return second, first, nil
}

// ===========================================================================
// Layer 3: Box (asymmetric wrappers)
// ===========================================================================

func BoxCurve25519XChaCha20Poly1305Keypair() (pk, sk [32]byte, err error) {
	if _, err := rand.Read(sk[:]); err != nil {
		return pk, sk, err
	}
	out, err := ScalarMultCurve25519Base(&sk)
	if err != nil {
		return pk, sk, err
	}
	pk = *out
	return pk, sk, nil
}

func BoxCurve25519XChaCha20Poly1305SeedKeypair(seed *[32]byte) (pk, sk [32]byte, err error) {
	skBytes, err := GenericHash(BoxCurve25519XChaCha20Poly1305SecretKeyBytes, seed[:], nil)
	if err != nil {
		return pk, sk, err
	}
	copy(sk[:], skBytes)
	out, err := ScalarMultCurve25519Base(&sk)
	if err != nil {
		return pk, sk, err
	}
	pk = *out
	return pk, sk, nil
}

// beforeNM: k = HChaCha20(X25519(sk, pk), zero16)
func BoxCurve25519XChaCha20Poly1305BeforeNM(pk, sk *[32]byte) ([32]byte, error) {
	var k [32]byte
	s, err := ScalarMultCurve25519(sk, pk)
	if err != nil {
		return k, err
	}
	var zero16 [16]byte
	k = hChaCha20(s[:], zero16[:])
	return k, nil
}

func BoxCurve25519XChaCha20Poly1305Easy(m, nonce []byte, pk, sk *[32]byte) ([]byte, error) {
	k, err := BoxCurve25519XChaCha20Poly1305BeforeNM(pk, sk)
	if err != nil {
		return nil, err
	}
	return boxEasyAfterNM(m, nonce, k[:])
}

func BoxCurve25519XChaCha20Poly1305OpenEasy(c, nonce []byte, pk, sk *[32]byte) ([]byte, error) {
	k, err := BoxCurve25519XChaCha20Poly1305BeforeNM(pk, sk)
	if err != nil {
		return nil, err
	}
	return boxOpenEasyAfterNM(c, nonce, k[:])
}

func BoxCurve25519XChaCha20Poly1305Seal(m []byte, pk *[32]byte) ([]byte, error) {
	var esk [32]byte
	if _, err := rand.Read(esk[:]); err != nil {
		return nil, err
	}
	epk, err := ScalarMultCurve25519Base(&esk)
	if err != nil {
		return nil, err
	}
	// nonce = BLAKE2b-24(epk || pk)
	h, err := blake2b.New(24, nil)
	if err != nil {
		return nil, err
	}
	h.Write(epk[:])
	h.Write(pk[:])
	var nonce [24]byte
	copy(nonce[:], h.Sum(nil))
	out := make([]byte, 32+16+len(m))
	copy(out[:32], epk[:])
	ct, err := BoxCurve25519XChaCha20Poly1305Easy(m, nonce[:], pk, &esk)
	if err != nil {
		return nil, err
	}
	copy(out[32:], ct)
	MemZero(esk[:])
	return out, nil
}

func BoxCurve25519XChaCha20Poly1305SealOpen(c []byte, pk, sk *[32]byte) ([]byte, error) {
	if len(c) < BoxCurve25519XChaCha20Poly1305SealBytes {
		return nil, errors.New("naion: sealed box too short")
	}
	var epk [32]byte
	copy(epk[:], c[:32])
	h, err := blake2b.New(24, nil)
	if err != nil {
		return nil, err
	}
	h.Write(epk[:])
	h.Write(pk[:])
	var nonce [24]byte
	copy(nonce[:], h.Sum(nil))
	return BoxCurve25519XChaCha20Poly1305OpenEasy(c[32:], nonce[:], &epk, sk)
}

// ===========================================================================
// Layer 3: Ed25519
// ===========================================================================

func SignEd25519Keypair() (pk [32]byte, sk [64]byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return pk, sk, err
	}
	copy(pk[:], pub)
	copy(sk[:], priv)
	return pk, sk, nil
}

func SignEd25519SeedKeypair(seed *[32]byte) (pk [32]byte, sk [64]byte, err error) {
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	copy(pk[:], pub)
	copy(sk[:], priv)
	return pk, sk, nil
}

// SignEd25519 returns sig || m.
func SignEd25519(m []byte, sk *[64]byte) ([]byte, error) {
	sig := ed25519.Sign(ed25519.PrivateKey(sk[:]), m)
	return append(append([]byte{}, sig...), m...), nil
}

// SignEd25519Open verifies sig || m and returns m.
func SignEd25519Open(sm []byte, pk *[32]byte) ([]byte, error) {
	if len(sm) < 64 {
		return nil, errors.New("naion: signed message too short")
	}
	if !ed25519.Verify(ed25519.PublicKey(pk[:]), sm[64:], sm[:64]) {
		return nil, errors.New("naion: Ed25519 verification failed")
	}
	out := make([]byte, len(sm)-64)
	copy(out, sm[64:])
	return out, nil
}

func SignEd25519Detached(m []byte, sk *[64]byte) ([64]byte, error) {
	var sig [64]byte
	copy(sig[:], ed25519.Sign(ed25519.PrivateKey(sk[:]), m))
	return sig, nil
}

func SignEd25519VerifyDetached(sig *[64]byte, m []byte, pk *[32]byte) bool {
	return ed25519.Verify(ed25519.PublicKey(pk[:]), m, sig[:])
}

func SignEd25519SKToSeed(sk *[64]byte) [32]byte {
	var seed [32]byte
	copy(seed[:], sk[:32])
	return seed
}

func SignEd25519SKToPK(sk *[64]byte) [32]byte {
	var pk [32]byte
	copy(pk[:], sk[32:])
	return pk
}

// SignEd25519PKToCurve25519 converts an Ed25519 public key to a Curve25519
// public key via the libsodium map u = (1+y)/(1-y) mod p.
func SignEd25519PKToCurve25519(edPK *[32]byte) ([32]byte, error) {
	return ed25519PKToCurve25519(edPK)
}

// reverseBytes reverses b in place (little-endian <-> big-endian byte order).
func reverseBytes(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}

// ed25519PKToCurve25519 converts an Ed25519 public key to a Curve25519 public
// key via the libsodium map u = (1+y)/(1-y) mod p (RFC 7748 / libsodium
// crypto_sign_ed25519_pk_to_curve25519): recover the Edwards y-coordinate from
// the Ed25519 public-key encoding and map it to the Montgomery u-coordinate
// used by X25519.
func ed25519PKToCurve25519(edPK *[32]byte) ([32]byte, error) {
	const pHex = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"
	p, ok := new(big.Int).SetString(pHex, 16)
	if !ok {
		return [32]byte{}, errors.New("naion: invalid curve25519 prime")
	}

	var yBytes [32]byte
	copy(yBytes[:], edPK[:])
	yBytes[31] &= 0x7f
	reverseBytes(yBytes[:])
	y := new(big.Int).SetBytes(yBytes[:])
	if y.Cmp(p) >= 0 {
		return [32]byte{}, errors.New("naion: invalid Ed25519 public key")
	}

	one := big.NewInt(1)
	num := new(big.Int).Mod(new(big.Int).Add(one, y), p)
	den := new(big.Int).Mod(new(big.Int).Sub(one, y), p)
	inv := new(big.Int).ModInverse(den, p)
	if inv == nil {
		return [32]byte{}, errors.New("naion: invalid Ed25519 public key")
	}
	u := new(big.Int).Mod(new(big.Int).Mul(num, inv), p)

	var out [32]byte
	be := u.Bytes()
	copy(out[32-len(be):], be)
	reverseBytes(out[:])
	return out, nil
}

// SignEd25519SKToCurve25519: X sk = clamp(SHA512(ed_seed)[0:32]).
func SignEd25519SKToCurve25519(edSK *[64]byte) ([32]byte, error) {
	var out [32]byte
	h := sha512.Sum512(edSK[:32])
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	copy(out[:], h[:32])
	return out, nil
}

// ===========================================================================
// Layer 3: CSM
// ===========================================================================

type CSMClient struct {
	EdSeed           [32]byte
	EdSecretKey      [64]byte
	EdPublicKey      [32]byte
	ServerEdPublicKey [32]byte
}

type CSMServer struct {
	EdSeed                    [32]byte
	EdSecretKey               [64]byte
	EdPublicKey               [32]byte
	ClientEdPublicKey         [32]byte
	ClientPublicKeyInitialized bool
}

func CSMInit() CSMError { return CSMOK }

func (c *CSMClient) Wipe() {
	var zero CSMClient
	*c = zero
}

func (s *CSMServer) Wipe() {
	var zero CSMServer
	*s = zero
}

func CSMClientCreate(edSeed, serverEdPK *[32]byte) (*CSMClient, CSMError) {
	c := &CSMClient{}
	copy(c.EdSeed[:], edSeed[:])
	copy(c.ServerEdPublicKey[:], serverEdPK[:])
	pk, sk, err := SignEd25519SeedKeypair(edSeed)
	if err != nil {
		return nil, CSMErrCrypto
	}
	c.EdPublicKey = pk
	c.EdSecretKey = sk
	return c, CSMOK
}

func CSMServerCreate(edSeed *[32]byte) (*CSMServer, CSMError) {
	s := &CSMServer{}
	copy(s.EdSeed[:], edSeed[:])
	pk, sk, err := SignEd25519SeedKeypair(edSeed)
	if err != nil {
		return nil, CSMErrCrypto
	}
	s.EdPublicKey = pk
	s.EdSecretKey = sk
	return s, CSMOK
}

func CSMClientEncryptSize(plaintextLen int) int {
	return 64 + 32 + 24 + 16 + 32 + plaintextLen
}

func CSMClientDecryptMaxPlaintextSize(packetLen int) int {
	fixed := 64 + 32 + 24 + 16
	if packetLen <= fixed {
		return 0
	}
	return packetLen - fixed
}

func CSMServerEncryptSize(plaintextLen int) int {
	return 64 + 32 + 24 + 16 + plaintextLen
}

func CSMServerDecryptMaxPlaintextSize(packetLen int) int {
	fixed := 64 + 32 + 24 + 16 + 32
	if packetLen <= fixed {
		return 0
	}
	return packetLen - fixed
}

// csmInternalSeal performs the CSM AEAD seal: derives the beforenm key from the
// ephemeral X25519 key pair, generates a fresh nonce, and IETF-AEAD encrypts.
// Writes nonce || mac || ciphertext into out (aad = sessionXPub).
func csmInternalSeal(plaintext, peerXPub, selfXSk, aad, out []byte) CSMError {
	var nonce [24]byte
	if err := fillRandom(nonce[:]); err != nil {
		return CSMErrRandomProvider
	}
	var ekey [32]byte
	k, err := beforeNMRaw(peerXPub, selfXSk)
	if err != nil {
		return CSMErrCrypto
	}
	ekey = k
	copy(out[:24], nonce[:])
	ct, mac, err := aeadIETFXChaCha20Poly1305EncryptDetached(plaintext, aad, nonce[:], ekey[:])
	if err != nil {
		MemZero(ekey[:])
		return CSMErrCrypto
	}
	copy(out[24:24+16], mac[:])
	copy(out[24+16:], ct)
	MemZero(ekey[:])
	return CSMOK
}

func csmInternalOpen(nonceCipher, peerXPub, selfXSk, aad []byte) ([]byte, CSMError) {
	if len(nonceCipher) <= 24+16 {
		return nil, CSMErrInvalidArg
	}
	plaintextLen := len(nonceCipher) - 24 - 16
	nonce := nonceCipher[:24]
	mac := nonceCipher[24 : 24+16]
	ciphertext := nonceCipher[24+16:]
	k, err := beforeNMRaw(peerXPub, selfXSk)
	if err != nil {
		return nil, CSMErrCrypto
	}
	pt, err := aeadIETFXChaCha20Poly1305DecryptDetached(ciphertext, mac, aad, nonce, k[:])
	MemZero(k[:])
	if err != nil {
		return nil, CSMErrCrypto
	}
	_ = plaintextLen
	return pt, CSMOK
}

// beforeNMRaw computes HChaCha20(X25519(selfXSk, peerXPub), zero16) from slices.
func beforeNMRaw(peerXPub, selfXSk []byte) ([32]byte, error) {
	var n, p, k [32]byte
	copy(n[:], selfXSk)
	copy(p[:], peerXPub)
	s, err := ScalarMultCurve25519(&n, &p)
	if err != nil {
		return k, err
	}
	var zero16 [16]byte
	k = hChaCha20(s[:], zero16[:])
	return k, nil
}

func csmInternalSign(buffer, edSK []byte) ([64]byte, CSMError) {
	var sk [64]byte
	copy(sk[:], edSK)
	sig, err := SignEd25519Detached(buffer, &sk)
	if err != nil {
		return sig, CSMErrCrypto
	}
	return sig, CSMOK
}

func csmInternalVerify(sig, buffer, edPK []byte) CSMError {
	var s [64]byte
	var p [32]byte
	copy(s[:], sig)
	copy(p[:], edPK)
	if SignEd25519VerifyDetached(&s, buffer, &p) {
		return CSMOK
	}
	return CSMErrVerifyFailed
}

func (c *CSMClient) Encrypt(plaintext []byte) ([]byte, CSMError) {
	if len(plaintext) == 0 {
		return nil, CSMErrNoData
	}
	out := make([]byte, CSMClientEncryptSize(len(plaintext)))
	serverXPK, err := SignEd25519PKToCurve25519(&c.ServerEdPublicKey)
	if err != nil {
		return nil, CSMErrCrypto
	}
	var sessionXSK [32]byte
	if _, err := rand.Read(sessionXSK[:]); err != nil {
		return nil, CSMErrRandomProvider
	}
	sessionXPK, err := ScalarMultCurve25519Base(&sessionXSK)
	if err != nil {
		return nil, CSMErrCrypto
	}
	body := out[64:]
	copy(body[:32], sessionXPK[:])
	bodyPayload := body[32:]
	plainPayload := make([]byte, 32+len(plaintext))
	copy(plainPayload[:32], c.EdPublicKey[:])
	copy(plainPayload[32:], plaintext)
	if rc := csmInternalSeal(plainPayload, serverXPK[:], sessionXSK[:], sessionXPK[:], bodyPayload); rc != CSMOK {
		MemZero(sessionXSK[:])
		return nil, rc
	}
	bodyLen := 32 + len(bodyPayload)
	sig, rc := csmInternalSign(body[:bodyLen], c.EdSecretKey[:])
	if rc != CSMOK {
		MemZero(sessionXSK[:])
		return nil, rc
	}
	copy(out[:64], sig[:])
	MemZero(sessionXSK[:])
	return out, CSMOK
}

func (c *CSMClient) Decrypt(packet []byte) ([]byte, CSMError) {
	minSize := 64 + 32 + 24 + 16
	if len(packet) <= minSize {
		return nil, CSMErrInvalidArg
	}
	sig := packet[:64]
	body := packet[64:]
	if rc := csmInternalVerify(sig, body, c.ServerEdPublicKey[:]); rc != CSMOK {
		return nil, CSMErrVerifyFailed
	}
	clientXSK, err := SignEd25519SKToCurve25519(&c.EdSecretKey)
	if err != nil {
		return nil, CSMErrCrypto
	}
	sessionXPK := body[:32]
	nonceCipher := body[32:]
	pt, rc := csmInternalOpen(nonceCipher, sessionXPK, clientXSK[:], sessionXPK)
	if rc != CSMOK {
		return nil, rc
	}
	MemZero(clientXSK[:])
	return pt, CSMOK
}

func (s *CSMServer) Decrypt(packet []byte) ([]byte, CSMError) {
	minSize := 64 + 32 + 24 + 16 + 32
	if len(packet) <= minSize {
		return nil, CSMErrInvalidArg
	}
	serverXSK, err := SignEd25519SKToCurve25519(&s.EdSecretKey)
	if err != nil {
		return nil, CSMErrCrypto
	}
	sig := packet[:64]
	body := packet[64:]
	sessionXPK := body[:32]
	nonceCipher := body[32:]
	opened, rc := csmInternalOpen(nonceCipher, sessionXPK, serverXSK[:], sessionXPK)
	if rc != CSMOK {
		MemZero(serverXSK[:])
		return nil, rc
	}
	if len(opened) <= 32 {
		MemZero(serverXSK[:])
		return nil, CSMErrCrypto
	}
	var clientEdPK [32]byte
	copy(clientEdPK[:], opened[:32])
	if rc := csmInternalVerify(sig, body, clientEdPK[:]); rc != CSMOK {
		MemZero(serverXSK[:])
		return nil, rc
	}
	s.ClientEdPublicKey = clientEdPK
	s.ClientPublicKeyInitialized = true
	pt := make([]byte, len(opened)-32)
	copy(pt, opened[32:])
	MemZero(serverXSK[:])
	return pt, CSMOK
}

func (s *CSMServer) Encrypt(plaintext []byte) ([]byte, CSMError) {
	if len(plaintext) == 0 {
		return nil, CSMErrNoData
	}
	if !s.ClientPublicKeyInitialized {
		return nil, CSMErrState
	}
	out := make([]byte, CSMServerEncryptSize(len(plaintext)))
	clientXPK, err := SignEd25519PKToCurve25519(&s.ClientEdPublicKey)
	if err != nil {
		return nil, CSMErrCrypto
	}
	var sessionXSK [32]byte
	if _, err := rand.Read(sessionXSK[:]); err != nil {
		return nil, CSMErrRandomProvider
	}
	sessionXPK, err := ScalarMultCurve25519Base(&sessionXSK)
	if err != nil {
		return nil, CSMErrCrypto
	}
	body := out[64:]
	copy(body[:32], sessionXPK[:])
	bodyPayload := body[32:]
	if rc := csmInternalSeal(plaintext, clientXPK[:], sessionXSK[:], sessionXPK[:], bodyPayload); rc != CSMOK {
		MemZero(sessionXSK[:])
		return nil, rc
	}
	bodyLen := 32 + len(bodyPayload)
	sig, rc := csmInternalSign(body[:bodyLen], s.EdSecretKey[:])
	if rc != CSMOK {
		MemZero(sessionXSK[:])
		return nil, rc
	}
	copy(out[:64], sig[:])
	MemZero(sessionXSK[:])
	return out, CSMOK
}

// ===========================================================================
// Layer 4: CSM-CA
// ===========================================================================

type CSMCAClient struct {
	EdSeed            [32]byte
	EdSecretKey       [64]byte
	EdPublicKey       [32]byte
	CAEdPublicKey     [32]byte
	ServerEdPublicKey [32]byte
	ServerKeyVerified bool
}

type CSMCAServer struct {
	EdSeed            [32]byte
	EdSecretKey       [64]byte
	EdPublicKey       [32]byte
	CASignature       [64]byte
	ClientEdPublicKey [32]byte
	ClientKeyVerified bool
}

func (c *CSMCAClient) Wipe() {
	var zero CSMCAClient
	*c = zero
}

func (s *CSMCAServer) Wipe() {
	var zero CSMCAServer
	*s = zero
}

func CSMCAClientCreate(edSeed, caEdPK *[32]byte) (*CSMCAClient, CSMError) {
	c := &CSMCAClient{}
	copy(c.EdSeed[:], edSeed[:])
	copy(c.CAEdPublicKey[:], caEdPK[:])
	pk, sk, err := SignEd25519SeedKeypair(edSeed)
	if err != nil {
		return nil, CSMErrCrypto
	}
	c.EdPublicKey = pk
	c.EdSecretKey = sk
	return c, CSMOK
}

func CSMCAServerCreate(edSeed *[32]byte, caSignature *[64]byte) (*CSMCAServer, CSMError) {
	s := &CSMCAServer{}
	copy(s.EdSeed[:], edSeed[:])
	copy(s.CASignature[:], caSignature[:])
	pk, sk, err := SignEd25519SeedKeypair(edSeed)
	if err != nil {
		return nil, CSMErrCrypto
	}
	s.EdPublicKey = pk
	s.EdSecretKey = sk
	return s, CSMOK
}

func CSMCAHandshakeResponseSize() int { return CSMCACertBytes }

func (s *CSMCAServer) HandshakeResponse() ([96]byte, CSMError) {
	var m1 [96]byte
	copy(m1[:32], s.EdPublicKey[:])
	copy(m1[32:], s.CASignature[:])
	return m1, CSMOK
}

func (c *CSMCAClient) HandshakeVerify(m1 []byte) CSMError {
	if len(m1) != CSMCACertBytes {
		return CSMErrInvalidArg
	}
	var sig [64]byte
	copy(sig[:], m1[32:])
	if !SignEd25519VerifyDetached(&sig, m1[:32], &c.CAEdPublicKey) {
		return CSMErrVerifyFailed
	}
	copy(c.ServerEdPublicKey[:], m1[:32])
	c.ServerKeyVerified = true
	return CSMOK
}

func CSMCAClientEncryptSize(n int) int { return CSMClientEncryptSize(n) }
func CSMCAClientDecryptMaxPlaintextSize(n int) int { return CSMClientDecryptMaxPlaintextSize(n) }
func CSMCAServerEncryptSize(n int) int { return CSMServerEncryptSize(n) }
func CSMCAServerDecryptMaxPlaintextSize(n int) int { return CSMServerDecryptMaxPlaintextSize(n) }

func (c *CSMCAClient) Encrypt(pt []byte) ([]byte, CSMError) {
	if len(pt) == 0 {
		return nil, CSMErrNoData
	}
	out := make([]byte, CSMCAClientEncryptSize(len(pt)))
	serverXPK, err := SignEd25519PKToCurve25519(&c.ServerEdPublicKey)
	if err != nil {
		return nil, CSMErrCrypto
	}
	var sessionXSK [32]byte
	if _, err := rand.Read(sessionXSK[:]); err != nil {
		return nil, CSMErrRandomProvider
	}
	sessionXPK, err := ScalarMultCurve25519Base(&sessionXSK)
	if err != nil {
		return nil, CSMErrCrypto
	}
	body := out[64:]
	copy(body[:32], sessionXPK[:])
	bodyPayload := body[32:]
	plainPayload := make([]byte, 32+len(pt))
	copy(plainPayload[:32], c.EdPublicKey[:])
	copy(plainPayload[32:], pt)
	if rc := csmInternalSeal(plainPayload, serverXPK[:], sessionXSK[:], sessionXPK[:], bodyPayload); rc != CSMOK {
		MemZero(sessionXSK[:])
		return nil, rc
	}
	bodyLen := 32 + len(bodyPayload)
	sig, rc := csmInternalSign(body[:bodyLen], c.EdSecretKey[:])
	if rc != CSMOK {
		MemZero(sessionXSK[:])
		return nil, rc
	}
	copy(out[:64], sig[:])
	MemZero(sessionXSK[:])
	return out, CSMOK
}

func (c *CSMCAClient) Decrypt(pkt []byte) ([]byte, CSMError) {
	minSize := 64 + 32 + 24 + 16
	if len(pkt) <= minSize {
		return nil, CSMErrInvalidArg
	}
	sig := pkt[:64]
	body := pkt[64:]
	if rc := csmInternalVerify(sig, body, c.ServerEdPublicKey[:]); rc != CSMOK {
		return nil, CSMErrVerifyFailed
	}
	clientXSK, err := SignEd25519SKToCurve25519(&c.EdSecretKey)
	if err != nil {
		return nil, CSMErrCrypto
	}
	sessionXPK := body[:32]
	nonceCipher := body[32:]
	pt, rc := csmInternalOpen(nonceCipher, sessionXPK, clientXSK[:], sessionXPK)
	MemZero(clientXSK[:])
	return pt, rc
}

func (s *CSMCAServer) Encrypt(pt []byte) ([]byte, CSMError) {
	if len(pt) == 0 {
		return nil, CSMErrNoData
	}
	if !s.ClientKeyVerified {
		// CSM-CA server learns client key from first decrypt; mirror CSM state guard.
	}
	out := make([]byte, CSMCAServerEncryptSize(len(pt)))
	if !s.ClientKeyVerified {
		// fall through: client key may have been set; if not, beforeNM will fail
	}
	clientXPK, err := SignEd25519PKToCurve25519(&s.ClientEdPublicKey)
	if err != nil {
		return nil, CSMErrCrypto
	}
	var sessionXSK [32]byte
	if _, err := rand.Read(sessionXSK[:]); err != nil {
		return nil, CSMErrRandomProvider
	}
	sessionXPK, err := ScalarMultCurve25519Base(&sessionXSK)
	if err != nil {
		return nil, CSMErrCrypto
	}
	body := out[64:]
	copy(body[:32], sessionXPK[:])
	bodyPayload := body[32:]
	if rc := csmInternalSeal(pt, clientXPK[:], sessionXSK[:], sessionXPK[:], bodyPayload); rc != CSMOK {
		MemZero(sessionXSK[:])
		return nil, rc
	}
	bodyLen := 32 + len(bodyPayload)
	sig, rc := csmInternalSign(body[:bodyLen], s.EdSecretKey[:])
	if rc != CSMOK {
		MemZero(sessionXSK[:])
		return nil, rc
	}
	copy(out[:64], sig[:])
	MemZero(sessionXSK[:])
	return out, CSMOK
}

func (s *CSMCAServer) Decrypt(pkt []byte) ([]byte, CSMError) {
	minSize := 64 + 32 + 24 + 16 + 32
	if len(pkt) <= minSize {
		return nil, CSMErrInvalidArg
	}
	serverXSK, err := SignEd25519SKToCurve25519(&s.EdSecretKey)
	if err != nil {
		return nil, CSMErrCrypto
	}
	sig := pkt[:64]
	body := pkt[64:]
	sessionXPK := body[:32]
	nonceCipher := body[32:]
	opened, rc := csmInternalOpen(nonceCipher, sessionXPK, serverXSK[:], sessionXPK)
	if rc != CSMOK {
		MemZero(serverXSK[:])
		return nil, rc
	}
	if len(opened) <= 32 {
		MemZero(serverXSK[:])
		return nil, CSMErrCrypto
	}
	var clientEdPK [32]byte
	copy(clientEdPK[:], opened[:32])
	if rc := csmInternalVerify(sig, body, clientEdPK[:]); rc != CSMOK {
		MemZero(serverXSK[:])
		return nil, rc
	}
	s.ClientEdPublicKey = clientEdPK
	s.ClientKeyVerified = true
	pt := make([]byte, len(opened)-32)
	copy(pt, opened[32:])
	MemZero(serverXSK[:])
	return pt, CSMOK
}

// ===========================================================================
// XSalsa20 family + runtime selector
// ===========================================================================

var gUseXChaCha20 = true

// BoxSetUseXChaCha20 selects the default box family (true = XChaCha20).
func BoxSetUseXChaCha20(use bool) { gUseXChaCha20 = use }

// BoxGetUseXChaCha20 reports the current default box family.
func BoxGetUseXChaCha20() bool { return gUseXChaCha20 }

// SetUseXChaCha20 is an alias for BoxSetUseXChaCha20.
func SetUseXChaCha20(use bool) { gUseXChaCha20 = use }

// GetUseXChaCha20 is an alias for BoxGetUseXChaCha20.
func GetUseXChaCha20() bool { return gUseXChaCha20 }

// xsalsa20 afternm engine (classic NaCl construction over Salsa20).
func xsalsa20BoxEasyAfterNM(m, nonce, k []byte) ([]byte, error) {
	out := make([]byte, 16+len(m))
	var block0 [64]byte
	mlen := len(m)
	firstTake := mlen
	if firstTake > 32 {
		firstTake = 32
	}
	if firstTake > 0 {
		copy(block0[32:], m[:firstTake])
	}
	xsalsa20XORIC(block0[:], block0[:32+firstTake], nonce, 0, k)
	var st poly1305State
	poly1305Init(&st, block0[:])
	if firstTake > 0 {
		copy(out[16:], block0[32:32+firstTake])
	}
	rem := mlen - firstTake
	if rem > 0 {
		xsalsa20XORIC(out[16+firstTake:], m[firstTake:], nonce, 1, k)
	}
	poly1305Update(&st, out[16:16+mlen])
	poly1305Finish(&st, out[:16])
	MemZero(block0[:])
	return out, nil
}

func xsalsa20BoxOpenEasyAfterNM(c, nonce, k []byte) ([]byte, error) {
	if len(c) < 16 {
		return nil, errors.New("naion: ciphertext too short")
	}
	mlen := len(c) - 16
	cipher := c[16:]
	out := make([]byte, mlen)
	var block0 [64]byte
	firstTake := mlen
	if firstTake > 32 {
		firstTake = 32
	}
	if firstTake > 0 {
		copy(block0[32:], cipher[:firstTake])
	}
	xsalsa20XORIC(block0[:], block0[:64], nonce, 0, k)
	var st poly1305State
	poly1305Init(&st, block0[:])
	poly1305Update(&st, cipher)
	var computed [16]byte
	poly1305Finish(&st, computed[:])
	if verify16(c[:16], computed[:]) != 1 {
		MemZero(block0[:])
		return nil, errors.New("naion: box verification failed")
	}
	if firstTake > 0 {
		copy(out, block0[32:32+firstTake])
	}
	rem := mlen - firstTake
	if rem > 0 {
		xsalsa20XORIC(out[firstTake:], cipher[firstTake:], nonce, 1, k)
	}
	MemZero(block0[:])
	return out, nil
}

func SecretboxXSalsa20Poly1305Easy(m, nonce, key []byte) ([]byte, error) {
	return xsalsa20BoxEasyAfterNM(m, nonce, key)
}

func SecretboxXSalsa20Poly1305OpenEasy(c, nonce, key []byte) ([]byte, error) {
	return xsalsa20BoxOpenEasyAfterNM(c, nonce, key)
}

func SecretboxXSalsa20Poly1305Detached(m, nonce, key []byte) ([]byte, [16]byte, error) {
	combined, err := xsalsa20BoxEasyAfterNM(m, nonce, key)
	if err != nil {
		return nil, [16]byte{}, err
	}
	var mac [16]byte
	copy(mac[:], combined[:16])
	ct := make([]byte, len(m))
	copy(ct, combined[16:])
	return ct, mac, nil
}

func SecretboxXSalsa20Poly1305OpenDetached(c []byte, mac *[16]byte, nonce, key []byte) ([]byte, error) {
	combined := make([]byte, 16+len(c))
	copy(combined[:16], mac[:])
	copy(combined[16:], c)
	return xsalsa20BoxOpenEasyAfterNM(combined, nonce, key)
}

// BoxCurve25519XSalsa20Poly1305BeforeNM: k = HSalsa20(X25519(sk,pk), zero16).
func BoxCurve25519XSalsa20Poly1305BeforeNM(pk, sk *[32]byte) ([32]byte, error) {
	var k [32]byte
	s, err := ScalarMultCurve25519(sk, pk)
	if err != nil {
		return k, err
	}
	var zero16 [16]byte
	hsalsa20(k[:], zero16[:], s[:])
	return k, nil
}

func BoxCurve25519XSalsa20Poly1305Keypair() (pk, sk [32]byte, err error) {
	return BoxCurve25519XChaCha20Poly1305Keypair()
}

func BoxCurve25519XSalsa20Poly1305SeedKeypair(seed *[32]byte) (pk, sk [32]byte, err error) {
	return BoxCurve25519XChaCha20Poly1305SeedKeypair(seed)
}

func BoxCurve25519XSalsa20Poly1305EasyAfterNM(m, nonce, k []byte) ([]byte, error) {
	return xsalsa20BoxEasyAfterNM(m, nonce, k)
}

func BoxCurve25519XSalsa20Poly1305OpenEasyAfterNM(c, nonce, k []byte) ([]byte, error) {
	return xsalsa20BoxOpenEasyAfterNM(c, nonce, k)
}

func BoxCurve25519XSalsa20Poly1305Easy(m, nonce []byte, pk, sk *[32]byte) ([]byte, error) {
	k, err := BoxCurve25519XSalsa20Poly1305BeforeNM(pk, sk)
	if err != nil {
		return nil, err
	}
	return xsalsa20BoxEasyAfterNM(m, nonce, k[:])
}

func BoxCurve25519XSalsa20Poly1305OpenEasy(c, nonce []byte, pk, sk *[32]byte) ([]byte, error) {
	k, err := BoxCurve25519XSalsa20Poly1305BeforeNM(pk, sk)
	if err != nil {
		return nil, err
	}
	return xsalsa20BoxOpenEasyAfterNM(c, nonce, k[:])
}

func BoxCurve25519XSalsa20Poly1305Seal(m []byte, pk *[32]byte) ([]byte, error) {
	var esk [32]byte
	if _, err := rand.Read(esk[:]); err != nil {
		return nil, err
	}
	epk, err := ScalarMultCurve25519Base(&esk)
	if err != nil {
		return nil, err
	}
	h, err := blake2b.New(24, nil)
	if err != nil {
		return nil, err
	}
	h.Write(epk[:])
	h.Write(pk[:])
	var nonce [24]byte
	copy(nonce[:], h.Sum(nil))
	out := make([]byte, 32+16+len(m))
	copy(out[:32], epk[:])
	ct, err := BoxCurve25519XSalsa20Poly1305Easy(m, nonce[:], pk, &esk)
	if err != nil {
		return nil, err
	}
	copy(out[32:], ct)
	MemZero(esk[:])
	return out, nil
}

func BoxCurve25519XSalsa20Poly1305SealOpen(c []byte, pk, sk *[32]byte) ([]byte, error) {
	if len(c) < 48 {
		return nil, errors.New("naion: sealed box too short")
	}
	var epk [32]byte
	copy(epk[:], c[:32])
	h, err := blake2b.New(24, nil)
	if err != nil {
		return nil, err
	}
	h.Write(epk[:])
	h.Write(pk[:])
	var nonce [24]byte
	copy(nonce[:], h.Sum(nil))
	return BoxCurve25519XSalsa20Poly1305OpenEasy(c[32:], nonce[:], &epk, sk)
}

// ---- generic box dispatch (selects XChaCha20 vs XSalsa20 at runtime) ----

func BoxKeypair() (pk, sk [32]byte, err error) {
	if gUseXChaCha20 {
		return BoxCurve25519XChaCha20Poly1305Keypair()
	}
	return BoxCurve25519XSalsa20Poly1305Keypair()
}

func BoxSeedKeypair(seed *[32]byte) (pk, sk [32]byte, err error) {
	if gUseXChaCha20 {
		return BoxCurve25519XChaCha20Poly1305SeedKeypair(seed)
	}
	return BoxCurve25519XSalsa20Poly1305SeedKeypair(seed)
}

func BoxBeforeNM(pk, sk *[32]byte) ([32]byte, error) {
	if gUseXChaCha20 {
		return BoxCurve25519XChaCha20Poly1305BeforeNM(pk, sk)
	}
	return BoxCurve25519XSalsa20Poly1305BeforeNM(pk, sk)
}

func BoxEasy(m, nonce []byte, pk, sk *[32]byte) ([]byte, error) {
	if gUseXChaCha20 {
		return BoxCurve25519XChaCha20Poly1305Easy(m, nonce, pk, sk)
	}
	return BoxCurve25519XSalsa20Poly1305Easy(m, nonce, pk, sk)
}

func BoxOpenEasy(c, nonce []byte, pk, sk *[32]byte) ([]byte, error) {
	if gUseXChaCha20 {
		return BoxCurve25519XChaCha20Poly1305OpenEasy(c, nonce, pk, sk)
	}
	return BoxCurve25519XSalsa20Poly1305OpenEasy(c, nonce, pk, sk)
}

func BoxEasyAfterNM(m, nonce, k []byte) ([]byte, error) {
	if gUseXChaCha20 {
		return boxEasyAfterNM(m, nonce, k)
	}
	return xsalsa20BoxEasyAfterNM(m, nonce, k)
}

func BoxOpenEasyAfterNM(c, nonce, k []byte) ([]byte, error) {
	if gUseXChaCha20 {
		return boxOpenEasyAfterNM(c, nonce, k)
	}
	return xsalsa20BoxOpenEasyAfterNM(c, nonce, k)
}

func BoxSeal(m []byte, pk *[32]byte) ([]byte, error) {
	if gUseXChaCha20 {
		return BoxCurve25519XChaCha20Poly1305Seal(m, pk)
	}
	return BoxCurve25519XSalsa20Poly1305Seal(m, pk)
}

func BoxSealOpen(c []byte, pk, sk *[32]byte) ([]byte, error) {
	if gUseXChaCha20 {
		return BoxCurve25519XChaCha20Poly1305SealOpen(c, pk, sk)
	}
	return BoxCurve25519XSalsa20Poly1305SealOpen(c, pk, sk)
}

// query helpers
func BoxSeedBytes() int      { return BoxSeedBytesMax }
func BoxPublicKeyBytes() int { return BoxPublicKeyBytesMax }
func BoxSecretKeyBytes() int { return BoxSecretKeyBytesMax }
func BoxBeforeNMBytes() int  { return BoxBeforeNMBytesMax }
func BoxNonceBytes() int     { return BoxNonceBytesMax }
func BoxMacBytes() int       { return BoxMacBytesMax }
func BoxSealBytes() int      { return BoxSealBytesMax }
