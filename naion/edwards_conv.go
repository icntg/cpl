// Edwards25519 → Curve25519 (Montgomery u) public key conversion.
//
// Computes u = (1 + y) / (1 - y) mod (2^255 - 19) from the y coordinate
// embedded in a 32-byte Ed25519 public key, matching libsodium's
// crypto_sign_ed25519_pk_to_curve25519. Uses math/big for clarity and
// verifiable correctness; performance is fine for per-key conversion.
//
// (Field-arithmetic approach distilled from filippo.io/edwards25519.)
package naion

import (
	"errors"
	"math/big"
)

var edP, _ = new(big.Int).SetString("57896044618658097711785492504343953926634992332820282019728792003956564819949", 10) // 2^255 - 19

// ed25519PKToCurve25519 converts an Ed25519 public key to a Curve25519 (X25519)
// public key.
func ed25519PKToCurve25519(edPK *[32]byte) ([32]byte, error) {
	var out [32]byte
	// Recover y: little-endian, clear sign bit (top bit of byte 31).
	yb := make([]byte, 32)
	copy(yb, edPK[:])
	yb[31] &= 0x7f
	// big.Int expects big-endian.
	y := new(big.Int).SetBytes(reverseBytes(yb))
	if y.Cmp(edP) >= 0 {
		return out, errors.New("naion: invalid Ed25519 public key")
	}

	one := big.NewInt(1)
	num := new(big.Int).Add(one, y)        // 1 + y
	den := new(big.Int).Sub(one, y)        // 1 - y
	if den.Sign() == 0 {
		return out, errors.New("naion: invalid Ed25519 public key")
	}
	// den^-1 mod p
	inv := new(big.Int).ModInverse(den, edP)
	if inv == nil {
		return out, errors.New("naion: invalid Ed25519 public key")
	}
	u := new(big.Int).Mul(num, inv)
	u.Mod(u, edP)

	// Encode u little-endian into 32 bytes.
	ub := u.Bytes() // big-endian, minimal length
	// pad to 32 then reverse
	var buf [32]byte
	copy(buf[32-len(ub):], ub)
	for i := 0; i < 16; i++ {
		buf[i], buf[31-i] = buf[31-i], buf[i]
	}
	copy(out[:], buf[:])
	return out, nil
}

func reverseBytes(b []byte) []byte {
	r := make([]byte, len(b))
	for i := range b {
		r[i] = b[len(b)-1-i]
	}
	return r
}
