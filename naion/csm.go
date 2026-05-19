package naion

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"math/big"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	SignBytes   = ed25519.SignatureSize
	EdSeedBytes = ed25519.SeedSize
	EdPKBytes   = ed25519.PublicKeySize
	EdSKBytes   = ed25519.PrivateKeySize
	XPKBytes    = 32
	XSKBytes    = 32
	NonceBytes  = chacha20poly1305.NonceSizeX
	MACBytes    = 16

	MaxUDPDatagramBytes = 1024
)

const (
	packetFixedOverheadBytes = SignBytes + XPKBytes + NonceBytes + MACBytes
	clientPacketFixedBytes   = packetFixedOverheadBytes + EdPKBytes
	serverPacketFixedBytes   = packetFixedOverheadBytes
	MaxClientPayloadBytes    = MaxUDPDatagramBytes - clientPacketFixedBytes
	MaxServerPayloadBytes    = MaxUDPDatagramBytes - serverPacketFixedBytes
)

var (
	ErrInvalidArgument = errors.New("csm: invalid argument")
	ErrBufferTooSmall  = errors.New("csm: buffer too small")
	ErrCrypto          = errors.New("csm: crypto failed")
	ErrVerifyFailed    = errors.New("csm: verify failed")
	ErrState           = errors.New("csm: invalid state")
	ErrNoData          = errors.New("csm: empty data")
	ErrPayloadTooLarge = errors.New("csm: payload too large")
	ErrInvalidPacket   = errors.New("csm: invalid packet")
)

func Init() int { return 0 }

func ClientEncryptSize(plaintextLen int) int {
	if plaintextLen < 0 {
		return 0
	}
	return clientPacketFixedBytes + plaintextLen
}

func ClientDecryptMaxPlaintextSize(packetLen int) int {
	if packetLen <= serverPacketFixedBytes {
		return 0
	}
	return packetLen - serverPacketFixedBytes
}

func ServerEncryptSize(plaintextLen int) int {
	if plaintextLen < 0 {
		return 0
	}
	return serverPacketFixedBytes + plaintextLen
}

func ServerDecryptMaxPlaintextSize(packetLen int) int {
	if packetLen <= clientPacketFixedBytes {
		return 0
	}
	return packetLen - clientPacketFixedBytes
}

type Client struct {
	edSeed            [EdSeedBytes]byte
	edSecretKey       ed25519.PrivateKey
	edPublicKey       ed25519.PublicKey
	serverEdPublicKey ed25519.PublicKey
}

type Server struct {
	edSeed                [EdSeedBytes]byte
	edSecretKey           ed25519.PrivateKey
	edPublicKey           ed25519.PublicKey
	clientEdPublicKey     ed25519.PublicKey
	clientPublicKeyInited bool
}

func NewClient(edSeedClient []byte, edPublicKeyServer []byte) (*Client, error) {
	if len(edSeedClient) != EdSeedBytes || len(edPublicKeyServer) != EdPKBytes {
		return nil, ErrInvalidArgument
	}
	var seed [EdSeedBytes]byte
	copy(seed[:], edSeedClient)
	edSecretKey := ed25519.NewKeyFromSeed(seed[:])
	edPublicKey := edSecretKey.Public().(ed25519.PublicKey)

	serverPK := make([]byte, EdPKBytes)
	copy(serverPK, edPublicKeyServer)

	return &Client{
		edSeed:            seed,
		edSecretKey:       edSecretKey,
		edPublicKey:       append(ed25519.PublicKey(nil), edPublicKey...),
		serverEdPublicKey: append(ed25519.PublicKey(nil), serverPK...),
	}, nil
}

func NewServer(edSeedServer []byte) (*Server, error) {
	if len(edSeedServer) != EdSeedBytes {
		return nil, ErrInvalidArgument
	}
	var seed [EdSeedBytes]byte
	copy(seed[:], edSeedServer)
	edSecretKey := ed25519.NewKeyFromSeed(seed[:])
	edPublicKey := edSecretKey.Public().(ed25519.PublicKey)
	return &Server{
		edSeed:      seed,
		edSecretKey: edSecretKey,
		edPublicKey: append(ed25519.PublicKey(nil), edPublicKey...),
	}, nil
}

func (c *Client) Encrypt(plaintext []byte) ([]byte, error) {
	if c == nil {
		return nil, ErrInvalidArgument
	}
	if len(plaintext) == 0 {
		return nil, ErrNoData
	}
	if len(plaintext) > MaxClientPayloadBytes {
		return nil, ErrPayloadTooLarge
	}
	serverXPK, err := edPublicToCurve25519(c.serverEdPublicKey)
	if err != nil {
		return nil, err
	}
	sessionXPK, sessionXSK, err := generateX25519Keypair()
	if err != nil {
		return nil, err
	}

	payload := make([]byte, 0, EdPKBytes+len(plaintext))
	payload = append(payload, c.edPublicKey...)
	payload = append(payload, plaintext...)

	sealed, err := seal(payload, serverXPK, sessionXSK, sessionXPK[:])
	if err != nil {
		return nil, err
	}

	body := make([]byte, 0, XPKBytes+len(sealed))
	body = append(body, sessionXPK[:]...)
	body = append(body, sealed...)
	sig := ed25519.Sign(c.edSecretKey, body)
	out := make([]byte, 0, len(sig)+len(body))
	out = append(out, sig...)
	out = append(out, body...)
	return out, nil
}

func (c *Client) Decrypt(packet []byte) ([]byte, error) {
	if c == nil {
		return nil, ErrInvalidArgument
	}
	minSize := serverPacketFixedBytes
	if len(packet) <= minSize {
		return nil, ErrInvalidPacket
	}
	signature := packet[:SignBytes]
	body := packet[SignBytes:]
	if !ed25519.Verify(c.serverEdPublicKey, body, signature) {
		return nil, ErrVerifyFailed
	}
	var sessionXPK [XPKBytes]byte
	copy(sessionXPK[:], body[:XPKBytes])
	nonceCipher := body[XPKBytes:]
	clientXSK := edSecretToCurve25519(c.edSecretKey)
	opened, err := openBox(nonceCipher, &sessionXPK, &clientXSK, sessionXPK[:])
	if err != nil {
		return nil, err
	}
	if len(opened) == 0 {
		return nil, ErrInvalidPacket
	}
	return append([]byte(nil), opened...), nil
}

func (s *Server) Decrypt(packet []byte) ([]byte, error) {
	if s == nil {
		return nil, ErrInvalidArgument
	}
	minSize := clientPacketFixedBytes
	if len(packet) <= minSize {
		return nil, ErrInvalidPacket
	}
	signature := packet[:SignBytes]
	body := packet[SignBytes:]
	var sessionXPK [XPKBytes]byte
	copy(sessionXPK[:], body[:XPKBytes])
	nonceCipher := body[XPKBytes:]
	serverXSK := edSecretToCurve25519(s.edSecretKey)
	opened, err := openBox(nonceCipher, &sessionXPK, &serverXSK, sessionXPK[:])
	if err != nil {
		return nil, err
	}

	if len(opened) <= EdPKBytes {
		return nil, ErrInvalidPacket
	}

	clientEDPK := append([]byte(nil), opened[:EdPKBytes]...)
	plaintext := append([]byte(nil), opened[EdPKBytes:]...)
	if !ed25519.Verify(clientEDPK, body, signature) {
		return nil, ErrVerifyFailed
	}
	s.clientEdPublicKey = clientEDPK
	s.clientPublicKeyInited = true
	return plaintext, nil
}

func (s *Server) Encrypt(plaintext []byte) ([]byte, error) {
	if s == nil {
		return nil, ErrInvalidArgument
	}
	if !s.clientPublicKeyInited {
		return nil, ErrState
	}
	if len(plaintext) == 0 {
		return nil, ErrNoData
	}
	if len(plaintext) > MaxServerPayloadBytes {
		return nil, ErrPayloadTooLarge
	}
	clientXPK, err := edPublicToCurve25519(s.clientEdPublicKey)
	if err != nil {
		return nil, err
	}
	sessionXPK, sessionXSK, err := generateX25519Keypair()
	if err != nil {
		return nil, err
	}

	sealed, err := seal(plaintext, clientXPK, sessionXSK, sessionXPK[:])
	if err != nil {
		return nil, err
	}
	body := make([]byte, 0, XPKBytes+len(sealed))
	body = append(body, sessionXPK[:]...)
	body = append(body, sealed...)
	sig := ed25519.Sign(s.edSecretKey, body)
	out := make([]byte, 0, len(sig)+len(body))
	out = append(out, sig...)
	out = append(out, body...)
	return out, nil
}

func (s *Server) ClientPublicKeyInitialized() bool {
	return s != nil && s.clientPublicKeyInited
}

func (s *Server) ClientEdPublicKey() []byte {
	if s == nil || !s.clientPublicKeyInited {
		return nil
	}
	return append([]byte(nil), s.clientEdPublicKey...)
}

func (c *Client) EdPublicKey() []byte {
	if c == nil {
		return nil
	}
	return append([]byte(nil), c.edPublicKey...)
}

func (s *Server) EdPublicKey() []byte {
	if s == nil {
		return nil
	}
	return append([]byte(nil), s.edPublicKey...)
}

func generateX25519Keypair() (*[XPKBytes]byte, *[XSKBytes]byte, error) {
	var sk [XSKBytes]byte
	if _, err := rand.Read(sk[:]); err != nil {
		return nil, nil, ErrCrypto
	}
	clampCurve25519Secret(&sk)
	pkSlice, err := curve25519.X25519(sk[:], curve25519.Basepoint)
	if err != nil {
		return nil, nil, ErrCrypto
	}
	var pk [XPKBytes]byte
	copy(pk[:], pkSlice)
	return &pk, &sk, nil
}

func seal(plaintext []byte, peerXPK *[XPKBytes]byte, selfXSK *[XSKBytes]byte, aad []byte) ([]byte, error) {
	if len(plaintext) == 0 || peerXPK == nil || selfXSK == nil {
		return nil, ErrInvalidArgument
	}
	var nonce [NonceBytes]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, ErrCrypto
	}
	aeadKey, err := deriveAEADKey(peerXPK, selfXSK)
	if err != nil {
		return nil, ErrCrypto
	}
	aead, err := chacha20poly1305.NewX(aeadKey)
	if err != nil {
		return nil, ErrCrypto
	}
	ciphertextAndTag := aead.Seal(nil, nonce[:], plaintext, aad)
	out := make([]byte, 0, NonceBytes+len(ciphertextAndTag))
	out = append(out, nonce[:]...)
	out = append(out, ciphertextAndTag[len(ciphertextAndTag)-MACBytes:]...)
	out = append(out, ciphertextAndTag[:len(ciphertextAndTag)-MACBytes]...)
	return out, nil
}

func openBox(nonceCipher []byte, peerXPK *[XPKBytes]byte, selfXSK *[XSKBytes]byte, aad []byte) ([]byte, error) {
	if len(nonceCipher) <= NonceBytes+MACBytes || peerXPK == nil || selfXSK == nil {
		return nil, ErrInvalidArgument
	}
	var nonce [NonceBytes]byte
	copy(nonce[:], nonceCipher[:NonceBytes])
	macCiphertext := nonceCipher[NonceBytes:]
	aeadKey, err := deriveAEADKey(peerXPK, selfXSK)
	if err != nil {
		return nil, ErrCrypto
	}
	aead, err := chacha20poly1305.NewX(aeadKey)
	if err != nil {
		return nil, ErrCrypto
	}
	combined := make([]byte, 0, len(macCiphertext))
	combined = append(combined, macCiphertext[MACBytes:]...)
	combined = append(combined, macCiphertext[:MACBytes]...)
	opened, err := aead.Open(nil, nonce[:], combined, aad)
	if err != nil {
		return nil, ErrCrypto
	}
	return opened, nil
}

func deriveAEADKey(peerXPK *[XPKBytes]byte, selfXSK *[XSKBytes]byte) ([]byte, error) {
	shared, err := curve25519.X25519(selfXSK[:], peerXPK[:])
	if err != nil {
		return nil, ErrCrypto
	}
	zeroNonce := make([]byte, 16)
	key, err := chacha20.HChaCha20(shared, zeroNonce)
	if err != nil {
		return nil, ErrCrypto
	}
	return key, nil
}

func edSecretToCurve25519(edSecret ed25519.PrivateKey) [XSKBytes]byte {
	seed := edSecret.Seed()
	h := sha512.Sum512(seed)
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	var out [XSKBytes]byte
	copy(out[:], h[:32])
	return out
}

func edPublicToCurve25519(edPublic ed25519.PublicKey) (*[XPKBytes]byte, error) {
	if len(edPublic) != EdPKBytes {
		return nil, ErrInvalidArgument
	}
	const pHex = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"
	p, ok := new(big.Int).SetString(pHex, 16)
	if !ok {
		return nil, ErrCrypto
	}

	yBytes := make([]byte, 32)
	copy(yBytes, edPublic)
	yBytes[31] &= 0x7f
	reverse(yBytes)
	y := new(big.Int).SetBytes(yBytes)
	if y.Cmp(p) >= 0 {
		return nil, ErrCrypto
	}

	one := big.NewInt(1)
	num := new(big.Int).Add(one, y)
	num.Mod(num, p)
	den := new(big.Int).Sub(one, y)
	den.Mod(den, p)
	inv := new(big.Int).ModInverse(den, p)
	if inv == nil {
		return nil, ErrCrypto
	}
	u := new(big.Int).Mul(num, inv)
	u.Mod(u, p)

	be := u.Bytes()
	le := make([]byte, 32)
	copy(le[32-len(be):], be)
	reverse(le)
	var out [XPKBytes]byte
	copy(out[:], le)
	return &out, nil
}

func clampCurve25519Secret(sk *[XSKBytes]byte) {
	sk[0] &= 248
	sk[31] &= 127
	sk[31] |= 64
}

func reverse(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}
