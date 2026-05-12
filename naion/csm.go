package naion

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math/big"
	"sync"
	"time"

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

	PacketMetaBytes       = 16
	MaxUDPDatagramBytes   = 1024
	PacketProtocolVersion = 1
	packetMagic           = "IFW1"
)

const (
	packetFixedOverheadBytes = SignBytes + XPKBytes + NonceBytes + MACBytes
	clientPacketFixedBytes   = packetFixedOverheadBytes + PacketMetaBytes + EdPKBytes
	serverPacketFixedBytes   = packetFixedOverheadBytes + PacketMetaBytes
	MaxClientPayloadBytes    = MaxUDPDatagramBytes - clientPacketFixedBytes
	MaxServerPayloadBytes    = MaxUDPDatagramBytes - serverPacketFixedBytes
	defaultReplayRetentionMS = uint64(5 * 60 * 1000)
)

var (
	ErrInvalidArgument        = errors.New("csm: invalid argument")
	ErrBufferTooSmall         = errors.New("csm: buffer too small")
	ErrCrypto                 = errors.New("csm: crypto failed")
	ErrVerifyFailed           = errors.New("csm: verify failed")
	ErrState                  = errors.New("csm: invalid state")
	ErrNoData                 = errors.New("csm: empty data")
	ErrPayloadTooLarge        = errors.New("csm: payload too large")
	ErrInvalidPacket          = errors.New("csm: invalid packet")
	ErrInvalidMeta            = errors.New("csm: invalid packet meta")
	ErrTimestampOutsideWindow = errors.New("csm: timestamp outside window")
	ErrReplayDetected         = errors.New("csm: replay detected")
)

type PacketMeta struct {
	ProtocolVersion uint8
	Reserved        uint8
	Flags           uint16
	TimestampMS     uint64
}

type ReplayCache interface {
	CheckAndStore(clientPublicKey, signature []byte, timestampMS, nowMS uint64) error
}

type MemoryReplayCache struct {
	mu          sync.Mutex
	retentionMS uint64
	entries     map[[32]byte]uint64
}

func NewMemoryReplayCache(retention time.Duration) *MemoryReplayCache {
	retentionMS := uint64(retention / time.Millisecond)
	if retentionMS == 0 {
		retentionMS = defaultReplayRetentionMS
	}
	return &MemoryReplayCache{
		retentionMS: retentionMS,
		entries:     make(map[[32]byte]uint64),
	}
}

func (c *MemoryReplayCache) CheckAndStore(clientPublicKey, signature []byte, timestampMS, nowMS uint64) error {
	if c == nil {
		return ErrInvalidArgument
	}
	_ = timestampMS
	key := replayKey(clientPublicKey, signature)

	c.mu.Lock()
	defer c.mu.Unlock()

	for k, expiry := range c.entries {
		if expiry <= nowMS {
			delete(c.entries, k)
		}
	}

	if expiry, ok := c.entries[key]; ok && expiry > nowMS {
		return ErrReplayDetected
	}

	c.entries[key] = nowMS + c.retentionMS
	return nil
}

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
	nowFunc           func() time.Time
}

type Server struct {
	edSeed                [EdSeedBytes]byte
	edSecretKey           ed25519.PrivateKey
	edPublicKey           ed25519.PublicKey
	clientEdPublicKey     ed25519.PublicKey
	clientPublicKeyInited bool
	timestampWindowMS     uint64
	replayCache           ReplayCache
	nowFunc               func() time.Time
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
		nowFunc:           time.Now,
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
		nowFunc:     time.Now,
	}, nil
}

func (c *Client) SetNowFunc(fn func() time.Time) {
	if c == nil {
		return
	}
	if fn == nil {
		c.nowFunc = time.Now
		return
	}
	c.nowFunc = fn
}

func (s *Server) SetNowFunc(fn func() time.Time) {
	if s == nil {
		return
	}
	if fn == nil {
		s.nowFunc = time.Now
		return
	}
	s.nowFunc = fn
}

func (s *Server) SetTimestampWindow(window time.Duration) {
	if s == nil {
		return
	}
	if window <= 0 {
		s.timestampWindowMS = 0
		return
	}
	s.timestampWindowMS = uint64(window / time.Millisecond)
}

func (s *Server) SetReplayCache(cache ReplayCache) {
	if s == nil {
		return
	}
	s.replayCache = cache
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

	payload := make([]byte, 0, PacketMetaBytes+EdPKBytes+len(plaintext))
	payload = append(payload, marshalPacketMeta(newPacketMeta(currentTimestampMS(c.nowFunc)))...)
	payload = append(payload, c.edPublicKey...)
	payload = append(payload, plaintext...)

	sealed, err := seal(payload, serverXPK, sessionXSK)
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
	opened, err := openBox(nonceCipher, &sessionXPK, &clientXSK)
	if err != nil {
		return nil, err
	}
	_, payload, err := parsePacketMeta(opened)
	if err != nil {
		return nil, err
	}
	if len(payload) == 0 {
		return nil, ErrInvalidPacket
	}
	return append([]byte(nil), payload...), nil
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
	opened, err := openBox(nonceCipher, &sessionXPK, &serverXSK)
	if err != nil {
		return nil, err
	}

	meta, payload, err := parsePacketMeta(opened)
	if err != nil {
		return nil, err
	}
	if len(payload) <= EdPKBytes {
		return nil, ErrInvalidPacket
	}

	clientEDPK := append([]byte(nil), payload[:EdPKBytes]...)
	plaintext := append([]byte(nil), payload[EdPKBytes:]...)
	if !ed25519.Verify(clientEDPK, body, signature) {
		return nil, ErrVerifyFailed
	}
	if err := s.validateTimestamp(meta); err != nil {
		return nil, err
	}
	if err := s.checkReplay(clientEDPK, signature, meta.TimestampMS); err != nil {
		return nil, err
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

	payload := make([]byte, 0, PacketMetaBytes+len(plaintext))
	payload = append(payload, marshalPacketMeta(newPacketMeta(currentTimestampMS(s.nowFunc)))...)
	payload = append(payload, plaintext...)

	sealed, err := seal(payload, clientXPK, sessionXSK)
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

func newPacketMeta(nowMS uint64) PacketMeta {
	return PacketMeta{
		ProtocolVersion: PacketProtocolVersion,
		TimestampMS:     nowMS,
	}
}

func marshalPacketMeta(meta PacketMeta) []byte {
	out := make([]byte, PacketMetaBytes)
	copy(out[:4], []byte(packetMagic))
	out[4] = meta.ProtocolVersion
	out[5] = meta.Reserved
	binary.LittleEndian.PutUint16(out[6:8], meta.Flags)
	binary.LittleEndian.PutUint64(out[8:16], meta.TimestampMS)
	return out
}

func parsePacketMeta(buffer []byte) (PacketMeta, []byte, error) {
	if len(buffer) < PacketMetaBytes {
		return PacketMeta{}, nil, ErrInvalidMeta
	}
	if string(buffer[:4]) != packetMagic {
		return PacketMeta{}, nil, ErrInvalidMeta
	}
	meta := PacketMeta{
		ProtocolVersion: buffer[4],
		Reserved:        buffer[5],
		Flags:           binary.LittleEndian.Uint16(buffer[6:8]),
		TimestampMS:     binary.LittleEndian.Uint64(buffer[8:16]),
	}
	if meta.ProtocolVersion != PacketProtocolVersion {
		return PacketMeta{}, nil, ErrInvalidMeta
	}
	return meta, buffer[PacketMetaBytes:], nil
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

func seal(plaintext []byte, peerXPK *[XPKBytes]byte, selfXSK *[XSKBytes]byte) ([]byte, error) {
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
	ciphertextAndTag := aead.Seal(nil, nonce[:], plaintext, nil)
	out := make([]byte, 0, NonceBytes+len(ciphertextAndTag))
	out = append(out, nonce[:]...)
	out = append(out, ciphertextAndTag[len(ciphertextAndTag)-MACBytes:]...)
	out = append(out, ciphertextAndTag[:len(ciphertextAndTag)-MACBytes]...)
	return out, nil
}

func openBox(nonceCipher []byte, peerXPK *[XPKBytes]byte, selfXSK *[XSKBytes]byte) ([]byte, error) {
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
	opened, err := aead.Open(nil, nonce[:], combined, nil)
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

func currentTimestampMS(nowFn func() time.Time) uint64 {
	if nowFn == nil {
		nowFn = time.Now
	}
	return uint64(nowFn().UnixMilli())
}

func (s *Server) validateTimestamp(meta PacketMeta) error {
	if s == nil || s.timestampWindowMS == 0 {
		return nil
	}
	nowMS := currentTimestampMS(s.nowFunc)
	var diff uint64
	if nowMS >= meta.TimestampMS {
		diff = nowMS - meta.TimestampMS
	} else {
		diff = meta.TimestampMS - nowMS
	}
	if diff > s.timestampWindowMS {
		return ErrTimestampOutsideWindow
	}
	return nil
}

func (s *Server) checkReplay(clientPublicKey, signature []byte, timestampMS uint64) error {
	if s == nil || s.replayCache == nil {
		return nil
	}
	return s.replayCache.CheckAndStore(clientPublicKey, signature, timestampMS, currentTimestampMS(s.nowFunc))
}

func replayKey(clientPublicKey, signature []byte) [32]byte {
	buf := make([]byte, 0, len(clientPublicKey)+len(signature))
	buf = append(buf, clientPublicKey...)
	buf = append(buf, signature...)
	return sha256.Sum256(buf)
}
