// gen_cert_vectors.go prints test/cert_vectors.inc, the C++ definitions of the test vectors
// of test/test_cert.cpp (cpl::cert), to stdout. Standard library only.
//
// Usage, from the cpl directory:
//
//	go run test/gen_cert_vectors.go > test/cert_vectors.inc
//
// Every value is deterministic: each Ed25519 key is derived from a fixed seed, every
// certificate has a fixed serial number and a fixed validity window, and
// x509.CreateCertificate reads its entropy from a seeded reader. The verification time is
// fixed (kFixedNow, 2027-01-15T08:00:00Z) and every validity window that has to pass rule
// R5 contains it.
//
// The generator checks its own output (chain signatures, token signatures) and exits with
// status 1 instead of printing a broken vector.
package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

const (
	// kFixedNow is the time at which the tests verify the vectors: 2027-01-15T08:00:00Z.
	kFixedNow = 1800000000

	graceSeconds = 86400
)

// ---------------------------------------------------------------------------
// Deterministic building blocks
// ---------------------------------------------------------------------------

// check aborts the generator on an unexpected error.
func check(err error) {
	if err != nil {
		broken(err.Error())
	}
}

// broken reports an invariant that does not hold and exits with status 1. Nothing has been
// printed at this point, so a broken vector never reaches the include file.
func broken(message string) {
	fmt.Fprintln(os.Stderr, "gen_cert_vectors: "+message)
	os.Exit(1)
}

// fixedSeed derives the 32 byte seed of a key, or of the entropy stream, from a label.
func fixedSeed(label string) []byte {
	sum := sha256.Sum256([]byte("cpl-cert-vectors/" + label))
	return sum[:]
}

// edKey derives an Ed25519 key from the seed of a label.
func edKey(label string) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(fixedSeed(label))
}

// p256Key derives a P-256 key: SHA-256 of the label is the scalar, reduced modulo the
// group order.
func p256Key(label string) *ecdsa.PrivateKey {
	curve := elliptic.P256()
	scalar := new(big.Int).SetBytes(fixedSeed(label))
	scalar.Mod(scalar, curve.Params().N)
	publicX, publicY := curve.ScalarBaseMult(scalar.Bytes())
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: publicX, Y: publicY},
		D:         scalar,
	}
}

// entropy is a deterministic io.Reader: SHA-256 in counter mode over a fixed seed.
// x509.CreateCertificate reads everything that needs randomness from it, so the output of
// the generator does not depend on the machine that runs it.
type entropy struct {
	block   []byte
	counter uint32
}

func (r *entropy) Read(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		if len(r.block) == 0 {
			counter := []byte{byte(r.counter >> 24), byte(r.counter >> 16), byte(r.counter >> 8), byte(r.counter)}
			sum := sha256.Sum256(append(fixedSeed("entropy"), counter...))
			r.block = sum[:]
			r.counter++
		}
		n := copy(p, r.block)
		r.block = r.block[n:]
		p = p[n:]
		total += n
	}
	return total, nil
}

// utc returns midnight UTC of a date.
func utc(year, month, day int) time.Time {
	return time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
}

// keyID returns a fixed key identifier: the first 20 bytes of SHA-256 over the public key.
// The identifiers are written explicitly so that the certificates do not depend on the
// defaults of the Go version that builds them.
func keyID(public any) []byte {
	der, err := x509.MarshalPKIXPublicKey(public)
	check(err)
	sum := sha256.Sum256(der)
	return sum[:20]
}

// ---------------------------------------------------------------------------
// Minimal DER building, for certificates that x509.CreateCertificate cannot express
// ---------------------------------------------------------------------------

// derLength encodes a length in the shortest form.
func derLength(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	case n < 0x10000:
		return []byte{0x82, byte(n >> 8), byte(n)}
	default:
		return []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

// derTLV builds one element from its identifier octet and its content octets.
func derTLV(tag byte, content ...[]byte) []byte {
	body := bytes.Join(content, nil)
	out := make([]byte, 0, 2+len(body))
	out = append(append(out, tag), derLength(len(body))...)
	return append(out, body...)
}

// derBitString builds a BIT STRING; unused is the number of bits of the last octet that are
// not used.
func derBitString(unused byte, octets []byte) []byte {
	return derTLV(0x03, append([]byte{unused}, octets...))
}

// derCut splits one element into its content octets and the octets that follow it.
func derCut(element []byte) (content []byte, rest []byte) {
	if len(element) < 2 || element[0]&0x1F == 0x1F || element[1] == 0x80 {
		broken("derCut: unsupported element")
	}
	length, offset := int(element[1]), 2
	if element[1]&0x80 != 0 {
		count := int(element[1] & 0x7F)
		length = 0
		for i := 0; i < count; i++ {
			length = length<<8 | int(element[2+i])
		}
		offset = 2 + count
	}
	if length > len(element)-offset {
		broken("derCut: element is truncated")
	}
	return element[offset : offset+length], element[offset+length:]
}

// derElements returns the elements of a constructed value.
func derElements(constructed []byte) [][]byte {
	content, _ := derCut(constructed)
	var elements [][]byte
	for len(content) > 0 {
		_, rest := derCut(content)
		elements = append(elements, content[:len(content)-len(rest)])
		content = rest
	}
	return elements
}

var (
	// ed25519OID is 1.3.101.112.
	ed25519OID = []byte{0x06, 0x03, 0x2B, 0x65, 0x70}
	// ed25519Algorithm is "SEQUENCE { OID 1.3.101.112 }": the identifier that RFC 8410
	// prescribes for Ed25519, without parameters.
	ed25519Algorithm = derTLV(0x30, ed25519OID)
	// ed25519WithNull is the same identifier with a NULL parameter.
	ed25519WithNull = derTLV(0x30, ed25519OID, []byte{0x05, 0x00})
	// ecdsaWithSHA256 is the AlgorithmIdentifier of ecdsa-with-SHA256 (1.2.840.10045.4.3.2).
	ecdsaWithSHA256 = derTLV(0x30, []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02},
		[]byte{0x05, 0x00})
)

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

// createCert builds a certificate with x509.CreateCertificate: public is the subject key and
// signer signs.
func createCert(template *x509.Certificate, parent *x509.Certificate, public any, signer crypto.Signer) []byte {
	der, err := x509.CreateCertificate(&entropy{}, template, parent, public, signer)
	check(err)
	return der
}

// newRoot creates a self-signed Ed25519 CA and returns the parsed certificate.
func newRoot(key ed25519.PrivateKey, name string, serial int64) *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             utc(2020, 1, 1),
		NotAfter:              utc(2040, 1, 1),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          keyID(key.Public()),
	}
	certificate, err := x509.ParseCertificate(createCert(template, template, key.Public(), key))
	check(err)
	return certificate
}

// newIntermediate creates an Ed25519 CA certificate for public, signed by the owner of
// parent with signer.
func newIntermediate(serial int64, name string, notBefore, notAfter time.Time, public any,
	parent *x509.Certificate, signer ed25519.PrivateKey) []byte {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		SubjectKeyId:          keyID(public),
		AuthorityKeyId:        parent.SubjectKeyId,
	}
	return createCert(template, parent, public, signer)
}

// newEndEntity creates a non-CA certificate for public, signed by the owner of parent with
// signer.
func newEndEntity(serial int64, name string, notBefore, notAfter time.Time, public any,
	parent *x509.Certificate, signer ed25519.PrivateKey) []byte {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		SubjectKeyId:          keyID(public),
		AuthorityKeyId:        parent.SubjectKeyId,
	}
	return createCert(template, parent, public, signer)
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

// marshalJson serialises a value the way the server does: sorted keys, no indentation.
func marshalJson(value any) []byte {
	encoded, err := json.Marshal(value)
	check(err)
	return encoded
}

// validPayload is the payload of a valid token: issued one hour before kFixedNow and valid
// for seven days.
func validPayload() map[string]any {
	return map[string]any{
		"group":  "default",
		"serial": 42,
		"iat":    kFixedNow - 3600,
		"exp":    kFixedNow + 7*graceSeconds,
		"config": map[string]any{
			"server":                   "udp://192.0.2.10:53",
			"heartbeat_interval":       1800,
			"detect":                   true,
			"illegal_adapter_keywords": []string{"vpn", "tap"},
		},
	}
}

// signJwt serialises a header and a payload with base64url without padding and appends the
// Ed25519 signature by signer over the text "header.payload".
func signJwt(header, payload map[string]any, signer ed25519.PrivateKey) string {
	encode := func(value any) string {
		return base64.RawURLEncoding.EncodeToString(marshalJson(value))
	}
	signingInput := encode(header) + "." + encode(payload)
	signature := ed25519.Sign(signer, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// buildJwt assembles a token the way the server does: a header with alg, typ, kid and x5c,
// and a payload. x5c == nil leaves the certificate chain and the kid out of the header.
func buildJwt(x5c []string, alg string, payload map[string]any, signer ed25519.PrivateKey) string {
	header := map[string]any{"alg": alg, "typ": "JWT"}
	if x5c != nil {
		header["x5c"] = x5c
		header["kid"] = "ifw-config-ca-1"
	}
	return signJwt(header, payload, signer)
}

// checkSignature fails when token is not signed by public.
func checkSignature(token string, public ed25519.PublicKey, what string) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		broken(what + ": the token does not have three segments")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	check(err)
	if !ed25519.Verify(public, []byte(parts[0]+"."+parts[1]), signature) {
		broken(what + ": the signature does not verify")
	}
}

// tamperSerial changes one byte of the decoded payload, "serial":42 becomes "serial":43, and
// keeps the signature. The token stays well-formed and fails rule R6 only.
func tamperSerial(token string) string {
	parts := strings.Split(token, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	check(err)
	if !bytes.Contains(payload, []byte(`"serial":42`)) {
		broken(`tamperSerial: the payload does not contain "serial":42`)
	}
	parts[1] = base64.RawURLEncoding.EncodeToString(
		bytes.Replace(payload, []byte(`"serial":42`), []byte(`"serial":43`), 1))
	return strings.Join(parts, ".")
}

// jwtVector is one token of the include file.
type jwtVector struct {
	name    string            // C++ constant
	comment string            // names the case and the rule it violates
	token   string            // the token
	signer  ed25519.PublicKey // nil: the signature is not checked
}

// ---------------------------------------------------------------------------
// The include file
// ---------------------------------------------------------------------------

// emitComment writes comment lines of at most 96 columns.
func emitComment(out *bytes.Buffer, text string) {
	line := "//"
	for _, word := range strings.Fields(text) {
		if len(line)+1+len(word) > 96 {
			out.WriteString(line + "\n")
			line = "//"
		}
		line += " " + word
	}
	out.WriteString(line + "\n")
}

// emitSection writes the title of a section.
func emitSection(out *bytes.Buffer, title string) {
	rule := strings.Repeat("-", 77)
	out.WriteString("// " + rule + "\n// " + title + "\n// " + rule + "\n\n")
}

// emitBytes writes a byte array as hex. With a size greater than zero the array is declared
// with that exact length, so the compiler checks the generator.
func emitBytes(out *bytes.Buffer, name, comment string, data []byte, fixedSize int) {
	if fixedSize > 0 && len(data) != fixedSize {
		broken(name + ": the array does not have the declared length")
	}
	emitComment(out, comment)
	if fixedSize > 0 {
		fmt.Fprintf(out, "static const uint8_t %s[%d] = {\n", name, fixedSize)
	} else {
		fmt.Fprintf(out, "static const uint8_t %s[] = {\n", name)
	}
	for i := 0; i < len(data); i += 12 {
		out.WriteString("    ")
		for j := i; j < i+12 && j < len(data); j++ {
			if j > i {
				out.WriteString(", ")
			}
			fmt.Fprintf(out, "0x%02X", data[j])
		}
		// The comma after the last byte of an array is legal in C++, so every line ends the same way.
		out.WriteString(",\n")
	}
	out.WriteString("};\n\n")
}

// emitInt writes an int64_t constant.
func emitInt(out *bytes.Buffer, name, comment string, value int64) {
	emitComment(out, comment)
	fmt.Fprintf(out, "static const int64_t %s = %d;\n\n", name, value)
}

// cppChar escapes one byte of a C string literal.
func cppChar(c byte) string {
	switch c {
	case '"':
		return `\"`
	case '\\':
		return `\\`
	case '?':
		return `\?` // no trigraph can form across the literal
	}
	if c < 0x20 || c > 0x7E {
		return fmt.Sprintf("\\%03o", c) // octal: a hex escape would swallow the next digit
	}
	return string(c)
}

// emitString writes text as a C string literal whose lines have at most 96 columns.
func emitString(out *bytes.Buffer, name, comment, text string) {
	emitComment(out, comment)
	fmt.Fprintf(out, "static const char %s[] =\n", name)
	out.WriteString("    \"")
	length := 5 // four spaces and the opening quote
	for i := 0; i < len(text); i++ {
		token := cppChar(text[i])
		if length+len(token)+1 > 96 {
			out.WriteString("\"\n    \"")
			length = 5
		}
		out.WriteString(token)
		length += len(token)
	}
	out.WriteString("\";\n\n")
}

func main() {
	if time.Unix(kFixedNow, 0).UTC().Format(time.RFC3339) != "2027-01-15T08:00:00Z" {
		broken("kFixedNow is not 2027-01-15T08:00:00Z")
	}

	// Keys.
	rootKey := edKey("root")
	otherRootKey := edKey("other-root")
	interKey := edKey("intermediate")
	expiredKey := edKey("expired-intermediate")
	notYetValidKey := edKey("not-yet-valid-intermediate")
	forgedKey := edKey("forged-intermediate")
	generalizedKey := edKey("generalized-time-intermediate")
	strangerKey := edKey("stranger")
	ecdsaKey := p256Key("ecdsa-p256")

	rootPublic := rootKey.Public().(ed25519.PublicKey)
	otherRootPublic := otherRootKey.Public().(ed25519.PublicKey)
	interPublic := interKey.Public().(ed25519.PublicKey)
	expiredPublic := expiredKey.Public().(ed25519.PublicKey)
	notYetValidPublic := notYetValidKey.Public().(ed25519.PublicKey)
	forgedPublic := forgedKey.Public().(ed25519.PublicKey)
	strangerPublic := strangerKey.Public().(ed25519.PublicKey)

	root := newRoot(rootKey, "cpl-test-root", 0x0100)
	otherRoot := newRoot(otherRootKey, "cpl-test-other-root", 0x0101)

	// Certificates built with x509.CreateCertificate.
	windowStart, windowEnd := utc(2026, 6, 1), utc(2028, 6, 1)
	validDer := newIntermediate(0x1000, "cpl-test-valid-intermediate", windowStart, windowEnd,
		interPublic, root, rootKey)
	expiredStart, expiredEnd := utc(2020, 1, 1), utc(2021, 1, 1)
	expiredDer := newIntermediate(0x1001, "cpl-test-expired-intermediate", expiredStart, expiredEnd,
		expiredPublic, root, rootKey)
	notYetValidStart, notYetValidEnd := utc(2027, 2, 1), windowEnd
	notYetValidDer := newIntermediate(0x1002, "cpl-test-not-yet-valid-intermediate", notYetValidStart,
		notYetValidEnd, notYetValidPublic, root, rootKey)
	forgedDer := newIntermediate(0x1003, "cpl-test-forged-intermediate", windowStart, windowEnd,
		forgedPublic, otherRoot, otherRootKey)
	generalizedStart, generalizedEnd := utc(2049, 6, 1), utc(2055, 6, 1)
	generalizedDer := newIntermediate(0x1004, "cpl-test-generalized-time-intermediate", generalizedStart,
		generalizedEnd, generalizedKey.Public(), root, rootKey)
	ecdsaDer := newEndEntity(0x1005, "cpl-test-ecdsa-end-entity", windowStart, windowEnd,
		&ecdsaKey.PublicKey, root, rootKey)

	// Certificates rebuilt by hand around the valid intermediate: each one has exactly the
	// defect that its constant names. Where the defect does not touch the signature itself,
	// the root key signs the modified tbsCertificate again.
	validParts := derElements(validDer) // tbsCertificate, signatureAlgorithm, signatureValue
	tbsParts := derElements(validParts[0])
	if len(validParts) != 3 || len(tbsParts) != 8 {
		broken(fmt.Sprintf("unexpected shape of the intermediate: %d and %d elements", len(validParts), len(tbsParts)))
	}
	if !bytes.Equal(validParts[1], ed25519Algorithm) || !bytes.Equal(tbsParts[2], ed25519Algorithm) {
		broken("the hand-written Ed25519 identifier differs from the one that Go writes")
	}
	rebuild := func(parts [][]byte, algorithm []byte) []byte {
		tbs := derTLV(0x30, parts...)
		return derTLV(0x30, tbs, algorithm, derBitString(0, ed25519.Sign(rootKey, tbs)))
	}
	withTbsPart := func(position int, element []byte) [][]byte {
		parts := append([][]byte{}, tbsParts...)
		parts[position] = element
		return parts
	}
	outerAlgMismatchDer := derTLV(0x30, validParts[0], ecdsaWithSHA256, validParts[2])
	tbsAlgMismatchDer := rebuild(withTbsPart(2, ecdsaWithSHA256), ed25519Algorithm)
	nullParamsDer := rebuild(withTbsPart(2, ed25519WithNull), ed25519WithNull)
	unusedBitsSigDer := derTLV(0x30, validParts[0], validParts[1],
		derBitString(1, ed25519.Sign(rootKey, validParts[0])))
	trimmedKey := append([]byte{}, interPublic...)
	trimmedKey[len(trimmedKey)-1] &= 0xF0 // the four bits that become unused are zero
	unusedBitsKeyDer := rebuild(withTbsPart(6, derTLV(0x30, ed25519Algorithm, derBitString(4, trimmedKey))),
		ed25519Algorithm)
	longKey := append(append([]byte{}, interPublic...), 0x00)
	longKeyDer := rebuild(withTbsPart(6, derTLV(0x30, ed25519Algorithm, derBitString(0, longKey))),
		ed25519Algorithm)

	// Self-checks of the certificates.
	validCertificate, err := x509.ParseCertificate(validDer)
	check(err)
	check(validCertificate.CheckSignatureFrom(root))
	if !validCertificate.NotBefore.Equal(windowStart) || !validCertificate.NotAfter.Equal(windowEnd) {
		broken("the validity window of the intermediate differs from its template")
	}
	expiredCertificate, err := x509.ParseCertificate(expiredDer)
	check(err)
	check(expiredCertificate.CheckSignatureFrom(root))
	notYetValidCertificate, err := x509.ParseCertificate(notYetValidDer)
	check(err)
	check(notYetValidCertificate.CheckSignatureFrom(root))
	forgedCertificate, err := x509.ParseCertificate(forgedDer)
	check(err)
	check(forgedCertificate.CheckSignatureFrom(otherRoot))
	if forgedCertificate.CheckSignatureFrom(root) == nil {
		broken("the forged intermediate verifies under the root")
	}
	generalizedCertificate, err := x509.ParseCertificate(generalizedDer)
	check(err)
	check(generalizedCertificate.CheckSignatureFrom(root))
	ecdsaCertificate, err := x509.ParseCertificate(ecdsaDer)
	check(err)
	check(ecdsaCertificate.CheckSignatureFrom(root))
	if ecdsaCertificate.PublicKeyAlgorithm != x509.ECDSA {
		broken("the wrong-algorithm certificate does not carry an ECDSA key")
	}

	// Self-checks of the time rules: the windows must lie where the comments say.
	if validCertificate.NotBefore.Unix() > kFixedNow || validCertificate.NotAfter.Unix() < kFixedNow {
		broken("kFixedNow is outside the window of the valid intermediate")
	}
	if expiredCertificate.NotAfter.Unix() >= kFixedNow {
		broken("the expired intermediate is not expired at kFixedNow")
	}
	if notYetValidCertificate.NotBefore.Unix()-graceSeconds <= kFixedNow {
		broken("the not yet valid intermediate is within one day of kFixedNow")
	}

	// Tokens.
	x5c := func(certificate []byte) []string {
		return []string{base64.RawURLEncoding.EncodeToString(certificate)}
	}
	validJwt := buildJwt(x5c(validDer), "EdDSA", validPayload(), interKey)
	tamperedJwt := tamperSerial(validJwt)
	expiredPayload := validPayload()
	expiredPayload["exp"] = kFixedNow - 1
	notYetValidPayload := validPayload()
	notYetValidPayload["iat"] = kFixedNow + graceSeconds + 1
	noConfigPayload := validPayload()
	delete(noConfigPayload, "config")
	// The header keeps the certificate chain: the rules need it, and only the members that the
	// rules do not mention are extra.
	extraHeader := map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": "ifw-config-ca-1", "x5c": x5c(validDer), "jwk": map[string]any{"kty": "OKP"}}
	extraPayload := validPayload()
	extraPayload["to"] = "00"
	extraPayload["nested"] = map[string]any{"list": []any{1, "two", false}}
	truncatedDer := validDer[:len(validDer)-1]
	garbageDer := append(append([]byte{}, validDer...), 0x00)

	tokens := []jwtVector{
		{name: "kValidJwt", comment: "Valid token: signed by the key of kValidCert, issued one hour before kFixedNow and valid for seven days. Passes every rule.", token: validJwt, signer: interPublic},
		{name: "kExpiredJwt", comment: "Expired token: exp is one second before kFixedNow. Fails R8.", token: buildJwt(x5c(validDer), "EdDSA", expiredPayload, interKey), signer: interPublic},
		{name: "kNotYetValidJwt", comment: "Token from the future: iat is one day and one second after kFixedNow. Fails R8.", token: buildJwt(x5c(validDer), "EdDSA", notYetValidPayload, interKey), signer: interPublic},
		{name: "kTamperedJwt", comment: "Tampered token: one byte of the payload is changed (\"serial\":42 becomes 43) and the signature is kept. Fails R6.", token: tamperedJwt},
		{name: "kTwoCertsJwt", comment: "Token with two certificates in x5c. Fails R1.", token: buildJwt(append(x5c(validDer), x5c(expiredDer)...), "EdDSA", validPayload(), interKey), signer: interPublic},
		{name: "kHs256Jwt", comment: "Token whose header says alg HS256. Fails R1.", token: buildJwt(x5c(validDer), "HS256", validPayload(), interKey), signer: interPublic},
		{name: "kNoX5cJwt", comment: "Token whose header has no x5c. Fails R1.", token: buildJwt(nil, "EdDSA", validPayload(), interKey), signer: interPublic},
		{name: "kNoConfigJwt", comment: "Token whose payload has no config. Fails R1.", token: buildJwt(x5c(validDer), "EdDSA", noConfigPayload, interKey), signer: interPublic},
		{name: "kExtraMembersJwt", comment: "Valid token with members that the rules do not mention (jwk in the header, to and nested in the payload). Unknown members are ignored. Passes every rule.", token: signJwt(extraHeader, extraPayload, interKey), signer: interPublic},
		{name: "kFourSegmentsJwt", comment: "Valid token with a fourth segment appended. Fails R1.", token: validJwt + ".AAAA"},
		{name: "kWrongKeyJwt", comment: "Token signed by a key that is not the key of its certificate. Fails R6.", token: buildJwt(x5c(validDer), "EdDSA", validPayload(), strangerKey), signer: strangerPublic},
		{name: "kExpiredCertJwt", comment: "Token signed by the key of kExpiredCert. Fails R5, passes with SkipTime.", token: buildJwt(x5c(expiredDer), "EdDSA", validPayload(), expiredKey), signer: expiredPublic},
		{name: "kNotYetValidCertJwt", comment: "Token signed by the key of kNotYetValidCert. Fails R5, passes with SkipTime.", token: buildJwt(x5c(notYetValidDer), "EdDSA", validPayload(), notYetValidKey), signer: notYetValidPublic},
		{name: "kForgedCertJwt", comment: "Token signed by the key of kForgedCert. Fails R4.", token: buildJwt(x5c(forgedDer), "EdDSA", validPayload(), forgedKey), signer: forgedPublic},
		{name: "kEcdsaCertJwt", comment: "Token whose certificate carries an ECDSA P-256 key. Fails R3.", token: buildJwt(x5c(ecdsaDer), "EdDSA", validPayload(), interKey), signer: interPublic},
		{name: "kTbsAlgMismatchCertJwt", comment: "Token whose certificate declares ecdsa-with-SHA256 inside tbsCertificate. Fails R3.", token: buildJwt(x5c(tbsAlgMismatchDer), "EdDSA", validPayload(), interKey), signer: interPublic},
		{name: "kOuterAlgMismatchCertJwt", comment: "Token whose certificate declares ecdsa-with-SHA256 as outer signatureAlgorithm. Fails R3.", token: buildJwt(x5c(outerAlgMismatchDer), "EdDSA", validPayload(), interKey), signer: interPublic},
		{name: "kTruncatedCertJwt", comment: "Token whose certificate is kValidCert without its last byte. Fails R2.", token: buildJwt(x5c(truncatedDer), "EdDSA", validPayload(), interKey), signer: interPublic},
		{name: "kGarbageCertJwt", comment: "Token whose certificate is kValidCert followed by one extra byte. Fails R2.", token: buildJwt(x5c(garbageDer), "EdDSA", validPayload(), interKey), signer: interPublic},
	}
	for _, token := range tokens {
		if token.signer != nil {
			checkSignature(token.token, token.signer, token.name)
		}
	}
	// The tampered token keeps the signature of the valid token, which no longer verifies.
	tamperedParts := strings.Split(tamperedJwt, ".")
	tamperedSignature, err := base64.RawURLEncoding.DecodeString(tamperedParts[2])
	check(err)
	if ed25519.Verify(interPublic, []byte(tamperedParts[0]+"."+tamperedParts[1]), tamperedSignature) {
		broken("kTamperedJwt: the kept signature still verifies")
	}

	var out bytes.Buffer
	out.WriteString("// Generated by test/gen_cert_vectors.go - do not edit.\n" +
		"//\n" +
		"// Test vectors for test/test_cert.cpp (cpl::cert). Include the file inside an anonymous\n" +
		"// namespace.\n" +
		"//\n" +
		"// Every Ed25519 key is derived from a fixed seed, every certificate has a fixed serial\n" +
		"// number and a fixed validity window. kFixedNow is the time at which the tests verify the\n" +
		"// vectors (2027-01-15T08:00:00Z).\n" +
		"//\n" +
		"// k<Name>CertJwt is a token whose x5c carries k<Name>Cert. Unless its comment says otherwise,\n" +
		"// a token is signed by the key of the certificate it carries, so it violates the rule that\n" +
		"// its comment names and no other rule.\n\n")

	emitSection(&out, "Time and payload of the valid token")
	emitInt(&out, "kFixedNow", "Fixed verification time, 2027-01-15T08:00:00Z. Every window that has to pass R5 contains it.", kFixedNow)
	emitInt(&out, "kValidSerial", "serial of kValidJwt.", 42)
	emitInt(&out, "kValidIat", "iat of kValidJwt: one hour before kFixedNow.", kFixedNow-3600)
	emitInt(&out, "kValidExp", "exp of kValidJwt: seven days after kFixedNow.", kFixedNow+7*graceSeconds)
	emitString(&out, "kValidPayloadJson", "Decoded payload of kValidJwt.", string(marshalJson(validPayload())))

	emitSection(&out, "Keys")
	emitBytes(&out, "kRootPublicKey", "Root public key: the trust anchor that the agent embeds.", rootPublic, 32)
	emitBytes(&out, "kOtherRootPublicKey", "Public key of another root: kForgedCert chains to it, no valid vector does.", otherRootPublic, 32)
	emitBytes(&out, "kValidCertPublicKey", "Public key of kValidCert: the key that signs every well-formed token that carries it.", interPublic, 32)

	emitSection(&out, "Certificates")
	emitBytes(&out, "kValidCert", "Valid intermediate: an Ed25519 CA signed by the root, valid from 2026-06-01 to 2028-06-01.", validDer, 0)
	emitInt(&out, "kValidCertNotBefore", "notBefore of kValidCert (2026-06-01T00:00:00Z), Unix seconds.", validCertificate.NotBefore.Unix())
	emitInt(&out, "kValidCertNotAfter", "notAfter of kValidCert (2028-06-01T00:00:00Z), Unix seconds.", validCertificate.NotAfter.Unix())
	emitBytes(&out, "kExpiredCert", "Expired intermediate: signed by the root, valid from 2020-01-01 to 2021-01-01.", expiredDer, 0)
	emitInt(&out, "kExpiredCertNotBefore", "notBefore of kExpiredCert (2020-01-01T00:00:00Z), Unix seconds.", expiredCertificate.NotBefore.Unix())
	emitInt(&out, "kExpiredCertNotAfter", "notAfter of kExpiredCert (2021-01-01T00:00:00Z), Unix seconds.", expiredCertificate.NotAfter.Unix())
	emitBytes(&out, "kNotYetValidCert", "Intermediate whose window starts more than one day after kFixedNow: 2027-02-01 to 2028-06-01.", notYetValidDer, 0)
	emitInt(&out, "kNotYetValidCertNotBefore", "notBefore of kNotYetValidCert (2027-02-01T00:00:00Z), Unix seconds.", notYetValidCertificate.NotBefore.Unix())
	emitInt(&out, "kNotYetValidCertNotAfter", "notAfter of kNotYetValidCert (2028-06-01T00:00:00Z), Unix seconds.", notYetValidCertificate.NotAfter.Unix())
	emitBytes(&out, "kForgedCert", "Intermediate with the window of kValidCert, signed by the other root instead of kRootPublicKey. Fails R4.", forgedDer, 0)
	emitBytes(&out, "kEcdsaCert", "Certificate with an ECDSA P-256 key, signed by the root. Its signature algorithm is Ed25519, its key is not. Fails R3.", ecdsaDer, 0)
	emitBytes(&out, "kGeneralizedTimeCert", "Intermediate whose window ends in 2055, so Go writes GeneralizedTime instead of UTCTime: 2049-06-01 to 2055-06-01. Parses like kValidCert.", generalizedDer, 0)
	emitInt(&out, "kGeneralizedTimeCertNotBefore", "notBefore of kGeneralizedTimeCert (2049-06-01T00:00:00Z), Unix seconds.", generalizedCertificate.NotBefore.Unix())
	emitInt(&out, "kGeneralizedTimeCertNotAfter", "notAfter of kGeneralizedTimeCert (2055-06-01T00:00:00Z), Unix seconds.", generalizedCertificate.NotAfter.Unix())
	emitBytes(&out, "kOuterAlgMismatchCert", "kValidCert rebuilt with ecdsa-with-SHA256 as outer signatureAlgorithm; tbsCertificate still says Ed25519. Fails R3.", outerAlgMismatchDer, 0)
	emitBytes(&out, "kTbsAlgMismatchCert", "kValidCert rebuilt with ecdsa-with-SHA256 inside tbsCertificate and signed again by the root. Fails R3.", tbsAlgMismatchDer, 0)
	emitBytes(&out, "kNullParamsAlgCert", "kValidCert rebuilt with a NULL parameter after the Ed25519 OID in both algorithm identifiers; signed again by the root. Fails R3.", nullParamsDer, 0)
	emitBytes(&out, "kUnusedBitsSigCert", "kValidCert rebuilt with one unused bit declared in the signatureValue BIT STRING. Fails R2.", unusedBitsSigDer, 0)
	emitBytes(&out, "kUnusedBitsKeyCert", "kValidCert rebuilt with four unused bits declared in the subject public key BIT STRING; signed again by the root. Fails R2.", unusedBitsKeyDer, 0)
	emitBytes(&out, "kLongKeyCert", "kValidCert rebuilt with a 33 byte subject public key; signed again by the root. Fails R2.", longKeyDer, 0)

	emitSection(&out, "Tokens")
	for _, token := range tokens {
		emitString(&out, token.name, token.comment, token.token)
	}

	_, _ = os.Stdout.Write(out.Bytes())
}
