package test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"naion"
)

const (
	testClientSeedHex = "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f"
	testServerSeedHex = "f0e1d2c3b4a5968778695a4b3c2d1e0fefdecdbcab9a89786756453423120100"
)

var testSizes = []int{1, 16, 64, 256, 512, 840}

func mustHex(t testing.TB, text string) []byte {
	t.Helper()
	out, err := hex.DecodeString(text)
	if err != nil {
		t.Fatalf("hex decode failed: %v", err)
	}
	return out
}

func testPayload(size int) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = byte((size*17 + i*29) & 0xFF)
	}
	return out
}

func newPair(t testing.TB) (*naion.Client, *naion.Server) {
	t.Helper()
	server, err := naion.NewServer(mustHex(t, testServerSeedHex))
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	client, err := naion.NewClient(mustHex(t, testClientSeedHex), server.EdPublicKey())
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	return client, server
}

func bootstrapServer(t testing.TB, client *naion.Client, server *naion.Server) {
	t.Helper()
	packet, err := client.Encrypt([]byte("bootstrap"))
	if err != nil {
		t.Fatalf("bootstrap client encrypt failed: %v", err)
	}
	if _, err := server.Decrypt(packet); err != nil {
		t.Fatalf("bootstrap server decrypt failed: %v", err)
	}
}

func TestGoLocalRoundTripSizes(t *testing.T) {
	for _, size := range testSizes {
		size := size
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			payload := testPayload(size)
			client, server := newPair(t)

			clientPacket, err := client.Encrypt(payload)
			if err != nil {
				t.Fatalf("client encrypt failed: %v", err)
			}
			serverPlain, err := server.Decrypt(clientPacket)
			if err != nil {
				t.Fatalf("server decrypt failed: %v", err)
			}
			if !bytes.Equal(serverPlain, payload) {
				t.Fatalf("client->server mismatch")
			}

			client, server = newPair(t)
			bootstrapServer(t, client, server)
			serverPacket, err := server.Encrypt(payload)
			if err != nil {
				t.Fatalf("server encrypt failed: %v", err)
			}
			clientPlain, err := client.Decrypt(serverPacket)
			if err != nil {
				t.Fatalf("client decrypt failed: %v", err)
			}
			if !bytes.Equal(clientPlain, payload) {
				t.Fatalf("server->client mismatch")
			}
		})
	}
}

func BenchmarkGoClientEncrypt(b *testing.B) {
	for _, size := range testSizes {
		size := size
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			payload := testPayload(size)
			client, _ := newPair(b)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := client.Encrypt(payload); err != nil {
					b.Fatalf("client encrypt failed: %v", err)
				}
			}
		})
	}
}

func BenchmarkGoServerDecrypt(b *testing.B) {
	for _, size := range testSizes {
		size := size
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			payload := testPayload(size)
			client, _ := newPair(b)
			packet, err := client.Encrypt(payload)
			if err != nil {
				b.Fatalf("prepare client packet failed: %v", err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, server := newPair(b)
				if _, err := server.Decrypt(packet); err != nil {
					b.Fatalf("server decrypt failed: %v", err)
				}
			}
		})
	}
}

func BenchmarkGoServerEncrypt(b *testing.B) {
	for _, size := range testSizes {
		size := size
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			payload := testPayload(size)
			client, server := newPair(b)
			bootstrapServer(b, client, server)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := server.Encrypt(payload); err != nil {
					b.Fatalf("server encrypt failed: %v", err)
				}
			}
		})
	}
}

func BenchmarkGoClientDecrypt(b *testing.B) {
	for _, size := range testSizes {
		size := size
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			payload := testPayload(size)
			client, server := newPair(b)
			bootstrapServer(b, client, server)
			packet, err := server.Encrypt(payload)
			if err != nil {
				b.Fatalf("prepare server packet failed: %v", err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := client.Decrypt(packet); err != nil {
					b.Fatalf("client decrypt failed: %v", err)
				}
			}
		})
	}
}
