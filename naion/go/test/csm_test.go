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

func seed32(t testing.TB, hexStr string) [32]byte {
	t.Helper()
	raw := mustHex(t, hexStr)
	if len(raw) != 32 {
		t.Fatalf("seed must be 32 bytes, got %d", len(raw))
	}
	var s [32]byte
	copy(s[:], raw)
	return s
}

func testPayload(size int) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = byte((size*17 + i*29) & 0xFF)
	}
	return out
}

func newPair(t testing.TB) (*naion.CSMClient, *naion.CSMServer) {
	t.Helper()
	ss := seed32(t, testServerSeedHex)
	server, rc := naion.CSMServerCreate(&ss)
	if rc != naion.CSMOK {
		t.Fatalf("CSMServerCreate failed: %v", rc)
	}
	cs := seed32(t, testClientSeedHex)
	spk := server.EdPublicKey
	client, rc := naion.CSMClientCreate(&cs, &spk)
	if rc != naion.CSMOK {
		t.Fatalf("CSMClientCreate failed: %v", rc)
	}
	return client, server
}

func bootstrapServer(t testing.TB, client *naion.CSMClient, server *naion.CSMServer) {
	t.Helper()
	packet, rc := client.Encrypt([]byte("bootstrap"))
	if rc != naion.CSMOK {
		t.Fatalf("bootstrap client encrypt failed: %v", rc)
	}
	if _, rc := server.Decrypt(packet); rc != naion.CSMOK {
		t.Fatalf("bootstrap server decrypt failed: %v", rc)
	}
}

func TestGoLocalRoundTripSizes(t *testing.T) {
	for _, size := range testSizes {
		size := size
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			payload := testPayload(size)
			client, server := newPair(t)

			clientPacket, rc := client.Encrypt(payload)
			if rc != naion.CSMOK {
				t.Fatalf("client encrypt failed: %v", rc)
			}
			serverPlain, rc := server.Decrypt(clientPacket)
			if rc != naion.CSMOK {
				t.Fatalf("server decrypt failed: %v", rc)
			}
			if !bytes.Equal(serverPlain, payload) {
				t.Fatalf("client->server mismatch")
			}

			client, server = newPair(t)
			bootstrapServer(t, client, server)
			serverPacket, rc := server.Encrypt(payload)
			if rc != naion.CSMOK {
				t.Fatalf("server encrypt failed: %v", rc)
			}
			clientPlain, rc := client.Decrypt(serverPacket)
			if rc != naion.CSMOK {
				t.Fatalf("client decrypt failed: %v", rc)
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
				if _, rc := client.Encrypt(payload); rc != naion.CSMOK {
					b.Fatalf("client encrypt failed: %v", rc)
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
			packet, rc := client.Encrypt(payload)
			if rc != naion.CSMOK {
				b.Fatalf("prepare client packet failed: %v", rc)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, server := newPair(b)
				if _, rc := server.Decrypt(packet); rc != naion.CSMOK {
					b.Fatalf("server decrypt failed: %v", rc)
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
				if _, rc := server.Encrypt(payload); rc != naion.CSMOK {
					b.Fatalf("server encrypt failed: %v", rc)
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
			packet, rc := server.Encrypt(payload)
			if rc != naion.CSMOK {
				b.Fatalf("prepare server packet failed: %v", rc)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, rc := client.Decrypt(packet); rc != naion.CSMOK {
					b.Fatalf("client decrypt failed: %v", rc)
				}
			}
		})
	}
}
