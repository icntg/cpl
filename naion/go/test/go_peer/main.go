package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"naion"
)

type result struct {
	OK           bool   `json:"ok"`
	ElapsedNS    int64  `json:"elapsed_ns"`
	Repeat       int    `json:"repeat"`
	PacketB64    string `json:"packet_b64,omitempty"`
	PlaintextB64 string `json:"plaintext_b64,omitempty"`
}

func decodeHex(name string, value string) []byte {
	out, err := hex.DecodeString(value)
	if err != nil {
		log.Fatalf("%s hex decode failed: %v", name, err)
	}
	return out
}

func decodeB64(name string, value string) []byte {
	out, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		log.Fatalf("%s base64 decode failed: %v", name, err)
	}
	return out
}

func encodeB64(value []byte) string {
	return base64.StdEncoding.EncodeToString(value)
}

func seed32(name string, value string) [32]byte {
	raw := decodeHex(name, value)
	if len(raw) != 32 {
		log.Fatalf("%s must be 32 bytes, got %d", name, len(raw))
	}
	var s [32]byte
	copy(s[:], raw)
	return s
}

func newClientAndServer(clientSeedHex string, serverSeedHex string) (*naion.CSMClient, *naion.CSMServer) {
	ss := seed32("server-seed", serverSeedHex)
	server, rc := naion.CSMServerCreate(&ss)
	if rc != naion.CSMOK {
		log.Fatalf("CSMServerCreate failed: %v", rc)
	}
	cs := seed32("client-seed", clientSeedHex)
	spk := server.EdPublicKey
	client, rc := naion.CSMClientCreate(&cs, &spk)
	if rc != naion.CSMOK {
		log.Fatalf("CSMClientCreate failed: %v", rc)
	}
	return client, server
}

func emit(v result) {
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(v); err != nil {
		log.Fatalf("json encode failed: %v", err)
	}
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("usage: %s <client-encrypt|server-decrypt|server-encrypt|client-decrypt> [flags]", os.Args[0])
	}

	op := os.Args[1]
	fs := flag.NewFlagSet(op, flag.ExitOnError)
	clientSeedHex := fs.String("client-seed", "", "client Ed25519 seed hex")
	serverSeedHex := fs.String("server-seed", "", "server Ed25519 seed hex")
	payloadB64 := fs.String("payload-b64", "", "payload base64")
	packetB64 := fs.String("packet-b64", "", "packet base64")
	bootstrapPacketB64 := fs.String("bootstrap-packet-b64", "", "bootstrap packet base64")
	repeat := fs.Int("repeat", 1, "repeat count for timing")
	sleepBeforeDecryptMS := fs.Int("sleep-before-decrypt-ms", 0, "sleep before decrypt in milliseconds")
	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatal(err)
	}
	if *clientSeedHex == "" || *serverSeedHex == "" {
		log.Fatal("client-seed and server-seed are required")
	}
	if *repeat < 1 {
		log.Fatal("repeat must be >= 1")
	}

	client, server := newClientAndServer(*clientSeedHex, *serverSeedHex)

	switch op {
	case "client-encrypt":
		payload := decodeB64("payload-b64", *payloadB64)
		begin := time.Now()
		var packet []byte
		for i := 0; i < *repeat; i++ {
			p, rc := client.Encrypt(payload)
			if rc != naion.CSMOK {
				log.Fatalf("client encrypt failed: %v", rc)
			}
			packet = p
		}
		elapsed := time.Since(begin).Nanoseconds()
		emit(result{OK: true, ElapsedNS: elapsed, Repeat: *repeat, PacketB64: encodeB64(packet)})
	case "server-decrypt":
		packet := decodeB64("packet-b64", *packetB64)
		if *sleepBeforeDecryptMS > 0 {
			time.Sleep(time.Duration(*sleepBeforeDecryptMS) * time.Millisecond)
		}
		begin := time.Now()
		var plaintext []byte
		for i := 0; i < *repeat; i++ {
			pt, rc := server.Decrypt(packet)
			if rc != naion.CSMOK {
				log.Fatalf("server decrypt failed: %v", rc)
			}
			plaintext = pt
		}
		elapsed := time.Since(begin).Nanoseconds()
		emit(result{OK: true, ElapsedNS: elapsed, Repeat: *repeat, PlaintextB64: encodeB64(plaintext)})
	case "server-encrypt":
		bootstrapPacket := decodeB64("bootstrap-packet-b64", *bootstrapPacketB64)
		if _, rc := server.Decrypt(bootstrapPacket); rc != naion.CSMOK {
			log.Fatalf("bootstrap decrypt failed: %v", rc)
		}
		payload := decodeB64("payload-b64", *payloadB64)
		begin := time.Now()
		var packet []byte
		for i := 0; i < *repeat; i++ {
			p, rc := server.Encrypt(payload)
			if rc != naion.CSMOK {
				log.Fatalf("server encrypt failed: %v", rc)
			}
			packet = p
		}
		elapsed := time.Since(begin).Nanoseconds()
		emit(result{OK: true, ElapsedNS: elapsed, Repeat: *repeat, PacketB64: encodeB64(packet)})
	case "client-decrypt":
		packet := decodeB64("packet-b64", *packetB64)
		begin := time.Now()
		var plaintext []byte
		for i := 0; i < *repeat; i++ {
			pt, rc := client.Decrypt(packet)
			if rc != naion.CSMOK {
				log.Fatalf("client decrypt failed: %v", rc)
			}
			plaintext = pt
		}
		elapsed := time.Since(begin).Nanoseconds()
		emit(result{OK: true, ElapsedNS: elapsed, Repeat: *repeat, PlaintextB64: encodeB64(plaintext)})
	default:
		log.Fatalf("unknown op: %s", fmt.Sprintf("%q", op))
	}
}
