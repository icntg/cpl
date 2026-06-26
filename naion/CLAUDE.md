# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

**Naion** (钠离子) is a simplified, standalone reimplementation of libsodium's core cryptographic APIs. It is a single-header, STB-style C library with zero external dependencies — all primitives are implemented portably within the header.

**CSM** (Client-Server Model) is a secure messaging layer built on naion, providing identity-bound, encrypted, signed packets for client/server communication over UDP (max 1024-byte datagrams). CSM and its CA-handshake variant (CSM-CA) now live **inside** `naion.h` as Layer 3 and Layer 4.

This directory is a subdirectory within the larger `icntg/cpl` monorepo.

## Build & Usage

There is no build system. The library follows the STB single-header pattern:

```c
// In exactly one .c file:
#define NAION_IMPLEMENTATION
#include "naion.h"
```

All other translation units simply `#include "naion.h"` without the `#define`.

Compile with any C99 or C++ compiler. No special flags required. Example:

```bash
gcc -o myapp myapp.c naion.c
```

The legacy `csm.h`/`csm.c` have been **removed** — their functionality was merged into `naion.h`. Code that used CSM should switch from `csm_*` symbols to `naion_csm_*` and `#include "naion.h"`.

## Four-layer, tailorable architecture

Naion is organised into four progressively-built layers plus an optional XSalsa20 family. Layers are controlled by macros that must be defined **before** `#include "naion.h"`; all default to ON, and any upper layer implicitly enables everything it depends on.

```
Layer 1 (NAION_LAYER_SYMM)     — XChaCha20 stream + BLAKE2b hash + RNG
    ↓ depends on
Layer 2 (NAION_LAYER_AEAD)     — XChaCha20-Poly1305 AEAD-IETF + secretbox
                                  + box symmetric core (*_easy_afternm)
    ↓ depends on
Layer 3 (NAION_LAYER_CSM)      — X25519/KX + asymmetric box + Ed25519 + CSM
    ↓ depends on
Layer 4 (NAION_LAYER_CSM_CA)   — CSM + CA-certificate handshake
```

Independent of the layers:

```
NAION_XSALSA20 (default 0)     — Salsa20 core + XSalsa20 secretbox/box
                                  + runtime gUseXChaCha20 dispatch
```

Build matrix (each compiles standalone):

| Config | Flags |
|---|---|
| Layer 1 only | `-DNAION_LAYER_AEAD=0 -DNAION_LAYER_CSM=0 -DNAION_LAYER_CSM_CA=0` |
| Layer 1+2 | `-DNAION_LAYER_CSM=0 -DNAION_LAYER_CSM_CA=0` |
| Layer 1-3 | `-DNAION_LAYER_CSM_CA=0` |
| Layer 1-4 (default) | *(none)* |
| Layer 1-4 + XSalsa20 | `-DNAION_XSALSA20=1` |

**XSalsa20 default change:** XSalsa20/Salsa20 is no longer compiled by default (`NAION_XSALSA20=0`). The generic `naion_box_*` dispatch family then delegates directly to the XChaCha20 variants with no runtime overhead, and `gUseXChaCha20` collapses to a compile-time constant 1. Request XSalsa20 explicitly with `-DNAION_XSALSA20=1` when interop with the XSalsa20 wire format is required.

### Module map

| Module | API Prefix | Layer |
|---|---|---|
| BLAKE2b | `naion_generichash_*` | L1 |
| XChaCha20 stream | `naion_stream_xchacha20_*` | L1 |
| Randomness | `naion_set/get_random_provider`, `naion_init` | L1 |
| XChaCha20-Poly1305 IETF | `naion_aead_xchacha20poly1305_ietf_*` | L2 |
| secretbox (XChaCha20) | `naion_secretbox_xchacha20poly1305_*` | L2 |
| Box symmetric core | `naion_box_curve25519xchacha20poly1305_*_afternm` | L2 |
| X25519 / KX | `naion_scalarmult_*`, `naion_kx_*` | L3 |
| Box (asymmetric) | `naion_box_curve25519xchacha20poly1305_*` (keypair/beforenm/easy/seal), `naion_box_*` | L3 |
| Ed25519 | `naion_sign_ed25519_*` | L3 |
| CSM | `naion_csm_*` | L3 |
| CSM-CA | `naion_csm_ca_*` | L4 |
| XSalsa20 (optional) | `naion_secretbox_xsalsa20poly1305_*`, `naion_box_curve25519xsalsa20poly1305_*` | NAION_XSALSA20 |

**Key note on the box split:** the `*_easy_afternm` / `*_open_easy_afternm` entry points are pure symmetric AEAD (precomputed key + nonce, no Curve25519). secretbox delegates to them, so they live at Layer 2. The asymmetric box wrappers (`keypair`, `beforenm`, `easy`, `seal`) add X25519 key agreement and live at Layer 3.

**Key conversion:** `naion_sign_ed25519_pk_to_curve25519` and `naion_sign_ed25519_sk_to_curve25519` convert Ed25519 keys to X25519 keys — critical for protocols that use Ed25519 for identity but X25519 for key exchange (CSM does exactly this).

**Randomness:** Callers may plug in a custom RNG via `naion_set_random_provider()`. The built-in fallback uses `CryptGenRandom` on Windows, `getrandom()` on Linux, and `/dev/urandom` on other POSIX.

**Optional libsodium compat:** Defining `NAION_ENABLE_SODIUM_COMPAT_NAMES` before include creates `#define` aliases (`sodium_init` → `naion_init`, etc.). Disabled by default to avoid symbol collisions.

## CSM — client/server secure messaging

CSM is now part of `naion.h` (Layer 3). See `PROTOCOL.md` for the full specification.

**Packet layout (fixed outer structure):**
```
signature(64) | session_x25519_public_key(32) | nonce(24) | mac(16) | ciphertext(variable)
```
Fixed overhead: 136 bytes. Max UDP datagram: 1024 bytes.

**Directional asymmetry:**
- Client → Server plaintext: `client_ed25519_public_key(32) || application_payload` (max payload: 856 bytes)
- Server → Client plaintext: `application_payload` only (max payload: 888 bytes)

The server learns the client's public key from the first successfully decrypted packet — no pre-sharing of client keys.

**Crypto flow:** Ed25519 detached signatures for authentication, X25519 ephemeral-static DH for key agreement, HChaCha20 for key derivation, XChaCha20-Poly1305-IETF for AEAD encryption (with the session X25519 public key as AAD).

**API prefix:** `naion_csm_*` (renamed from the former `csm_*`).

**Error codes:** `NAION_CSM_OK` (0), negative values for `NAION_CSM_ERR_INVALID_ARGUMENT`, `NAION_CSM_ERR_BUFFER_TOO_SMALL`, `NAION_CSM_ERR_CRYPTO`, `NAION_CSM_ERR_VERIFY_FAILED`, `NAION_CSM_ERR_STATE`, `NAION_CSM_ERR_RANDOM_PROVIDER`, `NAION_CSM_ERR_NO_DATA`.

**Heap allocation:** CSM encrypt/decrypt `malloc` a small scratch buffer. These functions use a unified `goto` cleanup pattern (`__ERROR__` zeroes sensitive material on failure, `__FREE__` releases every resource) with a single return statement per function.

## CSM-CA — CA-certificate handshake (Layer 4)

When the client cannot be preloaded with the server's public key, it carries only a built-in CA public key. The server presents a 96-byte certificate `server_ed_pk(32) || ca_signature(64)`; the client verifies the signature against the CA key, stores the server key, then communicates using the Layer 3 CSM packet format. See `PROTOCOL.md` → "CA 握手".

API prefix: `naion_csm_ca_*`.

### Implementation Internals

All cryptographic primitives in naion.h are **portable C** (no assembly, no SIMD intrinsics):
- **BLAKE2b**: Reference implementation from RFC 7693
- **SHA-512**: Minimal implementation used only for Ed25519 → X25519 secret key conversion
- **X25519**: Based on TweetNaCl primitives (field arithmetic over Curve25519)
- **Ed25519**: Deterministic, using TweetNaCl-style formulas (ref10)
- **ChaCha20 / HChaCha20 / XChaCha20**: Standard implementation
- **Salsa20 / HSalsa20 / XSalsa20**: Built only when `NAION_XSALSA20=1`
- **Poly1305**: Standard implementation, combined with ChaCha20 for AEAD

Internal helpers use `_naion_` / `naion_csm_internal_` prefixes and are `static` — they do not leak into the linkable symbol table.

## Cross-Language Consistency

The CSM protocol has implementations in three languages that must remain compatible:
- `naion.h` (C — this repo)
- `csm.py` (Python — not present in this directory)
- `csm.go` (Go — not present in this directory)

All three must maintain identical packet layout, AEAD associated data, detached signature coverage, and UDP size budget. Changes to the protocol must be reflected across all implementations.

## Platform Support

- **Windows**: CryptGenRandom for entropy, `<windows.h>` + `<wincrypt.h>`
- **Linux**: `getrandom()` syscall (via `<sys/syscall.h>`)
- **Other POSIX**: `/dev/urandom` fallback (`<unistd.h>`, `<fcntl.h>`)
- Runtime CPU feature detection is not used — all primitives are portable C

## Key Design Decisions

1. **Four trimmable layers.** Upper layers force their prerequisites on; the library can be built at any layer boundary, defaulting to all four.
2. **XSalsa20 off by default.** `NAION_XSALSA20` defaults to 0; the generic `naion_box_*` dispatch then compiles to direct XChaCha20 delegation. Enable XSalsa20 only for libsodium XSalsa20 wire-format interop.
3. **Unified cleanup in CSM.** CSM's heap-using functions follow a single `__ERROR__`/`__FREE__` `goto` pattern so every exit path zeroes secrets then frees.
4. **Deterministic Ed25519.** No random nonces in signing — seed-derived keys produce deterministic signatures (compatible with RFC 8032 deterministic mode).
5. **Fixed UDP budget.** The 1024-byte limit is a protocol constant, not configurable. Payloads exceeding the directional max must be handled at a higher layer.
6. **CSM has no replay protection, timestamps, or versioning.** These are explicitly out of scope and belong in the application payload layer above CSM.
