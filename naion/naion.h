#ifndef NAION_H
#define NAION_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NAION_VERSION_STRING "naion/0.2"

/* ========================================================================= */
/* Layer / feature selection macros                                          */
/* ========================================================================= */
/*
 * Naion is organised into four progressively-built layers, plus an optional
 * XSalsa20 family. Layers default to ON; defining any upper layer implicitly
 * enables everything it depends on.
 *
 *   Layer 1 (NAION_LAYER_SYMM)     XChaCha20 stream + BLAKE2b hash + RNG
 *       v depends on
 *   Layer 2 (NAION_LAYER_AEAD)     XChaCha20-Poly1305 AEAD-IETF + secretbox
 *       v depends on
 *   Layer 3 (NAION_LAYER_CSM)      Ed25519 + X25519 + Box + CSM
 *       v depends on
 *   Layer 4 (NAION_LAYER_CSM_CA)   CSM + CA-certificate handshake
 *       v depends on
 *   Layer 5 (NAION_LAYER_CSM_SESSION) CSM with ephemeral-ephemeral session DH
 *                                     (full forward secrecy per session)
 *
 *   NAION_XSALSA20 (default 0)     Salsa20 core + XSalsa20 secretbox/box +
 *                                  runtime gUseXChaCha20 dispatch
 *
 * All macros must be defined before #include "naion.h" to take effect.
 */
#ifndef NAION_LAYER_SYMM
#define NAION_LAYER_SYMM 1
#endif
#ifndef NAION_LAYER_AEAD
#define NAION_LAYER_AEAD 1
#endif
#ifndef NAION_LAYER_CSM
#define NAION_LAYER_CSM 1
#endif
#ifndef NAION_LAYER_CSM_CA
#define NAION_LAYER_CSM_CA 1
#endif
#ifndef NAION_LAYER_CSM_SESSION
#define NAION_LAYER_CSM_SESSION 1
#endif
#ifndef NAION_XSALSA20
#define NAION_XSALSA20 0
#endif

/* Upper layers force their prerequisites on. */
#if NAION_LAYER_AEAD && !NAION_LAYER_SYMM
#undef  NAION_LAYER_SYMM
#define NAION_LAYER_SYMM 1
#endif
#if NAION_LAYER_CSM && !NAION_LAYER_AEAD
#undef  NAION_LAYER_AEAD
#define NAION_LAYER_AEAD 1
#endif
#if NAION_LAYER_CSM_CA && !NAION_LAYER_CSM
#undef  NAION_LAYER_CSM
#define NAION_LAYER_CSM 1
#endif
#if NAION_LAYER_CSM_SESSION && !NAION_LAYER_CSM_CA
#undef  NAION_LAYER_CSM_CA
#define NAION_LAYER_CSM_CA 1
#endif

typedef void (*naion_random_provider_fn)(void * const buf, const size_t size);

/* ========================================================================= */
/* Layer 1 — NAION_LAYER_SYMM (hash + stream cipher + RNG)                   */
/* ========================================================================= */
#if NAION_LAYER_SYMM

/* caller-provided randomness provider; must match randombytes_buf prototype */
void naion_set_random_provider(naion_random_provider_fn provider);
naion_random_provider_fn naion_get_random_provider(void);

/* libsodium-compatible core init */
int naion_init(void);
void naion_memzero(void *pnt, size_t len);

/* ------------------------------------------------------------------------- */
/* BLAKE2b (naion_generichash) */
/* ------------------------------------------------------------------------- */

#define naion_generichash_BYTES 32U
#define naion_generichash_BYTES_MIN 16U
#define naion_generichash_BYTES_MAX 64U
#define naion_generichash_KEYBYTES 32U
#define naion_generichash_KEYBYTES_MIN 16U
#define naion_generichash_KEYBYTES_MAX 64U
#define naion_generichash_SALTBYTES 16U
#define naion_generichash_PERSONALBYTES 16U
#define naion_generichash_STATEBYTES 384U

typedef struct naion_generichash_state {
    uint8_t opaque[naion_generichash_STATEBYTES];
} naion_generichash_state;

int naion_generichash(unsigned char *out, size_t outlen,
                       const unsigned char *in, unsigned long long inlen,
                       const unsigned char *key, size_t keylen);

int naion_generichash_init(naion_generichash_state *state,
                            const unsigned char *key, size_t keylen,
                            size_t outlen);

int naion_generichash_update(naion_generichash_state *state,
                              const unsigned char *in,
                              unsigned long long inlen);

int naion_generichash_final(naion_generichash_state *state,
                             unsigned char *out, size_t outlen);

/* ------------------------------------------------------------------------- */
/* XChaCha20 stream */
/* ------------------------------------------------------------------------- */

#define naion_stream_xchacha20_KEYBYTES 32U
#define naion_stream_xchacha20_NONCEBYTES 24U

int naion_stream_xchacha20(unsigned char *c, unsigned long long clen,
                            const unsigned char *n,
                            const unsigned char *k);

int naion_stream_xchacha20_xor(unsigned char *c, const unsigned char *m,
                                unsigned long long mlen,
                                const unsigned char *n,
                                const unsigned char *k);

int naion_stream_xchacha20_xor_ic(unsigned char *c, const unsigned char *m,
                                   unsigned long long mlen,
                                   const unsigned char *n, uint64_t ic,
                                   const unsigned char *k);

#endif /* NAION_LAYER_SYMM */

/* ========================================================================= */
/* Layer 2 — NAION_LAYER_AEAD (AEAD-IETF + secretbox + symmetric box core)  */
/* ========================================================================= */
#if NAION_LAYER_AEAD

/* ------------------------------------------------------------------------- */
/* XChaCha20-Poly1305 (IETF) */
/* ------------------------------------------------------------------------- */

#define naion_aead_xchacha20poly1305_ietf_KEYBYTES 32U
#define naion_aead_xchacha20poly1305_ietf_NSECBYTES 0U
#define naion_aead_xchacha20poly1305_ietf_NPUBBYTES 24U
#define naion_aead_xchacha20poly1305_ietf_ABYTES 16U

int naion_aead_xchacha20poly1305_ietf_encrypt(
    unsigned char *c, unsigned long long *clen_p,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k);

int naion_aead_xchacha20poly1305_ietf_decrypt(
    unsigned char *m, unsigned long long *mlen_p,
    unsigned char *nsec,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k);

int naion_aead_xchacha20poly1305_ietf_encrypt_detached(
    unsigned char *c, unsigned char *mac, unsigned long long *maclen_p,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k);

int naion_aead_xchacha20poly1305_ietf_decrypt_detached(
    unsigned char *m,
    unsigned char *nsec,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *mac,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k);

/* ------------------------------------------------------------------------- */
/* secretbox (XChaCha20-Poly1305) */
/* ------------------------------------------------------------------------- */

#define naion_secretbox_xchacha20poly1305_KEYBYTES 32U
#define naion_secretbox_xchacha20poly1305_NONCEBYTES 24U
#define naion_secretbox_xchacha20poly1305_MACBYTES 16U

int naion_secretbox_xchacha20poly1305_easy(unsigned char *c,
                                            const unsigned char *m,
                                            unsigned long long mlen,
                                            const unsigned char *n,
                                            const unsigned char *k);

int naion_secretbox_xchacha20poly1305_open_easy(unsigned char *m,
                                                 const unsigned char *c,
                                                 unsigned long long clen,
                                                 const unsigned char *n,
                                                 const unsigned char *k);

int naion_secretbox_xchacha20poly1305_detached(unsigned char *c,
                                                unsigned char *mac,
                                                const unsigned char *m,
                                                unsigned long long mlen,
                                                const unsigned char *n,
                                                const unsigned char *k);

int naion_secretbox_xchacha20poly1305_open_detached(unsigned char *m,
                                                     const unsigned char *c,
                                                     const unsigned char *mac,
                                                     unsigned long long clen,
                                                     const unsigned char *n,
                                                     const unsigned char *k);

/* ------------------------------------------------------------------------- */
/* secretbox (XSalsa20-Poly1305 compatible names) */
/* ------------------------------------------------------------------------- */
#if NAION_XSALSA20
#define naion_secretbox_xsalsa20poly1305_KEYBYTES naion_secretbox_xchacha20poly1305_KEYBYTES
#define naion_secretbox_xsalsa20poly1305_NONCEBYTES naion_secretbox_xchacha20poly1305_NONCEBYTES
#define naion_secretbox_xsalsa20poly1305_MACBYTES naion_secretbox_xchacha20poly1305_MACBYTES

int naion_secretbox_xsalsa20poly1305_easy(unsigned char *c,
                                           const unsigned char *m,
                                           unsigned long long mlen,
                                           const unsigned char *n,
                                           const unsigned char *k);

int naion_secretbox_xsalsa20poly1305_open_easy(unsigned char *m,
                                                const unsigned char *c,
                                                unsigned long long clen,
                                                const unsigned char *n,
                                                const unsigned char *k);

int naion_secretbox_xsalsa20poly1305_detached(unsigned char *c,
                                               unsigned char *mac,
                                               const unsigned char *m,
                                               unsigned long long mlen,
                                               const unsigned char *n,
                                               const unsigned char *k);

int naion_secretbox_xsalsa20poly1305_open_detached(unsigned char *m,
                                                    const unsigned char *c,
                                                    const unsigned char *mac,
                                                    unsigned long long clen,
                                                    const unsigned char *n,
                                                    const unsigned char *k);
#endif /* NAION_XSALSA20 */

/* ------------------------------------------------------------------------- */
/* Box symmetric core (shared engine for secretbox + asymmetric box).
 * The *_afternm / *_open_easy_afternm entry points are pure symmetric
 * authenticated encryption: they consume a precomputed 32-byte key and a
 * 24-byte nonce, with no Curve25519 work. secretbox delegates to them, so they
 * live at the AEAD layer even though the asymmetric box wrappers below (which
 * add X25519 key agreement) require Layer 3. */
/* ------------------------------------------------------------------------- */

#define naion_box_curve25519xchacha20poly1305_BEFORENMBYTES 32U
#define naion_box_curve25519xchacha20poly1305_NONCEBYTES 24U
#define naion_box_curve25519xchacha20poly1305_MACBYTES 16U

int naion_box_curve25519xchacha20poly1305_easy_afternm(
    unsigned char *c, const unsigned char *m, unsigned long long mlen,
    const unsigned char *n, const unsigned char *k);

int naion_box_curve25519xchacha20poly1305_open_easy_afternm(
    unsigned char *m, const unsigned char *c, unsigned long long clen,
    const unsigned char *n, const unsigned char *k);

#endif /* NAION_LAYER_AEAD */

/* ========================================================================= */
/* Layer 3 — NAION_LAYER_CSM (X25519/KX/Box + Ed25519 + CSM)                */
/* ========================================================================= */
#if NAION_LAYER_CSM

/* ------------------------------------------------------------------------- */
/* X25519 key exchange + box */
/* ------------------------------------------------------------------------- */

#define naion_scalarmult_curve25519_BYTES 32U
#define naion_scalarmult_curve25519_SCALARBYTES 32U

int naion_scalarmult_curve25519(unsigned char *q,
                                 const unsigned char *n,
                                 const unsigned char *p);

int naion_scalarmult_curve25519_base(unsigned char *q,
                                      const unsigned char *n);

#define naion_kx_PUBLICKEYBYTES 32U
#define naion_kx_SECRETKEYBYTES 32U
#define naion_kx_SEEDBYTES 32U
#define naion_kx_SESSIONKEYBYTES 32U

int naion_kx_keypair(unsigned char *pk, unsigned char *sk);

int naion_kx_seed_keypair(unsigned char *pk, unsigned char *sk,
                           const unsigned char *seed);

int naion_kx_client_session_keys(unsigned char *rx, unsigned char *tx,
                                  const unsigned char *client_pk,
                                  const unsigned char *client_sk,
                                  const unsigned char *server_pk);

int naion_kx_server_session_keys(unsigned char *rx, unsigned char *tx,
                                  const unsigned char *server_pk,
                                  const unsigned char *server_sk,
                                  const unsigned char *client_pk);

#define naion_box_curve25519xchacha20poly1305_SEEDBYTES 32U
#define naion_box_curve25519xchacha20poly1305_PUBLICKEYBYTES 32U
#define naion_box_curve25519xchacha20poly1305_SECRETKEYBYTES 32U
#define naion_box_curve25519xchacha20poly1305_SEALBYTES \
    (naion_box_curve25519xchacha20poly1305_PUBLICKEYBYTES + \
     naion_box_curve25519xchacha20poly1305_MACBYTES)

int naion_box_curve25519xchacha20poly1305_keypair(unsigned char *pk,
                                                    unsigned char *sk);

int naion_box_curve25519xchacha20poly1305_seed_keypair(
    unsigned char *pk, unsigned char *sk, const unsigned char *seed);

int naion_box_curve25519xchacha20poly1305_beforenm(unsigned char *k,
                                                     const unsigned char *pk,
                                                     const unsigned char *sk);

int naion_box_curve25519xchacha20poly1305_easy(unsigned char *c,
                                                 const unsigned char *m,
                                                 unsigned long long mlen,
                                                 const unsigned char *n,
                                                 const unsigned char *pk,
                                                 const unsigned char *sk);

int naion_box_curve25519xchacha20poly1305_open_easy(
    unsigned char *m, const unsigned char *c, unsigned long long clen,
    const unsigned char *n, const unsigned char *pk, const unsigned char *sk);

int naion_box_curve25519xchacha20poly1305_seal(unsigned char *c,
                                                 const unsigned char *m,
                                                 unsigned long long mlen,
                                                 const unsigned char *pk);

int naion_box_curve25519xchacha20poly1305_seal_open(
    unsigned char *m, const unsigned char *c, unsigned long long clen,
    const unsigned char *pk, const unsigned char *sk);

/* ------------------------------------------------------------------------- */
/* X25519 box (XSalsa20-Poly1305 compatible names) */
/* ------------------------------------------------------------------------- */
#if NAION_XSALSA20
#define naion_box_curve25519xsalsa20poly1305_SEEDBYTES naion_box_curve25519xchacha20poly1305_SEEDBYTES
#define naion_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES naion_box_curve25519xchacha20poly1305_PUBLICKEYBYTES
#define naion_box_curve25519xsalsa20poly1305_SECRETKEYBYTES naion_box_curve25519xchacha20poly1305_SECRETKEYBYTES
#define naion_box_curve25519xsalsa20poly1305_BEFORENMBYTES naion_box_curve25519xchacha20poly1305_BEFORENMBYTES
#define naion_box_curve25519xsalsa20poly1305_NONCEBYTES naion_box_curve25519xchacha20poly1305_NONCEBYTES
#define naion_box_curve25519xsalsa20poly1305_MACBYTES naion_box_curve25519xchacha20poly1305_MACBYTES
#define naion_box_curve25519xsalsa20poly1305_SEALBYTES naion_box_curve25519xchacha20poly1305_SEALBYTES

int naion_box_curve25519xsalsa20poly1305_keypair(unsigned char *pk,
                                                  unsigned char *sk);

int naion_box_curve25519xsalsa20poly1305_seed_keypair(
    unsigned char *pk, unsigned char *sk, const unsigned char *seed);

int naion_box_curve25519xsalsa20poly1305_beforenm(unsigned char *k,
                                                   const unsigned char *pk,
                                                   const unsigned char *sk);

int naion_box_curve25519xsalsa20poly1305_easy(unsigned char *c,
                                               const unsigned char *m,
                                               unsigned long long mlen,
                                               const unsigned char *n,
                                               const unsigned char *pk,
                                               const unsigned char *sk);

int naion_box_curve25519xsalsa20poly1305_open_easy(
    unsigned char *m, const unsigned char *c, unsigned long long clen,
    const unsigned char *n, const unsigned char *pk, const unsigned char *sk);

int naion_box_curve25519xsalsa20poly1305_easy_afternm(
    unsigned char *c, const unsigned char *m, unsigned long long mlen,
    const unsigned char *n, const unsigned char *k);

int naion_box_curve25519xsalsa20poly1305_open_easy_afternm(
    unsigned char *m, const unsigned char *c, unsigned long long clen,
    const unsigned char *n, const unsigned char *k);

int naion_box_curve25519xsalsa20poly1305_seal(unsigned char *c,
                                               const unsigned char *m,
                                               unsigned long long mlen,
                                               const unsigned char *pk);

int naion_box_curve25519xsalsa20poly1305_seal_open(
    unsigned char *m, const unsigned char *c, unsigned long long clen,
    const unsigned char *pk, const unsigned char *sk);
#endif /* NAION_XSALSA20 */

/* runtime selector for default naion_box_* family.
 * With NAION_XSALSA20=0 the selector is a compile-time constant 1; the
 * getters are still declared so existing call sites keep compiling. */
#if NAION_XSALSA20
extern int gUseXChaCha20; /* 1: xchacha20poly1305, 0: xsalsa20poly1305 */
#endif
void naion_box_set_use_xchacha20(int use_xchacha20);
int naion_box_get_use_xchacha20(void);
/* alias getter/setter for direct global-style naming */
void naion_set_use_xchacha20(int use_xchacha20);
int naion_get_use_xchacha20(void);

/* compile-time upper bounds for static arrays/templates */
#define naion_box_SEEDBYTES_MAX naion_box_curve25519xchacha20poly1305_SEEDBYTES
#define naion_box_PUBLICKEYBYTES_MAX naion_box_curve25519xchacha20poly1305_PUBLICKEYBYTES
#define naion_box_SECRETKEYBYTES_MAX naion_box_curve25519xchacha20poly1305_SECRETKEYBYTES
#define naion_box_BEFORENMBYTES_MAX naion_box_curve25519xchacha20poly1305_BEFORENMBYTES
#define naion_box_NONCEBYTES_MAX naion_box_curve25519xchacha20poly1305_NONCEBYTES
#define naion_box_MACBYTES_MAX naion_box_curve25519xchacha20poly1305_MACBYTES
#define naion_box_SEALBYTES_MAX naion_box_curve25519xchacha20poly1305_SEALBYTES

size_t naion_box_seedbytes(void);
size_t naion_box_publickeybytes(void);
size_t naion_box_secretkeybytes(void);
size_t naion_box_beforenmbytes(void);
size_t naion_box_noncebytes(void);
size_t naion_box_macbytes(void);
size_t naion_box_sealbytes(void);

/* kept as query-style aliases for existing code */
#define naion_box_SEEDBYTES ((size_t) naion_box_seedbytes())
#define naion_box_PUBLICKEYBYTES ((size_t) naion_box_publickeybytes())
#define naion_box_SECRETKEYBYTES ((size_t) naion_box_secretkeybytes())
#define naion_box_BEFORENMBYTES ((size_t) naion_box_beforenmbytes())
#define naion_box_NONCEBYTES ((size_t) naion_box_noncebytes())
#define naion_box_MACBYTES ((size_t) naion_box_macbytes())
#define naion_box_SEALBYTES ((size_t) naion_box_sealbytes())

int naion_box_keypair(unsigned char *pk, unsigned char *sk);
int naion_box_seed_keypair(unsigned char *pk, unsigned char *sk, const unsigned char *seed);
int naion_box_beforenm(unsigned char *k, const unsigned char *pk, const unsigned char *sk);
int naion_box_easy(unsigned char *c, const unsigned char *m, unsigned long long mlen,
                   const unsigned char *n, const unsigned char *pk, const unsigned char *sk);
int naion_box_open_easy(unsigned char *m, const unsigned char *c, unsigned long long clen,
                        const unsigned char *n, const unsigned char *pk, const unsigned char *sk);
int naion_box_easy_afternm(unsigned char *c, const unsigned char *m, unsigned long long mlen,
                           const unsigned char *n, const unsigned char *k);
int naion_box_open_easy_afternm(unsigned char *m, const unsigned char *c, unsigned long long clen,
                                const unsigned char *n, const unsigned char *k);
int naion_box_seal(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *pk);
int naion_box_seal_open(unsigned char *m, const unsigned char *c, unsigned long long clen,
                        const unsigned char *pk, const unsigned char *sk);

/* ------------------------------------------------------------------------- */
/* Ed25519 */
/* ------------------------------------------------------------------------- */

#define naion_sign_ed25519_BYTES 64U
#define naion_sign_ed25519_SEEDBYTES 32U
#define naion_sign_ed25519_PUBLICKEYBYTES 32U
#define naion_sign_ed25519_SECRETKEYBYTES 64U

int naion_sign_ed25519_keypair(unsigned char *pk, unsigned char *sk);

int naion_sign_ed25519_seed_keypair(unsigned char *pk, unsigned char *sk,
                                     const unsigned char *seed);

int naion_sign_ed25519(unsigned char *sm, unsigned long long *smlen_p,
                        const unsigned char *m, unsigned long long mlen,
                        const unsigned char *sk);

int naion_sign_ed25519_open(unsigned char *m, unsigned long long *mlen_p,
                             const unsigned char *sm,
                             unsigned long long smlen,
                             const unsigned char *pk);

int naion_sign_ed25519_detached(unsigned char *sig,
                                 unsigned long long *siglen_p,
                                 const unsigned char *m,
                                 unsigned long long mlen,
                                 const unsigned char *sk);

int naion_sign_ed25519_verify_detached(const unsigned char *sig,
                                        const unsigned char *m,
                                        unsigned long long mlen,
                                        const unsigned char *pk);

int naion_sign_ed25519_sk_to_seed(unsigned char *seed,
                                   const unsigned char *sk);

int naion_sign_ed25519_sk_to_pk(unsigned char *pk,
                                 const unsigned char *sk);

int naion_sign_ed25519_pk_to_curve25519(unsigned char *curve25519_pk,
                                         const unsigned char *ed25519_pk);

int naion_sign_ed25519_sk_to_curve25519(unsigned char *curve25519_sk,
                                         const unsigned char *ed25519_sk);

/* ------------------------------------------------------------------------- */
/* CSM — client/server secure messaging (client holds server public key)     */
/* Identical packet layout to the former csm.h. See PROTOCOL.md.             */
/* ------------------------------------------------------------------------- */

enum {
    NAION_CSM_OK = 0,
    NAION_CSM_ERR_INVALID_ARGUMENT = -1,
    NAION_CSM_ERR_BUFFER_TOO_SMALL = -2,
    NAION_CSM_ERR_CRYPTO = -3,
    NAION_CSM_ERR_VERIFY_FAILED = -4,
    NAION_CSM_ERR_STATE = -5,
    NAION_CSM_ERR_RANDOM_PROVIDER = -6,
    NAION_CSM_ERR_NO_DATA = -7
};

#define NAION_CSM_PACKET_OVERHEAD \
    (naion_sign_ed25519_BYTES + naion_box_PUBLICKEYBYTES_MAX + \
     naion_box_NONCEBYTES_MAX + naion_box_MACBYTES_MAX)
#define NAION_CSM_CLIENT_PK_BYTES naion_sign_ed25519_PUBLICKEYBYTES
#define NAION_CSM_MAX_UDP_DATAGRAM_BYTES 1024U
#define NAION_CSM_MAX_CLIENT_PAYLOAD_BYTES \
    (NAION_CSM_MAX_UDP_DATAGRAM_BYTES - NAION_CSM_PACKET_OVERHEAD - NAION_CSM_CLIENT_PK_BYTES)
#define NAION_CSM_MAX_SERVER_PAYLOAD_BYTES \
    (NAION_CSM_MAX_UDP_DATAGRAM_BYTES - NAION_CSM_PACKET_OVERHEAD)

typedef struct naion_csm_client {
    uint8_t ed_seed[naion_sign_ed25519_SEEDBYTES];
    uint8_t ed_secret_key[naion_sign_ed25519_SECRETKEYBYTES];
    uint8_t ed_public_key[naion_sign_ed25519_PUBLICKEYBYTES];
    uint8_t server_ed_public_key[naion_sign_ed25519_PUBLICKEYBYTES];
} naion_csm_client;

typedef struct naion_csm_server {
    uint8_t ed_seed[naion_sign_ed25519_SEEDBYTES];
    uint8_t ed_secret_key[naion_sign_ed25519_SECRETKEYBYTES];
    uint8_t ed_public_key[naion_sign_ed25519_PUBLICKEYBYTES];
    uint8_t client_ed_public_key[naion_sign_ed25519_PUBLICKEYBYTES];
    int client_public_key_initialized;
} naion_csm_server;

int naion_csm_init(void);
void naion_csm_client_wipe(naion_csm_client *client);
void naion_csm_server_wipe(naion_csm_server *server);

int naion_csm_client_create(
    naion_csm_client *client,
    const uint8_t ed_seed_client[naion_sign_ed25519_SEEDBYTES],
    const uint8_t ed_public_key_server[naion_sign_ed25519_PUBLICKEYBYTES]
);

int naion_csm_server_create(
    naion_csm_server *server,
    const uint8_t ed_seed_server[naion_sign_ed25519_SEEDBYTES]
);

size_t naion_csm_client_encrypt_size(size_t plaintext_len);
size_t naion_csm_client_decrypt_max_plaintext_size(size_t packet_len);
size_t naion_csm_server_encrypt_size(size_t plaintext_len);
size_t naion_csm_server_decrypt_max_plaintext_size(size_t packet_len);

int naion_csm_client_encrypt(
    const naion_csm_client *client,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *out_packet,
    size_t out_packet_cap,
    size_t *out_packet_len
);

int naion_csm_client_decrypt(
    const naion_csm_client *client,
    const uint8_t *packet,
    size_t packet_len,
    uint8_t *out_plaintext,
    size_t out_plaintext_cap,
    size_t *out_plaintext_len
);

int naion_csm_server_decrypt(
    naion_csm_server *server,
    const uint8_t *packet,
    size_t packet_len,
    uint8_t *out_plaintext,
    size_t out_plaintext_cap,
    size_t *out_plaintext_len
);

int naion_csm_server_encrypt(
    const naion_csm_server *server,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *out_packet,
    size_t out_packet_cap,
    size_t *out_packet_len
);

#endif /* NAION_LAYER_CSM */

/* ========================================================================= */
/* Layer 4 — NAION_LAYER_CSM_CA (CSM + CA-certificate handshake)            */
/* ========================================================================= */
#if NAION_LAYER_CSM_CA

/*
 * CA handshake: the client no longer needs the server's long-term public key
 * up front. During a one-step handshake the server presents a 96-byte
 * certificate = server_ed25519_public_key[32] || ca_signature[64], where the
 * signature is Ed25519(server_ed_pk) produced offline by the CA. The client
 * verifies it against a built-in CA public key, then communicates using the
 * Layer 3 CSM packet format.
 */
#define NAION_CSM_CA_CERT_BYTES (naion_sign_ed25519_PUBLICKEYBYTES + naion_sign_ed25519_BYTES)

typedef struct naion_csm_ca_client {
    uint8_t ed_seed[naion_sign_ed25519_SEEDBYTES];
    uint8_t ed_secret_key[naion_sign_ed25519_SECRETKEYBYTES];
    uint8_t ed_public_key[naion_sign_ed25519_PUBLICKEYBYTES];
    uint8_t ca_ed_public_key[naion_sign_ed25519_PUBLICKEYBYTES];   /* built-in CA public key */
    uint8_t server_ed_public_key[naion_sign_ed25519_PUBLICKEYBYTES]; /* learnt from handshake */
    int server_key_verified;
} naion_csm_ca_client;

typedef struct naion_csm_ca_server {
    uint8_t ed_seed[naion_sign_ed25519_SEEDBYTES];
    uint8_t ed_secret_key[naion_sign_ed25519_SECRETKEYBYTES];
    uint8_t ed_public_key[naion_sign_ed25519_PUBLICKEYBYTES];
    uint8_t ca_signature[naion_sign_ed25519_BYTES];                 /* precomputed: CA-sign(server_ed_pk) */
    uint8_t client_ed_public_key[naion_sign_ed25519_PUBLICKEYBYTES]; /* learnt from first CSM packet */
    int client_key_verified;
} naion_csm_ca_server;

int naion_csm_ca_client_create(naion_csm_ca_client *client,
                                const uint8_t ed_seed[naion_sign_ed25519_SEEDBYTES],
                                const uint8_t ca_ed_pk[naion_sign_ed25519_PUBLICKEYBYTES]);
int naion_csm_ca_server_create(naion_csm_ca_server *server,
                                const uint8_t ed_seed[naion_sign_ed25519_SEEDBYTES],
                                const uint8_t ca_signature[naion_sign_ed25519_BYTES]);

size_t naion_csm_ca_handshake_response_size(void); /* == NAION_CSM_CA_CERT_BYTES (96) */
int naion_csm_ca_handshake_response(const naion_csm_ca_server *server,
                                     uint8_t out_m1[NAION_CSM_CA_CERT_BYTES],
                                     size_t out_cap, size_t *out_len);
int naion_csm_ca_handshake_verify(naion_csm_ca_client *client,
                                   const uint8_t *m1, size_t m1_len);

/* Post-handshake CSM traffic (identical packet format to Layer 3). */
size_t naion_csm_ca_client_encrypt_size(size_t plaintext_len);
size_t naion_csm_ca_client_decrypt_max_plaintext_size(size_t packet_len);
size_t naion_csm_ca_server_encrypt_size(size_t plaintext_len);
size_t naion_csm_ca_server_decrypt_max_plaintext_size(size_t packet_len);

int naion_csm_ca_client_encrypt(naion_csm_ca_client *client,
                                 const uint8_t *plaintext, size_t plaintext_len,
                                 uint8_t *out, size_t out_cap, size_t *out_len);
int naion_csm_ca_client_decrypt(const naion_csm_ca_client *client,
                                 const uint8_t *packet, size_t packet_len,
                                 uint8_t *out, size_t out_cap, size_t *out_len);
int naion_csm_ca_server_encrypt(const naion_csm_ca_server *server,
                                 const uint8_t *plaintext, size_t plaintext_len,
                                 uint8_t *out, size_t out_cap, size_t *out_len);
int naion_csm_ca_server_decrypt(naion_csm_ca_server *server,
                                 const uint8_t *packet, size_t packet_len,
                                 uint8_t *out, size_t out_cap, size_t *out_len);
void naion_csm_ca_client_wipe(naion_csm_ca_client *client);
void naion_csm_ca_server_wipe(naion_csm_ca_server *server);

#endif /* NAION_LAYER_CSM_CA */

/* ========================================================================= */
/* Layer 5 — NAION_LAYER_CSM_SESSION (ephemeral-ephemeral session DH, PFS)   */
/* ========================================================================= */
#if NAION_LAYER_CSM_SESSION
/*
 * CSM-Session: both peers run an ephemeral X25519 key pair for the lifetime of
 * a session, so the long-term Ed25519 identity keys never participate in
 * encryption.  A 1-RTT handshake authenticates both sides (CA certificate
 * chain + CLIENT_HELLO signature), after which each side knows the other's
 * Ed25519 public key and every packet is verified-then-decrypted symmetrically.
 * Packet overhead drops to 104 bytes (sig || nonce || mac || ct).
 *
 * See naion/plan03.md for the full design.  Session table / DoS bookkeeping is
 * deliberately left to the application layer (plan03 §2.3).
 */

#define NAION_CSM_SESS_CLIENT_HELLO_BYTES    128U  /* xpk(32) || ed_pk(32) || sig(64) */
#define NAION_CSM_SESS_SERVER_RESPONSE_BYTES 192U  /* sxpk(32) || sig(64) || sed_pk(32) || ca_sig(64) */

#define NAION_CSM_SESS_SESSION_XSK_BYTES     32U
#define NAION_CSM_SESS_SESSION_XPK_BYTES     32U
#define NAION_CSM_SESS_SESSION_SHARED_BYTES  32U
#define NAION_CSM_SESS_SESSION_AEAD_KEY_BYTES 32U

/* per-packet overhead = sig(64) + nonce(24) + mac(16) = 104 */
#define NAION_CSM_SESS_PACKET_OVERHEAD \
    (naion_sign_ed25519_BYTES + naion_box_NONCEBYTES_MAX + naion_box_MACBYTES_MAX)

#define NAION_CSM_SESS_MAX_UDP_DATAGRAM_BYTES   1024U
#define NAION_CSM_SESS_MAX_CLIENT_PAYLOAD_BYTES \
    (NAION_CSM_SESS_MAX_UDP_DATAGRAM_BYTES - NAION_CSM_SESS_PACKET_OVERHEAD)
#define NAION_CSM_SESS_MAX_SERVER_PAYLOAD_BYTES \
    (NAION_CSM_SESS_MAX_UDP_DATAGRAM_BYTES - NAION_CSM_SESS_PACKET_OVERHEAD)

typedef struct naion_csm_sess_client {
    /* identity keys (Ed25519) */
    uint8_t ed_seed[naion_sign_ed25519_SEEDBYTES];
    uint8_t ed_secret_key[naion_sign_ed25519_SECRETKEYBYTES];
    uint8_t ed_public_key[naion_sign_ed25519_PUBLICKEYBYTES];

    /* CA trust anchor */
    uint8_t ca_ed_public_key[naion_sign_ed25519_PUBLICKEYBYTES];

    /* server identity learnt from the handshake */
    uint8_t server_ed_public_key[naion_sign_ed25519_PUBLICKEYBYTES];

    /* ephemeral session X25519 key pair + derived AEAD key */
    uint8_t client_session_xsk[NAION_CSM_SESS_SESSION_XSK_BYTES];
    uint8_t client_session_xpk[NAION_CSM_SESS_SESSION_XPK_BYTES];
    uint8_t server_session_xpk[NAION_CSM_SESS_SESSION_XPK_BYTES];
    uint8_t session_aead_key[NAION_CSM_SESS_SESSION_AEAD_KEY_BYTES];

    int handshake_complete;  /* 0 = not finished, 1 = ready for traffic */
} naion_csm_sess_client;

typedef struct naion_csm_sess_server {
    /* identity keys (Ed25519) */
    uint8_t ed_seed[naion_sign_ed25519_SEEDBYTES];
    uint8_t ed_secret_key[naion_sign_ed25519_SECRETKEYBYTES];
    uint8_t ed_public_key[naion_sign_ed25519_PUBLICKEYBYTES];

    /* precomputed CA signature over ed_public_key */
    uint8_t ca_signature[naion_sign_ed25519_BYTES];

    /* ephemeral session X25519 key pair + derived AEAD key */
    uint8_t server_session_xsk[NAION_CSM_SESS_SESSION_XSK_BYTES];
    uint8_t server_session_xpk[NAION_CSM_SESS_SESSION_XPK_BYTES];
    uint8_t client_session_xpk[NAION_CSM_SESS_SESSION_XPK_BYTES];
    uint8_t session_aead_key[NAION_CSM_SESS_SESSION_AEAD_KEY_BYTES];

    /* client identity, verified during the handshake */
    uint8_t client_ed_public_key[naion_sign_ed25519_PUBLICKEYBYTES];

    int handshake_complete;
} naion_csm_sess_server;

int naion_csm_sess_client_create(
    naion_csm_sess_client *client,
    const uint8_t ed_seed[naion_sign_ed25519_SEEDBYTES],
    const uint8_t ca_ed_pk[naion_sign_ed25519_PUBLICKEYBYTES]);

int naion_csm_sess_server_create(
    naion_csm_sess_server *server,
    const uint8_t ed_seed[naion_sign_ed25519_SEEDBYTES],
    const uint8_t ca_signature[naion_sign_ed25519_BYTES]);

void naion_csm_sess_client_wipe(naion_csm_sess_client *client);
void naion_csm_sess_server_wipe(naion_csm_sess_server *server);

/* handshake: client_hello -> server_handshake -> client_finish (1-RTT) */
int naion_csm_sess_client_hello(
    naion_csm_sess_client *client,
    uint8_t out_client_hello[NAION_CSM_SESS_CLIENT_HELLO_BYTES]);

int naion_csm_sess_server_handshake(
    naion_csm_sess_server *server,
    const uint8_t client_hello[NAION_CSM_SESS_CLIENT_HELLO_BYTES],
    uint8_t out_m1[NAION_CSM_SESS_SERVER_RESPONSE_BYTES],
    size_t out_cap, size_t *out_len);

int naion_csm_sess_client_finish(
    naion_csm_sess_client *client,
    const uint8_t *m1, size_t m1_len);

/* post-handshake traffic: packet = sig(64) || nonce(24) || mac(16) || ct */
size_t naion_csm_sess_client_encrypt_size(size_t plaintext_len);
size_t naion_csm_sess_client_decrypt_max_plaintext_size(size_t packet_len);
size_t naion_csm_sess_server_encrypt_size(size_t plaintext_len);
size_t naion_csm_sess_server_decrypt_max_plaintext_size(size_t packet_len);

int naion_csm_sess_client_encrypt(
    naion_csm_sess_client *client,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *out, size_t out_cap, size_t *out_len);

int naion_csm_sess_client_decrypt(
    const naion_csm_sess_client *client,
    const uint8_t *packet, size_t packet_len,
    uint8_t *out, size_t out_cap, size_t *out_len);

int naion_csm_sess_server_encrypt(
    const naion_csm_sess_server *server,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *out, size_t out_cap, size_t *out_len);

int naion_csm_sess_server_decrypt(
    naion_csm_sess_server *server,
    const uint8_t *packet, size_t packet_len,
    uint8_t *out, size_t out_cap, size_t *out_len);

#endif /* NAION_LAYER_CSM_SESSION */

/*
 * Optional compatibility aliases.
 * Keep disabled by default to avoid symbol/name collisions with libsodium.
 */
#if defined(NAION_ENABLE_SODIUM_COMPAT_NAMES)
#define sodium_init naion_init
#define sodium_memzero naion_memzero
#define sodium_memcmp naion_memcmp
#define sodium_is_zero naion_is_zero
#endif

#ifdef __cplusplus
}
#endif

/* ------------------------------------------------------------------------- */
/* Single-header implementation */
/* Define NAION_IMPLEMENTATION in exactly one translation unit before include */
/* ------------------------------------------------------------------------- */
#if defined(NAION_IMPLEMENTATION)
#include <string.h>
#include <stdlib.h>
#include <time.h>
#if defined(DEBUG) && DEBUG
#include <stdio.h>
#endif

#if defined(_WIN32)
#include <windows.h>
#include <wincrypt.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif
#if defined(__has_include)
#if __has_include(<sys/random.h>)
#include <sys/random.h>
#define NAION_HAVE_GETRANDOM 1
#endif
#endif
#endif

#define SIMPLE_SODIUM_OK 0
#define SIMPLE_SODIUM_ERR (-1)

static naion_random_provider_fn g_random_provider = NULL;
#if NAION_XSALSA20
/* Default to XChaCha20-Poly1305 (24-byte nonce).
 * Explicitly-named naion_*_xchacha20poly1305_* functions unconditionally use
 * XChaCha20 and are unaffected by this switch; it only governs the generic
 * naion_box_* dispatch family. Defaults to 1 to keep 24-byte nonce semantics. */
int gUseXChaCha20 = 1;
#endif

static int naion_system_randombytes(unsigned char *buf, size_t size);
static void naion_system_random_provider(void * const buf, const size_t size);
static int naion_fallback_randombytes(unsigned char *buf, size_t size);

#if defined(DEBUG) && DEBUG
static void
naion_trace_dump_hex_always(const char *label, const unsigned char *buf, size_t len)
{
    size_t i;
    if (label == NULL) {
        label = "buf";
    }
    if (buf == NULL) {
        printf("[naion][trace] %s=<null>\n", label);
        return;
    }
    printf("[naion][trace] %s len=%zu: ", label, len);
    for (i = 0U; i < len; i++) {
        printf("%02x", (unsigned) buf[i]);
    }
    printf("\n");
}

static void
naion_debug_dump_hex(const char *label, const unsigned char *buf, size_t len)
{
    size_t i;
    size_t show = len > 64U ? 64U : len;

    if (label == NULL) {
        label = "buf";
    }
    if (buf == NULL) {
        printf("[naion][dbg] %s = <null>\n", label);
        return;
    }
    printf("[naion][dbg] %s len=%zu show=%zu: ", label, len, show);
    for (i = 0U; i < show; i++) {
        printf("%02x", (unsigned) buf[i]);
    }
    if (show < len) {
        printf("...");
    }
    printf("\n");
}
#endif

int naion_memcmp(const void *b1_, const void *b2_, size_t len);
int naion_is_zero(const unsigned char *n, const size_t nlen);

/* ------------------------------------------------------------------------- */
/* Minimal BLAKE2b reference implementation (portable, no SIMD) */
/* ------------------------------------------------------------------------- */

typedef struct _naion_blake2b_state {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t  buf[256];
    size_t   buflen;
    uint8_t  last_node;
} _naion_blake2b_state;

typedef struct _naion_blake2b_param {
    uint8_t digest_length;
    uint8_t key_length;
    uint8_t fanout;
    uint8_t depth;
    uint8_t leaf_length[4];
    uint8_t node_offset[8];
    uint8_t node_depth;
    uint8_t inner_length;
    uint8_t reserved[14];
    uint8_t salt[16];
    uint8_t personal[16];
} _naion_blake2b_param;

static const uint64_t _naion_blake2b_iv[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
    0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const uint8_t _naion_blake2b_sigma[12][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
};

static int
size_in_range(size_t v, size_t min_v, size_t max_v)
{
    return v >= min_v && v <= max_v;
}

static uint64_t
load64_le(const uint8_t *src)
{
    return ((uint64_t) src[0]) |
           ((uint64_t) src[1] << 8) |
           ((uint64_t) src[2] << 16) |
           ((uint64_t) src[3] << 24) |
           ((uint64_t) src[4] << 32) |
           ((uint64_t) src[5] << 40) |
           ((uint64_t) src[6] << 48) |
           ((uint64_t) src[7] << 56);
}

static void
store64_le(uint8_t *dst, uint64_t w)
{
    dst[0] = (uint8_t) (w);
    dst[1] = (uint8_t) (w >> 8);
    dst[2] = (uint8_t) (w >> 16);
    dst[3] = (uint8_t) (w >> 24);
    dst[4] = (uint8_t) (w >> 32);
    dst[5] = (uint8_t) (w >> 40);
    dst[6] = (uint8_t) (w >> 48);
    dst[7] = (uint8_t) (w >> 56);
}

static void
store32_le(uint8_t *dst, uint32_t w)
{
    dst[0] = (uint8_t) (w);
    dst[1] = (uint8_t) (w >> 8);
    dst[2] = (uint8_t) (w >> 16);
    dst[3] = (uint8_t) (w >> 24);
}

static uint64_t
rotr64(uint64_t w, unsigned c)
{
    return (w >> c) | (w << (64U - c));
}

static void
_naion_blake2b_set_lastblock(_naion_blake2b_state *s)
{
    if (s->last_node != 0U) {
        s->f[1] = ~0ULL;
    }
    s->f[0] = ~0ULL;
}

static void
_naion_blake2b_increment_counter(_naion_blake2b_state *s, uint64_t inc)
{
    s->t[0] += inc;
    s->t[1] += (s->t[0] < inc);
}

static void
_naion_blake2b_compress(_naion_blake2b_state *s, const uint8_t block[128])
{
    uint64_t m[16];
    uint64_t v[16];
    int      i;

    for (i = 0; i < 16; i++) {
        m[i] = load64_le(block + (size_t) i * 8U);
    }
    for (i = 0; i < 8; i++) {
        v[i] = s->h[i];
        v[i + 8] = _naion_blake2b_iv[i];
    }
    v[12] ^= s->t[0];
    v[13] ^= s->t[1];
    v[14] ^= s->f[0];
    v[15] ^= s->f[1];

#define SIMPLE_B2_G(r, i, a, b, c, d) \
    do { \
        a += b + m[_naion_blake2b_sigma[(r)][2 * (i) + 0]]; \
        d = rotr64(d ^ a, 32); \
        c += d; \
        b = rotr64(b ^ c, 24); \
        a += b + m[_naion_blake2b_sigma[(r)][2 * (i) + 1]]; \
        d = rotr64(d ^ a, 16); \
        c += d; \
        b = rotr64(b ^ c, 63); \
    } while (0)
#define SIMPLE_B2_ROUND(r) \
    do { \
        SIMPLE_B2_G((r), 0, v[0], v[4], v[8], v[12]); \
        SIMPLE_B2_G((r), 1, v[1], v[5], v[9], v[13]); \
        SIMPLE_B2_G((r), 2, v[2], v[6], v[10], v[14]); \
        SIMPLE_B2_G((r), 3, v[3], v[7], v[11], v[15]); \
        SIMPLE_B2_G((r), 4, v[0], v[5], v[10], v[15]); \
        SIMPLE_B2_G((r), 5, v[1], v[6], v[11], v[12]); \
        SIMPLE_B2_G((r), 6, v[2], v[7], v[8], v[13]); \
        SIMPLE_B2_G((r), 7, v[3], v[4], v[9], v[14]); \
    } while (0)

    SIMPLE_B2_ROUND(0);
    SIMPLE_B2_ROUND(1);
    SIMPLE_B2_ROUND(2);
    SIMPLE_B2_ROUND(3);
    SIMPLE_B2_ROUND(4);
    SIMPLE_B2_ROUND(5);
    SIMPLE_B2_ROUND(6);
    SIMPLE_B2_ROUND(7);
    SIMPLE_B2_ROUND(8);
    SIMPLE_B2_ROUND(9);
    SIMPLE_B2_ROUND(10);
    SIMPLE_B2_ROUND(11);

#undef SIMPLE_B2_G
#undef SIMPLE_B2_ROUND

    for (i = 0; i < 8; i++) {
        s->h[i] ^= v[i] ^ v[i + 8];
    }
}

static void
_naion_blake2b_init0(_naion_blake2b_state *s)
{
    int i;

    for (i = 0; i < 8; i++) {
        s->h[i] = _naion_blake2b_iv[i];
    }
    s->t[0] = 0ULL;
    s->t[1] = 0ULL;
    s->f[0] = 0ULL;
    s->f[1] = 0ULL;
    s->buflen = 0U;
    s->last_node = 0U;
    memset(s->buf, 0, sizeof s->buf);
}

static int
_naion_blake2b_init_param(_naion_blake2b_state *s, const _naion_blake2b_param *p)
{
    size_t  i;
    uint8_t block[64];

    _naion_blake2b_init0(s);
    memcpy(block, p, sizeof block);
    for (i = 0; i < 8; i++) {
        s->h[i] ^= load64_le(block + i * 8U);
    }
    return SIMPLE_SODIUM_OK;
}

static int
_naion_blake2b_update(_naion_blake2b_state *s, const uint8_t *in, uint64_t inlen)
{
    while (inlen > 0ULL) {
        size_t left = s->buflen;
        size_t fill = sizeof s->buf - left;

        if (inlen > (uint64_t) fill) {
            memcpy(s->buf + left, in, fill);
            s->buflen += fill;

            _naion_blake2b_increment_counter(s, 128U);
            _naion_blake2b_compress(s, s->buf);
            memmove(s->buf, s->buf + 128U, 128U);
            s->buflen -= 128U;
            in += fill;
            inlen -= (uint64_t) fill;
        } else {
            memcpy(s->buf + left, in, (size_t) inlen);
            s->buflen += (size_t) inlen;
            in += inlen;
            inlen = 0ULL;
        }
    }
    return SIMPLE_SODIUM_OK;
}

static int
_naion_blake2b_init(_naion_blake2b_state *s, uint8_t outlen)
{
    _naion_blake2b_param p;

    if (outlen == 0U || outlen > 64U) {
        return SIMPLE_SODIUM_ERR;
    }
    memset(&p, 0, sizeof p);
    p.digest_length = outlen;
    p.key_length = 0U;
    p.fanout = 1U;
    p.depth = 1U;
    store32_le(p.leaf_length, 0U);
    memset(p.node_offset, 0, sizeof p.node_offset);
    p.node_depth = 0U;
    p.inner_length = 0U;

    return _naion_blake2b_init_param(s, &p);
}

static int
_naion_blake2b_init_key(_naion_blake2b_state *s, uint8_t outlen,
                        const uint8_t *key, uint8_t keylen)
{
    _naion_blake2b_param p;
    uint8_t              block[128];

    if (outlen == 0U || outlen > 64U || key == NULL || keylen == 0U || keylen > 64U) {
        return SIMPLE_SODIUM_ERR;
    }
    memset(&p, 0, sizeof p);
    p.digest_length = outlen;
    p.key_length = keylen;
    p.fanout = 1U;
    p.depth = 1U;
    store32_le(p.leaf_length, 0U);
    memset(p.node_offset, 0, sizeof p.node_offset);
    p.node_depth = 0U;
    p.inner_length = 0U;

    if (_naion_blake2b_init_param(s, &p) != SIMPLE_SODIUM_OK) {
        return SIMPLE_SODIUM_ERR;
    }
    memset(block, 0, sizeof block);
    memcpy(block, key, keylen);
    if (_naion_blake2b_update(s, block, sizeof block) != SIMPLE_SODIUM_OK) {
        naion_memzero(block, sizeof block);
        return SIMPLE_SODIUM_ERR;
    }
    naion_memzero(block, sizeof block);
    return SIMPLE_SODIUM_OK;
}

static int
_naion_blake2b_final(_naion_blake2b_state *s, uint8_t *out, uint8_t outlen)
{
    uint8_t buffer[64];

    if (out == NULL || outlen == 0U || outlen > 64U || s->f[0] != 0ULL) {
        return SIMPLE_SODIUM_ERR;
    }
    if (s->buflen > 128U) {
        _naion_blake2b_increment_counter(s, 128U);
        _naion_blake2b_compress(s, s->buf);
        s->buflen -= 128U;
        memmove(s->buf, s->buf + 128U, s->buflen);
    }

    _naion_blake2b_increment_counter(s, (uint64_t) s->buflen);
    _naion_blake2b_set_lastblock(s);
    memset(s->buf + s->buflen, 0, sizeof s->buf - s->buflen);
    _naion_blake2b_compress(s, s->buf);

    store64_le(buffer + 0U, s->h[0]);
    store64_le(buffer + 8U, s->h[1]);
    store64_le(buffer + 16U, s->h[2]);
    store64_le(buffer + 24U, s->h[3]);
    store64_le(buffer + 32U, s->h[4]);
    store64_le(buffer + 40U, s->h[5]);
    store64_le(buffer + 48U, s->h[6]);
    store64_le(buffer + 56U, s->h[7]);
    memcpy(out, buffer, outlen);

    naion_memzero(buffer, sizeof buffer);
    naion_memzero(s, sizeof *s);
    return SIMPLE_SODIUM_OK;
}

static int
_naion_blake2b(uint8_t *out, uint8_t outlen, const uint8_t *in, uint64_t inlen,
               const uint8_t *key, uint8_t keylen)
{
    _naion_blake2b_state s;

    if (out == NULL || (in == NULL && inlen > 0ULL) ||
        (key == NULL && keylen > 0U) || outlen == 0U || outlen > 64U ||
        keylen > 64U) {
        return SIMPLE_SODIUM_ERR;
    }
    if (keylen > 0U) {
        if (_naion_blake2b_init_key(&s, outlen, key, keylen) != SIMPLE_SODIUM_OK) {
            return SIMPLE_SODIUM_ERR;
        }
    } else if (_naion_blake2b_init(&s, outlen) != SIMPLE_SODIUM_OK) {
        return SIMPLE_SODIUM_ERR;
    }
    if (_naion_blake2b_update(&s, in, inlen) != SIMPLE_SODIUM_OK) {
        return SIMPLE_SODIUM_ERR;
    }
    return _naion_blake2b_final(&s, out, outlen);
}

/* ------------------------------------------------------------------------- */
/* Minimal SHA-512 (for Ed25519->X25519 secret-key conversion) */
/* ------------------------------------------------------------------------- */

typedef struct _naion_sha512_ctx {
    uint64_t h[8];
    uint64_t bitlen_lo;
    uint64_t bitlen_hi;
    uint8_t  buf[128];
    size_t   buflen;
} _naion_sha512_ctx;

static const uint64_t _naion_sha512_k[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static uint64_t
load64_be(const uint8_t *src)
{
    return ((uint64_t) src[0] << 56) |
           ((uint64_t) src[1] << 48) |
           ((uint64_t) src[2] << 40) |
           ((uint64_t) src[3] << 32) |
           ((uint64_t) src[4] << 24) |
           ((uint64_t) src[5] << 16) |
           ((uint64_t) src[6] << 8) |
           ((uint64_t) src[7]);
}

static void
store64_be(uint8_t *dst, uint64_t w)
{
    dst[0] = (uint8_t) (w >> 56);
    dst[1] = (uint8_t) (w >> 48);
    dst[2] = (uint8_t) (w >> 40);
    dst[3] = (uint8_t) (w >> 32);
    dst[4] = (uint8_t) (w >> 24);
    dst[5] = (uint8_t) (w >> 16);
    dst[6] = (uint8_t) (w >> 8);
    dst[7] = (uint8_t) (w);
}

static uint64_t
sha512_big_sigma0(uint64_t x)
{
    return rotr64(x, 28U) ^ rotr64(x, 34U) ^ rotr64(x, 39U);
}

static uint64_t
sha512_big_sigma1(uint64_t x)
{
    return rotr64(x, 14U) ^ rotr64(x, 18U) ^ rotr64(x, 41U);
}

static uint64_t
sha512_small_sigma0(uint64_t x)
{
    return rotr64(x, 1U) ^ rotr64(x, 8U) ^ (x >> 7U);
}

static uint64_t
sha512_small_sigma1(uint64_t x)
{
    return rotr64(x, 19U) ^ rotr64(x, 61U) ^ (x >> 6U);
}

static void
_naion_sha512_transform(_naion_sha512_ctx *ctx, const uint8_t block[128])
{
    uint64_t w[80];
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t t1, t2;
    int      i;

    for (i = 0; i < 16; i++) {
        w[i] = load64_be(block + 8 * i);
    }
    for (i = 16; i < 80; i++) {
        w[i] = sha512_small_sigma1(w[i - 2]) + w[i - 7] +
               sha512_small_sigma0(w[i - 15]) + w[i - 16];
    }

    a = ctx->h[0];
    b = ctx->h[1];
    c = ctx->h[2];
    d = ctx->h[3];
    e = ctx->h[4];
    f = ctx->h[5];
    g = ctx->h[6];
    h = ctx->h[7];

    for (i = 0; i < 80; i++) {
        t1 = h + sha512_big_sigma1(e) + ((e & f) ^ ((~e) & g)) + _naion_sha512_k[i] + w[i];
        t2 = sha512_big_sigma0(a) + ((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
    ctx->h[5] += f;
    ctx->h[6] += g;
    ctx->h[7] += h;
}

static void
_naion_sha512_init(_naion_sha512_ctx *ctx)
{
    ctx->h[0] = 0x6a09e667f3bcc908ULL;
    ctx->h[1] = 0xbb67ae8584caa73bULL;
    ctx->h[2] = 0x3c6ef372fe94f82bULL;
    ctx->h[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->h[4] = 0x510e527fade682d1ULL;
    ctx->h[5] = 0x9b05688c2b3e6c1fULL;
    ctx->h[6] = 0x1f83d9abfb41bd6bULL;
    ctx->h[7] = 0x5be0cd19137e2179ULL;
    ctx->bitlen_lo = 0ULL;
    ctx->bitlen_hi = 0ULL;
    ctx->buflen = 0U;
}

static void
_naion_sha512_update(_naion_sha512_ctx *ctx, const uint8_t *in, size_t inlen)
{
    uint64_t bits = (uint64_t) inlen << 3U;

    ctx->bitlen_lo += bits;
    if (ctx->bitlen_lo < bits) {
        ctx->bitlen_hi++;
    }
    ctx->bitlen_hi += ((uint64_t) inlen >> 61U);

    while (inlen > 0U) {
        size_t take = 128U - ctx->buflen;
        if (take > inlen) {
            take = inlen;
        }
        memcpy(ctx->buf + ctx->buflen, in, take);
        ctx->buflen += take;
        in += take;
        inlen -= take;

        if (ctx->buflen == 128U) {
            _naion_sha512_transform(ctx, ctx->buf);
            ctx->buflen = 0U;
        }
    }
}

static void
_naion_sha512_final(_naion_sha512_ctx *ctx, uint8_t out[64])
{
    size_t i;

    ctx->buf[ctx->buflen++] = 0x80U;
    if (ctx->buflen > 112U) {
        memset(ctx->buf + ctx->buflen, 0, 128U - ctx->buflen);
        _naion_sha512_transform(ctx, ctx->buf);
        ctx->buflen = 0U;
    }
    memset(ctx->buf + ctx->buflen, 0, 112U - ctx->buflen);
    store64_be(ctx->buf + 112U, ctx->bitlen_hi);
    store64_be(ctx->buf + 120U, ctx->bitlen_lo);
    _naion_sha512_transform(ctx, ctx->buf);

    for (i = 0; i < 8U; i++) {
        store64_be(out + 8U * i, ctx->h[i]);
    }
    naion_memzero(ctx, sizeof *ctx);
}

static void
_naion_sha512_hash(uint8_t out[64], const uint8_t *in, size_t inlen)
{
    _naion_sha512_ctx ctx;

    _naion_sha512_init(&ctx);
    _naion_sha512_update(&ctx, in, inlen);
    _naion_sha512_final(&ctx, out);
}

/* ------------------------------------------------------------------------- */
/* Ed25519 helper checks (used by ref10 verification flow) */
/* ------------------------------------------------------------------------- */

static int
ed25519_has_small_order(const unsigned char s[32])
{
    static const unsigned char blacklist[][32] = {
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
        { 0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
        { 0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f }
    };
    unsigned char c[5] = { 0 };
    size_t        i;
    size_t        j;
    unsigned int  k = 0U;

    for (j = 0; j < 31; j++) {
        for (i = 0; i < sizeof blacklist / sizeof blacklist[0]; i++) {
            c[i] |= (unsigned char) (s[j] ^ blacklist[i][j]);
        }
    }
    for (i = 0; i < sizeof blacklist / sizeof blacklist[0]; i++) {
        c[i] |= (unsigned char) ((s[31] & 0x7f) ^ blacklist[i][31]);
    }
    for (i = 0; i < sizeof blacklist / sizeof blacklist[0]; i++) {
        k |= (unsigned int) (c[i] - 1U);
    }
    return (int) ((k >> 8) & 1U);
}

static int
ed25519_sc_is_canonical(const unsigned char s[32])
{
    static const unsigned char L[32] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    };
    unsigned char c = 0U;
    unsigned char n = 1U;
    int           i;

    for (i = 31; i >= 0; i--) {
        c |= (unsigned char) (((s[i] - L[i]) >> 8) & n);
        n &= (unsigned char) (((s[i] ^ L[i]) - 1U) >> 8);
    }
    return (int) c;
}

/* ------------------------------------------------------------------------- */
/* Minimal X25519 implementation (portable, based on TweetNaCl primitives) */
/* ------------------------------------------------------------------------- */

typedef int64_t _naion_i64;
typedef int32_t _naion_gf[16];

static void
_naion_x25519_set(_naion_gf dst, const _naion_gf src)
{
    int i;
    for (i = 0; i < 16; i++) {
        dst[i] = src[i];
    }
}

static void
_naion_x25519_add(_naion_gf o, const _naion_gf a, const _naion_gf b)
{
    int i;
    for (i = 0; i < 16; i++) {
        o[i] = a[i] + b[i];
    }
}

static void
_naion_x25519_sub(_naion_gf o, const _naion_gf a, const _naion_gf b)
{
    int i;
    for (i = 0; i < 16; i++) {
        o[i] = a[i] - b[i];
    }
}

static void
_naion_x25519_carry(_naion_gf o)
{
    int        i;
    _naion_i64 c;

    for (i = 0; i < 16; i++) {
        o[i] += (_naion_i64) 1 << 16;
        c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += (int32_t) (c - 1 + 37 * (c - 1) * (i == 15));
        o[i] -= (int32_t) (c << 16);
    }
}

static void
_naion_x25519_select(_naion_gf p, _naion_gf q, int b)
{
    _naion_i64 t;
    _naion_i64 c = ~(_naion_i64) (b - 1);
    int        i;

    for (i = 0; i < 16; i++) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void
_naion_x25519_pack(uint8_t out[32], const _naion_gf n)
{
    _naion_gf t;
    _naion_gf m;
    int       i;
    int       j;
    _naion_i64 b;

    _naion_x25519_set(t, n);
    _naion_x25519_carry(t);
    _naion_x25519_carry(t);
    _naion_x25519_carry(t);

    for (j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        _naion_x25519_select(t, m, (int) (1 - b));
    }

    for (i = 0; i < 16; i++) {
        out[2 * i] = (uint8_t) (t[i] & 0xff);
        out[2 * i + 1] = (uint8_t) ((t[i] >> 8) & 0xff);
    }
}

static void
_naion_x25519_unpack(_naion_gf o, const uint8_t n[32])
{
    int i;

    for (i = 0; i < 16; i++) {
        o[i] = n[2 * i] + ((_naion_i64) n[2 * i + 1] << 8);
    }
    o[15] &= 0x7fff;
}

static void
_naion_x25519_mul(_naion_gf o, const _naion_gf a, const _naion_gf b)
{
    /*
     * Field elements live in 32-bit limbs (see _naion_gf typedef).  The
     * convolution below accumulates into 64-bit temporaries so the products
     * never lose precision; only once a limb has been fully reduced back into
     * the 16-bit working range do we store it into the 32-bit element.
     *
     * Writing the raw 64-bit accumulator straight into a 32-bit limb would
     * truncate it modulo 2**32, which is *not* a reduction modulo 2**255-19,
     * so the subsequent carry passes could not repair it.  We therefore run
     * the carry chain on the 64-bit buffer first, and only then demote each
     * limb to _naion_gf.
     */
    _naion_i64 t[31];
    _naion_i64 c;
    int        i;
    int        j;

    memset(t, 0, sizeof t);
    for (i = 0; i < 16; i++) {
        for (j = 0; j < 16; j++) {
            t[i + j] += (_naion_i64) a[i] * (_naion_i64) b[j];
        }
    }
    for (i = 0; i < 15; i++) {
        t[i] += 38 * t[i + 16];
    }
    /*
     * Reduce the 16-limb result in place (on the 64-bit buffer) so every limb
     * fits comfortably inside int32 before it is stored.  Three passes match
     * the original TweetNaCl contract and keep the canonical range; the loop
     * is identical to _naion_x25519_carry but operates on int64 storage.
     */
    for (j = 0; j < 3; j++) {
        for (i = 0; i < 16; i++) {
            t[i] += (_naion_i64) 1 << 16;
            c = t[i] >> 16;
            t[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
            t[i] -= c << 16;
        }
    }
    for (i = 0; i < 16; i++) {
        o[i] = (int32_t) t[i];
    }
}

static void
_naion_x25519_sq(_naion_gf o, const _naion_gf a)
{
    _naion_x25519_mul(o, a, a);
}

static void
_naion_x25519_inv(_naion_gf o, const _naion_gf i)
{
    _naion_gf c;
    int       a;

    _naion_x25519_set(c, i);
    for (a = 253; a >= 0; a--) {
        _naion_x25519_sq(c, c);
        if (a != 2 && a != 4) {
            _naion_x25519_mul(c, c, i);
        }
    }
    _naion_x25519_set(o, c);
}

static int
_naion_x25519_has_small_order(const uint8_t p[32])
{
    static const uint8_t blacklist[7][32] = {
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3,
          0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32,
          0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00 },
        { 0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1,
          0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c,
          0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57 },
        { 0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
        { 0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
        { 0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f }
    };
    uint8_t      c[7] = { 0 };
    unsigned int k = 0U;
    size_t       i;
    size_t       j;

    for (j = 0; j < 31; j++) {
        for (i = 0; i < 7; i++) {
            c[i] |= (uint8_t) (p[j] ^ blacklist[i][j]);
        }
    }
    for (i = 0; i < 7; i++) {
        c[i] |= (uint8_t) ((p[31] & 0x7f) ^ blacklist[i][31]);
    }
    for (i = 0; i < 7; i++) {
        k |= (unsigned int) (c[i] - 1U);
    }
    return (int) ((k >> 8) & 1U);
}

static int
_naion_x25519_scalarmult(uint8_t q[32], const uint8_t n[32], const uint8_t p[32])
{
    static const _naion_gf _naion_x25519_121665 = { 0xdb41, 1 };
    uint8_t                z[32];
    _naion_gf              x;
    _naion_gf              a;
    _naion_gf              b;
    _naion_gf              c;
    _naion_gf              d;
    _naion_gf              e;
    _naion_gf              f;
    int                    i;
    int                    r;

    if (_naion_x25519_has_small_order(p)) {
        return SIMPLE_SODIUM_ERR;
    }
    memcpy(z, n, sizeof z);
    z[31] = (uint8_t) ((z[31] & 127U) | 64U);
    z[0] &= 248U;

    _naion_x25519_unpack(x, p);
    for (i = 0; i < 16; i++) {
        b[i] = x[i];
        d[i] = 0;
        a[i] = 0;
        c[i] = 0;
    }
    a[0] = 1;
    d[0] = 1;

    for (i = 254; i >= 0; i--) {
        r = (int) ((z[i >> 3] >> (i & 7)) & 1U);
        _naion_x25519_select(a, b, r);
        _naion_x25519_select(c, d, r);
        _naion_x25519_add(e, a, c);
        _naion_x25519_sub(a, a, c);
        _naion_x25519_add(c, b, d);
        _naion_x25519_sub(b, b, d);
        _naion_x25519_sq(d, e);
        _naion_x25519_sq(f, a);
        _naion_x25519_mul(a, c, a);
        _naion_x25519_mul(c, b, e);
        _naion_x25519_add(e, a, c);
        _naion_x25519_sub(a, a, c);
        _naion_x25519_sq(b, a);
        _naion_x25519_sub(c, d, f);
        _naion_x25519_mul(a, c, _naion_x25519_121665);
        _naion_x25519_add(a, a, d);
        _naion_x25519_mul(c, c, a);
        _naion_x25519_mul(a, d, f);
        _naion_x25519_mul(d, b, x);
        _naion_x25519_sq(b, e);
        _naion_x25519_select(a, b, r);
        _naion_x25519_select(c, d, r);
    }

    _naion_x25519_inv(c, c);
    _naion_x25519_mul(a, a, c);
    _naion_x25519_pack(q, a);
    return SIMPLE_SODIUM_OK;
}

static int
_naion_x25519_scalarmult_base(uint8_t q[32], const uint8_t n[32])
{
    static const uint8_t basepoint[32] = { 9 };

    return _naion_x25519_scalarmult(q, n, basepoint);
}

typedef _naion_gf _naion_ed25519_point[4];

static int _naion_ed25519_decode_validate_main_subgroup(_naion_gf y_out,
                                                        const unsigned char pk[32]);

static int
_naion_ed25519_pk_is_canonical(const unsigned char pk[32])
{
    unsigned char y_in[32];
    unsigned char y_can[32];
    _naion_gf      y;

    memcpy(y_in, pk, 32U);
    y_in[31] &= 0x7fU;
    _naion_x25519_unpack(y, y_in);
    _naion_x25519_pack(y_can, y);
    return naion_memcmp(y_in, y_can, 32U) == 0 ? 1 : 0;
}

static int
_naion_ed25519_pk_to_curve25519_fallback(unsigned char *curve25519_pk,
                                         const unsigned char *ed25519_pk)
{
    unsigned char den_bytes[32];
    _naion_gf      y;
    _naion_gf      num;
    _naion_gf      den;
    _naion_gf      invden;
    _naion_gf      u;

    if (curve25519_pk == NULL || ed25519_pk == NULL) {
        return SIMPLE_SODIUM_ERR;
    }
    if (_naion_ed25519_decode_validate_main_subgroup(y, ed25519_pk) != SIMPLE_SODIUM_OK) {
        return SIMPLE_SODIUM_ERR;
    }

    memset(num, 0, sizeof num);
    memset(den, 0, sizeof den);
    num[0] = 1;
    den[0] = 1;
    _naion_x25519_add(num, num, y); /* num = 1 + y */
    _naion_x25519_sub(den, den, y); /* den = 1 - y */
    _naion_x25519_pack(den_bytes, den);
    if (naion_is_zero(den_bytes, sizeof den_bytes)) {
        return SIMPLE_SODIUM_ERR;
    }

    _naion_x25519_inv(invden, den);
    _naion_x25519_mul(u, num, invden);
    _naion_x25519_pack(curve25519_pk, u);
    return SIMPLE_SODIUM_OK;
}

/* ------------------------------------------------------------------------- */
/* Minimal Ed25519 (deterministic) using TweetNaCl-style formulas            */
/* ------------------------------------------------------------------------- */

static const _naion_gf _naion_ed25519_0 = { 0 };
static const _naion_gf _naion_ed25519_1 = { 1 };
static const _naion_gf _naion_ed25519_D = {
    0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
    0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203
};
static const _naion_gf _naion_ed25519_D2 = {
    0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
    0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406
};
static const _naion_gf _naion_ed25519_X = {
    0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
    0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169
};
static const _naion_gf _naion_ed25519_Y = {
    0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666
};
static const _naion_gf _naion_ed25519_I = {
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
    0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83
};

static const unsigned char _naion_ed25519_L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

static void
_naion_ed25519_pow2523(_naion_gf o, const _naion_gf i)
{
    _naion_gf c;
    int       a;

    _naion_x25519_set(c, i);
    for (a = 250; a >= 0; a--) {
        _naion_x25519_sq(c, c);
        if (a != 1) {
            _naion_x25519_mul(c, c, i);
        }
    }
    _naion_x25519_set(o, c);
}

static void
_naion_ed25519_pack25519(unsigned char out[32], const _naion_gf n)
{
    _naion_x25519_pack(out, n);
}

static int
_naion_ed25519_par25519(const _naion_gf a)
{
    unsigned char d[32];

    _naion_ed25519_pack25519(d, a);
    return d[0] & 1;
}

static int
_naion_ed25519_neq25519(const _naion_gf a, const _naion_gf b)
{
    unsigned char c[32];
    unsigned char d[32];

    _naion_ed25519_pack25519(c, a);
    _naion_ed25519_pack25519(d, b);
    return naion_memcmp(c, d, 32U);
}

static void
_naion_ed25519_add(_naion_ed25519_point p, const _naion_ed25519_point q)
{
    _naion_gf a;
    _naion_gf b;
    _naion_gf c;
    _naion_gf d;
    _naion_gf e;
    _naion_gf f;
    _naion_gf g;
    _naion_gf h;
    _naion_gf t;

    _naion_x25519_add(a, p[1], p[0]);
    _naion_x25519_add(t, q[1], q[0]);
    _naion_x25519_mul(a, a, t);

    _naion_x25519_sub(b, p[1], p[0]);
    _naion_x25519_sub(t, q[1], q[0]);
    _naion_x25519_mul(b, b, t);

    _naion_x25519_mul(c, p[3], q[3]);
    _naion_x25519_mul(c, c, _naion_ed25519_D2);

    _naion_x25519_mul(d, p[2], q[2]);
    _naion_x25519_add(d, d, d);

    _naion_x25519_sub(e, a, b);
    _naion_x25519_sub(f, d, c);
    _naion_x25519_add(g, d, c);
    _naion_x25519_add(h, a, b);

    _naion_x25519_mul(p[0], e, f);
    _naion_x25519_mul(p[1], h, g);
    _naion_x25519_mul(p[2], g, f);
    _naion_x25519_mul(p[3], e, h);
}

static void
_naion_ed25519_cswap(_naion_ed25519_point p, _naion_ed25519_point q, int b)
{
    _naion_x25519_select(p[0], q[0], b);
    _naion_x25519_select(p[1], q[1], b);
    _naion_x25519_select(p[2], q[2], b);
    _naion_x25519_select(p[3], q[3], b);
}

static void
_naion_ed25519_pack(unsigned char r[32], _naion_ed25519_point p)
{
    _naion_gf tx;
    _naion_gf ty;
    _naion_gf zi;

    _naion_x25519_inv(zi, p[2]);
    _naion_x25519_mul(tx, p[0], zi);
    _naion_x25519_mul(ty, p[1], zi);
    _naion_ed25519_pack25519(r, ty);
    r[31] ^= (unsigned char) (_naion_ed25519_par25519(tx) << 7);
}

static void
_naion_ed25519_scalarmult(_naion_ed25519_point p,
                          _naion_ed25519_point q,
                          const unsigned char *s)
{
    int i;

    _naion_x25519_set(p[0], _naion_ed25519_0);
    _naion_x25519_set(p[1], _naion_ed25519_1);
    _naion_x25519_set(p[2], _naion_ed25519_1);
    _naion_x25519_set(p[3], _naion_ed25519_0);

    for (i = 255; i >= 0; --i) {
        int b = (int) ((s[i >> 3] >> (i & 7)) & 1U);
        _naion_ed25519_cswap(p, q, b);
        _naion_ed25519_add(q, p);
        _naion_ed25519_add(p, p);
        _naion_ed25519_cswap(p, q, b);
    }
}

static void
_naion_ed25519_scalarbase(_naion_ed25519_point p, const unsigned char *s)
{
    _naion_ed25519_point q;

    _naion_x25519_set(q[0], _naion_ed25519_X);
    _naion_x25519_set(q[1], _naion_ed25519_Y);
    _naion_x25519_set(q[2], _naion_ed25519_1);
    _naion_x25519_mul(q[3], _naion_ed25519_X, _naion_ed25519_Y);
    _naion_ed25519_scalarmult(p, q, s);
}

static void
_naion_ed25519_modL(unsigned char *r, _naion_i64 x[64])
{
    _naion_i64 carry;
    int        i;
    int        j;
    int        k;

    for (i = 63; i >= 32; --i) {
        carry = 0;
        for (j = i - 32, k = i - 12; j < k; ++j) {
            x[j] += carry - 16 * x[i] * (_naion_i64) _naion_ed25519_L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry * 256;
        }
        x[j] += carry;
        x[i] = 0;
    }
    carry = 0;
    for (j = 0; j < 32; ++j) {
        x[j] += carry - (x[31] >> 4) * (_naion_i64) _naion_ed25519_L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for (j = 0; j < 32; ++j) {
        x[j] -= carry * (_naion_i64) _naion_ed25519_L[j];
    }
    for (i = 0; i < 32; ++i) {
        x[i + 1] += x[i] >> 8;
        r[i] = (unsigned char) (x[i] & 255);
    }
}

static void
_naion_ed25519_reduce(unsigned char r[64])
{
    _naion_i64 x[64];
    int        i;

    for (i = 0; i < 64; ++i) {
        x[i] = (_naion_i64) (r[i] & 0xffU);
    }
    _naion_ed25519_modL(r, x);
}

static void
_naion_ed25519_muladd(unsigned char s[32], const unsigned char a[32],
                      const unsigned char b[32], const unsigned char c[32])
{
    _naion_i64 x[64];
    int        i;
    int        j;

    memset(x, 0, sizeof x);
    for (i = 0; i < 32; ++i) {
        x[i] = (_naion_i64) (c[i] & 0xffU);
    }
    for (i = 0; i < 32; ++i) {
        for (j = 0; j < 32; ++j) {
            x[i + j] += (_naion_i64) (a[i] & 0xffU) * (_naion_i64) (b[j] & 0xffU);
        }
    }
    _naion_ed25519_modL(s, x);
}

static int
_naion_ed25519_unpackneg(_naion_ed25519_point r, const unsigned char p[32])
{
    _naion_gf t;
    _naion_gf chk;
    _naion_gf num;
    _naion_gf den;
    _naion_gf den2;
    _naion_gf den4;
    _naion_gf den6;

    _naion_x25519_set(r[2], _naion_ed25519_1);
    _naion_x25519_unpack(r[1], p);
    _naion_x25519_sq(num, r[1]);
    _naion_x25519_mul(den, num, _naion_ed25519_D);
    _naion_x25519_sub(num, num, r[2]);
    _naion_x25519_add(den, r[2], den);

    _naion_x25519_sq(den2, den);
    _naion_x25519_sq(den4, den2);
    _naion_x25519_mul(den6, den4, den2);
    _naion_x25519_mul(t, den6, num);
    _naion_x25519_mul(t, t, den);
    _naion_ed25519_pow2523(t, t);
    _naion_x25519_mul(t, t, num);
    _naion_x25519_mul(t, t, den);
    _naion_x25519_mul(t, t, den);
    _naion_x25519_mul(r[0], t, den);

    _naion_x25519_sq(chk, r[0]);
    _naion_x25519_mul(chk, chk, den);
    if (_naion_ed25519_neq25519(chk, num) != 0) {
        _naion_x25519_mul(r[0], r[0], _naion_ed25519_I);
    }
    _naion_x25519_sq(chk, r[0]);
    _naion_x25519_mul(chk, chk, den);
    if (_naion_ed25519_neq25519(chk, num) != 0) {
        return SIMPLE_SODIUM_ERR;
    }
    if (_naion_ed25519_par25519(r[0]) == (int) ((p[31] >> 7) & 1U)) {
        _naion_x25519_sub(r[0], _naion_ed25519_0, r[0]);
    }
    _naion_x25519_mul(r[3], r[0], r[1]);
    return SIMPLE_SODIUM_OK;
}

static int
_naion_ed25519_decode_validate_main_subgroup(_naion_gf y_out,
                                             const unsigned char pk[32])
{
    static const unsigned char identity[32] = { 1 };
    unsigned char              check_bytes[32];
    _naion_ed25519_point       a;
    _naion_ed25519_point       a_check;
    _naion_ed25519_point       check;
    int                        ret = SIMPLE_SODIUM_ERR;

    if (pk == NULL) {
        return SIMPLE_SODIUM_ERR;
    }
    if (_naion_ed25519_pk_is_canonical(pk) == 0 ||
        ed25519_has_small_order(pk) != 0) {
        return SIMPLE_SODIUM_ERR;
    }
    if (_naion_ed25519_unpackneg(a, pk) != SIMPLE_SODIUM_OK) {
        return SIMPLE_SODIUM_ERR;
    }

    _naion_x25519_set(a_check[0], a[0]);
    _naion_x25519_set(a_check[1], a[1]);
    _naion_x25519_set(a_check[2], a[2]);
    _naion_x25519_set(a_check[3], a[3]);
    _naion_ed25519_scalarmult(check, a_check, _naion_ed25519_L);
    _naion_ed25519_pack(check_bytes, check);
    if (naion_memcmp(check_bytes, identity, sizeof identity) != 0) {
        ret = SIMPLE_SODIUM_ERR;
        goto cleanup;
    }

    if (y_out != NULL) {
        _naion_x25519_set(y_out, a[1]);
    }
    ret = SIMPLE_SODIUM_OK;

cleanup:
    naion_memzero(check_bytes, sizeof check_bytes);
    naion_memzero(a, sizeof a);
    naion_memzero(a_check, sizeof a_check);
    naion_memzero(check, sizeof check);
    return ret;
}

static int
_naion_ed25519_seed_keypair_internal(unsigned char *pk, unsigned char *sk,
                                     const unsigned char *seed)
{
    unsigned char        h[64];
    _naion_ed25519_point a;

    _naion_sha512_hash(h, seed, 32U);
    h[0] &= 248U;
    h[31] &= 127U;
    h[31] |= 64U;

    _naion_ed25519_scalarbase(a, h);
    _naion_ed25519_pack(pk, a);

    memcpy(sk, seed, 32U);
    memcpy(sk + 32U, pk, 32U);
    naion_memzero(h, sizeof h);
    naion_memzero(a, sizeof a);
    return SIMPLE_SODIUM_OK;
}

static int
_naion_ed25519_detached_sign_internal(unsigned char *sig,
                                      unsigned long long *siglen_p,
                                      const unsigned char *m,
                                      unsigned long long mlen,
                                      const unsigned char *sk)
{
    _naion_sha512_ctx     hs;
    unsigned char         az[64];
    unsigned char         nonce[64];
    unsigned char         hram[64];
    _naion_ed25519_point  r;

    if (mlen > (unsigned long long) ((size_t) -1)) {
        return SIMPLE_SODIUM_ERR;
    }

    _naion_sha512_hash(az, sk, 32U);
    _naion_sha512_init(&hs);
    _naion_sha512_update(&hs, az + 32U, 32U);
    if (mlen > 0ULL) {
        _naion_sha512_update(&hs, m, (size_t) mlen);
    }
    _naion_sha512_final(&hs, nonce);
    _naion_ed25519_reduce(nonce);

    _naion_ed25519_scalarbase(r, nonce);
    _naion_ed25519_pack(sig, r);

    _naion_sha512_init(&hs);
    _naion_sha512_update(&hs, sig, 32U);
    _naion_sha512_update(&hs, sk + 32U, 32U);
    if (mlen > 0ULL) {
        _naion_sha512_update(&hs, m, (size_t) mlen);
    }
    _naion_sha512_final(&hs, hram);
    _naion_ed25519_reduce(hram);

    az[0] &= 248U;
    az[31] &= 127U;
    az[31] |= 64U;
    _naion_ed25519_muladd(sig + 32U, hram, az, nonce);

    if (siglen_p != NULL) {
        *siglen_p = 64ULL;
    }
    naion_memzero(&hs, sizeof hs);
    naion_memzero(az, sizeof az);
    naion_memzero(nonce, sizeof nonce);
    naion_memzero(hram, sizeof hram);
    naion_memzero(r, sizeof r);
    return SIMPLE_SODIUM_OK;
}

static int
_naion_ed25519_detached_verify_internal(const unsigned char *sig,
                                        const unsigned char *m,
                                        unsigned long long mlen,
                                        const unsigned char *pk)
{
    _naion_sha512_ctx    hs;
    unsigned char        h[64];
    unsigned char        rcheck[32];
    _naion_ed25519_point a;
    _naion_ed25519_point p;
    _naion_ed25519_point sb;

    if (mlen > (unsigned long long) ((size_t) -1)) {
        return SIMPLE_SODIUM_ERR;
    }
    if (ed25519_sc_is_canonical(sig + 32U) == 0 ||
        ed25519_has_small_order(sig) != 0 ||
        _naion_ed25519_pk_is_canonical(pk) == 0 ||
        ed25519_has_small_order(pk) != 0) {
        return SIMPLE_SODIUM_ERR;
    }
    if (_naion_ed25519_unpackneg(a, pk) != SIMPLE_SODIUM_OK) {
        return SIMPLE_SODIUM_ERR;
    }

    _naion_sha512_init(&hs);
    _naion_sha512_update(&hs, sig, 32U);
    _naion_sha512_update(&hs, pk, 32U);
    if (mlen > 0ULL) {
        _naion_sha512_update(&hs, m, (size_t) mlen);
    }
    _naion_sha512_final(&hs, h);
    _naion_ed25519_reduce(h);

    _naion_ed25519_scalarmult(p, a, h);
    _naion_ed25519_scalarbase(sb, sig + 32U);
    _naion_ed25519_add(p, sb);
    _naion_ed25519_pack(rcheck, p);

    naion_memzero(&hs, sizeof hs);
    naion_memzero(h, sizeof h);
    naion_memzero(a, sizeof a);
    naion_memzero(p, sizeof p);
    naion_memzero(sb, sizeof sb);
    return naion_memcmp(rcheck, sig, 32U) == 0 ? SIMPLE_SODIUM_OK : SIMPLE_SODIUM_ERR;
}

/* ------------------------------------------------------------------------- */
/* ChaCha20 / HChaCha20 / XChaCha20 stream */
/* ------------------------------------------------------------------------- */

static uint32_t
load32_le_u32(const uint8_t src[4])
{
    return ((uint32_t) src[0]) |
           ((uint32_t) src[1] << 8) |
           ((uint32_t) src[2] << 16) |
           ((uint32_t) src[3] << 24);
}

static void
store32_le_u32(uint8_t dst[4], uint32_t w)
{
    dst[0] = (uint8_t) (w);
    dst[1] = (uint8_t) (w >> 8);
    dst[2] = (uint8_t) (w >> 16);
    dst[3] = (uint8_t) (w >> 24);
}

static uint32_t
rotl32(uint32_t x, int b)
{
    return (x << b) | (x >> (32 - b));
}

#if NAION_XSALSA20
/* ------------------------------------------------------------------ */
/* Salsa20 / HSalsa20 / XSalsa20 (only built when NAION_XSALSA20=1)   */
/* ------------------------------------------------------------------ */
static void
salsa20_quarterround(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
    uint32_t xa = *a;
    uint32_t xb = *b;
    uint32_t xc = *c;
    uint32_t xd = *d;

    xb ^= rotl32(xa + xd, 7);
    xc ^= rotl32(xb + xa, 9);
    xd ^= rotl32(xc + xb, 13);
    xa ^= rotl32(xd + xc, 18);

    *a = xa;
    *b = xb;
    *c = xc;
    *d = xd;
}

static void
salsa20_block(uint8_t out[64], const uint8_t key[32], const uint8_t nonce[8],
              uint32_t ctr_low, uint32_t ctr_high)
{
    uint32_t             st[16];
    uint32_t             x[16];
    int                  i;

    static const uint32_t c0 = 0x61707865U;
    static const uint32_t c1 = 0x3320646eU;
    static const uint32_t c2 = 0x79622d32U;
    static const uint32_t c3 = 0x6b206574U;

    st[0] = c0;
    st[1] = load32_le_u32(key + 0);
    st[2] = load32_le_u32(key + 4);
    st[3] = load32_le_u32(key + 8);
    st[4] = load32_le_u32(key + 12);
    st[5] = c1;
    st[6] = load32_le_u32(nonce + 0);
    st[7] = load32_le_u32(nonce + 4);
    st[8] = ctr_low;
    st[9] = ctr_high;
    st[10] = c2;
    st[11] = load32_le_u32(key + 16);
    st[12] = load32_le_u32(key + 20);
    st[13] = load32_le_u32(key + 24);
    st[14] = load32_le_u32(key + 28);
    st[15] = c3;

    for (i = 0; i < 16; i++) {
        x[i] = st[i];
    }
    for (i = 0; i < 10; i++) {
        salsa20_quarterround(&x[0], &x[4], &x[8], &x[12]);
        salsa20_quarterround(&x[5], &x[9], &x[13], &x[1]);
        salsa20_quarterround(&x[10], &x[14], &x[2], &x[6]);
        salsa20_quarterround(&x[15], &x[3], &x[7], &x[11]);

        salsa20_quarterround(&x[0], &x[1], &x[2], &x[3]);
        salsa20_quarterround(&x[5], &x[6], &x[7], &x[4]);
        salsa20_quarterround(&x[10], &x[11], &x[8], &x[9]);
        salsa20_quarterround(&x[15], &x[12], &x[13], &x[14]);
    }
    for (i = 0; i < 16; i++) {
        x[i] += st[i];
        store32_le_u32(out + 4 * i, x[i]);
    }
}

static void
hsalsa20(uint8_t out[32], const uint8_t nonce[16], const uint8_t key[32])
{
    uint32_t             x[16];
    int                  i;

    static const uint32_t c0 = 0x61707865U;
    static const uint32_t c1 = 0x3320646eU;
    static const uint32_t c2 = 0x79622d32U;
    static const uint32_t c3 = 0x6b206574U;

    x[0] = c0;
    x[1] = load32_le_u32(key + 0);
    x[2] = load32_le_u32(key + 4);
    x[3] = load32_le_u32(key + 8);
    x[4] = load32_le_u32(key + 12);
    x[5] = c1;
    x[6] = load32_le_u32(nonce + 0);
    x[7] = load32_le_u32(nonce + 4);
    x[8] = load32_le_u32(nonce + 8);
    x[9] = load32_le_u32(nonce + 12);
    x[10] = c2;
    x[11] = load32_le_u32(key + 16);
    x[12] = load32_le_u32(key + 20);
    x[13] = load32_le_u32(key + 24);
    x[14] = load32_le_u32(key + 28);
    x[15] = c3;

    for (i = 0; i < 10; i++) {
        salsa20_quarterround(&x[0], &x[4], &x[8], &x[12]);
        salsa20_quarterround(&x[5], &x[9], &x[13], &x[1]);
        salsa20_quarterround(&x[10], &x[14], &x[2], &x[6]);
        salsa20_quarterround(&x[15], &x[3], &x[7], &x[11]);

        salsa20_quarterround(&x[0], &x[1], &x[2], &x[3]);
        salsa20_quarterround(&x[5], &x[6], &x[7], &x[4]);
        salsa20_quarterround(&x[10], &x[11], &x[8], &x[9]);
        salsa20_quarterround(&x[15], &x[12], &x[13], &x[14]);
    }

    store32_le_u32(out + 0, x[0]);
    store32_le_u32(out + 4, x[5]);
    store32_le_u32(out + 8, x[10]);
    store32_le_u32(out + 12, x[15]);
    store32_le_u32(out + 16, x[6]);
    store32_le_u32(out + 20, x[7]);
    store32_le_u32(out + 24, x[8]);
    store32_le_u32(out + 28, x[9]);
}

static int
xsalsa20_xor_ic(uint8_t *c, const uint8_t *m, uint64_t mlen,
                const uint8_t n[24], uint64_t ic, const uint8_t k[32])
{
    uint8_t  subkey[32];
    uint8_t  nonce8[8];
    uint8_t  block[64];
    uint32_t ctr_low;
    uint32_t ctr_high;
    size_t   i;
    size_t   take;

    hsalsa20(subkey, n, k);
    memcpy(nonce8, n + 16, 8);
    ctr_low = (uint32_t) (ic & 0xffffffffU);
    ctr_high = (uint32_t) (ic >> 32);

    while (mlen > 0ULL) {
        salsa20_block(block, subkey, nonce8, ctr_low, ctr_high);
        ctr_low++;
        if (ctr_low == 0U) {
            ctr_high++;
        }

        take = (size_t) ((mlen < 64ULL) ? mlen : 64ULL);
        if (m == NULL) {
            for (i = 0; i < take; i++) {
                c[i] = block[i];
            }
        } else {
            for (i = 0; i < take; i++) {
                c[i] = (uint8_t) (m[i] ^ block[i]);
            }
        }
        c += take;
        if (m != NULL) {
            m += take;
        }
        mlen -= (uint64_t) take;
    }
    naion_memzero(subkey, sizeof subkey);
    naion_memzero(block, sizeof block);
    return SIMPLE_SODIUM_OK;
}
#endif /* NAION_XSALSA20 */

static void
chacha20_quarterround(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
    *a += *b; *d ^= *a; *d = rotl32(*d, 16);
    *c += *d; *b ^= *c; *b = rotl32(*b, 12);
    *a += *b; *d ^= *a; *d = rotl32(*d, 8);
    *c += *d; *b ^= *c; *b = rotl32(*b, 7);
}

static void
chacha20_block(uint8_t out[64], const uint8_t key[32],
               uint32_t counter, const uint8_t nonce[12])
{
    uint32_t             st[16];
    uint32_t             x[16];
    int                  i;

    st[0] = 0x61707865U;
    st[1] = 0x3320646eU;
    st[2] = 0x79622d32U;
    st[3] = 0x6b206574U;
    for (i = 0; i < 8; i++) {
        st[4 + i] = load32_le_u32(key + 4 * i);
    }
    st[12] = counter;
    st[13] = load32_le_u32(nonce + 0);
    st[14] = load32_le_u32(nonce + 4);
    st[15] = load32_le_u32(nonce + 8);

    for (i = 0; i < 16; i++) {
        x[i] = st[i];
    }
    for (i = 0; i < 10; i++) {
        chacha20_quarterround(&x[0], &x[4], &x[8], &x[12]);
        chacha20_quarterround(&x[1], &x[5], &x[9], &x[13]);
        chacha20_quarterround(&x[2], &x[6], &x[10], &x[14]);
        chacha20_quarterround(&x[3], &x[7], &x[11], &x[15]);
        chacha20_quarterround(&x[0], &x[5], &x[10], &x[15]);
        chacha20_quarterround(&x[1], &x[6], &x[11], &x[12]);
        chacha20_quarterround(&x[2], &x[7], &x[8], &x[13]);
        chacha20_quarterround(&x[3], &x[4], &x[9], &x[14]);
    }
    for (i = 0; i < 16; i++) {
        x[i] += st[i];
        store32_le_u32(out + 4 * i, x[i]);
    }
}

static void
hchacha20(uint8_t out[32], const uint8_t nonce[16], const uint8_t key[32])
{
    uint32_t             x[16];
    int                  i;

    x[0] = 0x61707865U;
    x[1] = 0x3320646eU;
    x[2] = 0x79622d32U;
    x[3] = 0x6b206574U;
    for (i = 0; i < 8; i++) {
        x[4 + i] = load32_le_u32(key + 4 * i);
    }
    x[12] = load32_le_u32(nonce + 0);
    x[13] = load32_le_u32(nonce + 4);
    x[14] = load32_le_u32(nonce + 8);
    x[15] = load32_le_u32(nonce + 12);

    for (i = 0; i < 10; i++) {
        chacha20_quarterround(&x[0], &x[4], &x[8], &x[12]);
        chacha20_quarterround(&x[1], &x[5], &x[9], &x[13]);
        chacha20_quarterround(&x[2], &x[6], &x[10], &x[14]);
        chacha20_quarterround(&x[3], &x[7], &x[11], &x[15]);
        chacha20_quarterround(&x[0], &x[5], &x[10], &x[15]);
        chacha20_quarterround(&x[1], &x[6], &x[11], &x[12]);
        chacha20_quarterround(&x[2], &x[7], &x[8], &x[13]);
        chacha20_quarterround(&x[3], &x[4], &x[9], &x[14]);
    }

    store32_le_u32(out + 0, x[0]);
    store32_le_u32(out + 4, x[1]);
    store32_le_u32(out + 8, x[2]);
    store32_le_u32(out + 12, x[3]);
    store32_le_u32(out + 16, x[12]);
    store32_le_u32(out + 20, x[13]);
    store32_le_u32(out + 24, x[14]);
    store32_le_u32(out + 28, x[15]);
}

static int
xchacha20_xor_ic(uint8_t *c, const uint8_t *m, uint64_t mlen,
                 const uint8_t n[24], uint64_t ic, const uint8_t k[32])
{
    uint8_t  subkey[32];
    uint8_t  nonce8[8];
    uint8_t  block[64];
    uint32_t ctr_low;
    uint32_t ctr_high;
    size_t   i;
    size_t   take;
    uint32_t st[16];
    uint32_t x[16];
    int      r;

    static const uint32_t c0 = 0x61707865U;
    static const uint32_t c1 = 0x3320646eU;
    static const uint32_t c2 = 0x79622d32U;
    static const uint32_t c3 = 0x6b206574U;

    hchacha20(subkey, n, k);
    memcpy(nonce8, n + 16, 8);
    ctr_low = (uint32_t) (ic & 0xffffffffU);
    ctr_high = (uint32_t) (ic >> 32);

    while (mlen > 0ULL) {
        st[0] = c0; st[1] = c1; st[2] = c2; st[3] = c3;
        for (r = 0; r < 8; r++) {
            st[4 + r] = load32_le_u32(subkey + 4 * r);
        }
        st[12] = ctr_low;
        st[13] = ctr_high;
        st[14] = load32_le_u32(nonce8 + 0);
        st[15] = load32_le_u32(nonce8 + 4);

        for (r = 0; r < 16; r++) {
            x[r] = st[r];
        }
        for (r = 0; r < 10; r++) {
            chacha20_quarterround(&x[0], &x[4], &x[8], &x[12]);
            chacha20_quarterround(&x[1], &x[5], &x[9], &x[13]);
            chacha20_quarterround(&x[2], &x[6], &x[10], &x[14]);
            chacha20_quarterround(&x[3], &x[7], &x[11], &x[15]);
            chacha20_quarterround(&x[0], &x[5], &x[10], &x[15]);
            chacha20_quarterround(&x[1], &x[6], &x[11], &x[12]);
            chacha20_quarterround(&x[2], &x[7], &x[8], &x[13]);
            chacha20_quarterround(&x[3], &x[4], &x[9], &x[14]);
        }
        for (r = 0; r < 16; r++) {
            x[r] += st[r];
            store32_le_u32(block + 4 * r, x[r]);
        }
        ctr_low++;
        if (ctr_low == 0U) {
            ctr_high++;
        }

        take = (size_t) ((mlen < 64ULL) ? mlen : 64ULL);
        if (m == NULL) {
            for (i = 0; i < take; i++) {
                c[i] = block[i];
            }
        } else {
            for (i = 0; i < take; i++) {
                c[i] = (uint8_t) (m[i] ^ block[i]);
            }
        }
        c += take;
        if (m != NULL) {
            m += take;
        }
        mlen -= (uint64_t) take;
    }
    naion_memzero(subkey, sizeof subkey);
    naion_memzero(block, sizeof block);
    return SIMPLE_SODIUM_OK;
}

/* ------------------------------------------------------------------------- */
/* Poly1305 + XChaCha20-Poly1305 (IETF) helpers */
/* ------------------------------------------------------------------------- */

typedef struct _naion_poly1305_state {
    uint32_t r0, r1, r2, r3, r4;
    uint32_t s1, s2, s3, s4;
    uint32_t h0, h1, h2, h3, h4;
    uint32_t pad0, pad1, pad2, pad3;
    size_t   leftover;
    uint8_t  buffer[16];
    uint8_t  final;
} _naion_poly1305_state;

static void
poly1305_blocks(_naion_poly1305_state *st, const uint8_t *m, size_t bytes)
{
    const uint32_t hibit = st->final ? 0U : (1U << 24);
    uint32_t       r0 = st->r0;
    uint32_t       r1 = st->r1;
    uint32_t       r2 = st->r2;
    uint32_t       r3 = st->r3;
    uint32_t       r4 = st->r4;
    uint32_t       s1 = st->s1;
    uint32_t       s2 = st->s2;
    uint32_t       s3 = st->s3;
    uint32_t       s4 = st->s4;
    uint32_t       h0 = st->h0;
    uint32_t       h1 = st->h1;
    uint32_t       h2 = st->h2;
    uint32_t       h3 = st->h3;
    uint32_t       h4 = st->h4;

    while (bytes >= 16U) {
        uint32_t t0 = load32_le_u32(m + 0);
        uint32_t t1 = load32_le_u32(m + 4);
        uint32_t t2 = load32_le_u32(m + 8);
        uint32_t t3 = load32_le_u32(m + 12);
        uint64_t d0, d1, d2, d3, d4;
        uint32_t c;

        h0 += t0 & 0x3ffffffU;
        h1 += ((t0 >> 26) | (t1 << 6)) & 0x3ffffffU;
        h2 += ((t1 >> 20) | (t2 << 12)) & 0x3ffffffU;
        h3 += ((t2 >> 14) | (t3 << 18)) & 0x3ffffffU;
        h4 += (t3 >> 8) | hibit;

        d0 = ((uint64_t) h0 * r0) + ((uint64_t) h1 * s4) + ((uint64_t) h2 * s3) +
             ((uint64_t) h3 * s2) + ((uint64_t) h4 * s1);
        d1 = ((uint64_t) h0 * r1) + ((uint64_t) h1 * r0) + ((uint64_t) h2 * s4) +
             ((uint64_t) h3 * s3) + ((uint64_t) h4 * s2);
        d2 = ((uint64_t) h0 * r2) + ((uint64_t) h1 * r1) + ((uint64_t) h2 * r0) +
             ((uint64_t) h3 * s4) + ((uint64_t) h4 * s3);
        d3 = ((uint64_t) h0 * r3) + ((uint64_t) h1 * r2) + ((uint64_t) h2 * r1) +
             ((uint64_t) h3 * r0) + ((uint64_t) h4 * s4);
        d4 = ((uint64_t) h0 * r4) + ((uint64_t) h1 * r3) + ((uint64_t) h2 * r2) +
             ((uint64_t) h3 * r1) + ((uint64_t) h4 * r0);

        c = (uint32_t) (d0 >> 26); h0 = (uint32_t) d0 & 0x3ffffffU; d1 += c;
        c = (uint32_t) (d1 >> 26); h1 = (uint32_t) d1 & 0x3ffffffU; d2 += c;
        c = (uint32_t) (d2 >> 26); h2 = (uint32_t) d2 & 0x3ffffffU; d3 += c;
        c = (uint32_t) (d3 >> 26); h3 = (uint32_t) d3 & 0x3ffffffU; d4 += c;
        c = (uint32_t) (d4 >> 26); h4 = (uint32_t) d4 & 0x3ffffffU;
        h0 += c * 5U;
        c = h0 >> 26; h0 &= 0x3ffffffU;
        h1 += c;

        m += 16;
        bytes -= 16U;
    }

    st->h0 = h0;
    st->h1 = h1;
    st->h2 = h2;
    st->h3 = h3;
    st->h4 = h4;
}

static void
poly1305_init(_naion_poly1305_state *st, const uint8_t key[32])
{
    uint32_t t0 = load32_le_u32(key + 0);
    uint32_t t1 = load32_le_u32(key + 4);
    uint32_t t2 = load32_le_u32(key + 8);
    uint32_t t3 = load32_le_u32(key + 12);

    st->r0 = t0 & 0x3ffffffU;
    st->r1 = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03U;
    st->r2 = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ffU;
    st->r3 = ((t2 >> 14) | (t3 << 18)) & 0x3f03fffU;
    st->r4 = (t3 >> 8) & 0x00fffffU;

    st->s1 = st->r1 * 5U;
    st->s2 = st->r2 * 5U;
    st->s3 = st->r3 * 5U;
    st->s4 = st->r4 * 5U;

    st->h0 = 0;
    st->h1 = 0;
    st->h2 = 0;
    st->h3 = 0;
    st->h4 = 0;

    st->pad0 = load32_le_u32(key + 16);
    st->pad1 = load32_le_u32(key + 20);
    st->pad2 = load32_le_u32(key + 24);
    st->pad3 = load32_le_u32(key + 28);

    st->leftover = 0U;
    st->final = 0U;
}

static void
poly1305_update(_naion_poly1305_state *st, const uint8_t *m, size_t bytes)
{
    size_t want;

    if (st->leftover != 0U) {
        want = 16U - st->leftover;
        if (want > bytes) {
            want = bytes;
        }
        memcpy(st->buffer + st->leftover, m, want);
        bytes -= want;
        m += want;
        st->leftover += want;
        if (st->leftover < 16U) {
            return;
        }
        poly1305_blocks(st, st->buffer, 16U);
        st->leftover = 0U;
    }
    if (bytes >= 16U) {
        want = bytes & ~(size_t) 0xfU;
        poly1305_blocks(st, m, want);
        m += want;
        bytes -= want;
    }
    if (bytes != 0U) {
        memcpy(st->buffer + st->leftover, m, bytes);
        st->leftover += bytes;
    }
}

static void
poly1305_finish(_naion_poly1305_state *st, uint8_t mac[16])
{
    uint32_t h0, h1, h2, h3, h4, c;
    uint32_t g0, g1, g2, g3, g4;
    uint64_t f;
    uint32_t mask;

    if (st->leftover != 0U) {
        st->buffer[st->leftover] = 1U;
        memset(st->buffer + st->leftover + 1U, 0, 16U - st->leftover - 1U);
        st->final = 1U;
        poly1305_blocks(st, st->buffer, 16U);
    }

    h0 = st->h0;
    h1 = st->h1;
    h2 = st->h2;
    h3 = st->h3;
    h4 = st->h4;

    c = h1 >> 26; h1 &= 0x3ffffffU; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffffU; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffffU; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffffU; h0 += c * 5U;
    c = h0 >> 26; h0 &= 0x3ffffffU; h1 += c;

    g0 = h0 + 5U;
    c = g0 >> 26; g0 &= 0x3ffffffU;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffffU;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffffU;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffffU;
    g4 = h4 + c - (1U << 26);

    mask = (g4 >> 31) - 1U;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    h0 = (h0) | (h1 << 26);
    h1 = (h1 >> 6) | (h2 << 20);
    h2 = (h2 >> 12) | (h3 << 14);
    h3 = (h3 >> 18) | (h4 << 8);

    f = (uint64_t) h0 + st->pad0;
    h0 = (uint32_t) f;
    f = (uint64_t) h1 + st->pad1 + (f >> 32);
    h1 = (uint32_t) f;
    f = (uint64_t) h2 + st->pad2 + (f >> 32);
    h2 = (uint32_t) f;
    f = (uint64_t) h3 + st->pad3 + (f >> 32);
    h3 = (uint32_t) f;

    store32_le_u32(mac + 0, h0);
    store32_le_u32(mac + 4, h1);
    store32_le_u32(mac + 8, h2);
    store32_le_u32(mac + 12, h3);

    naion_memzero(st, sizeof *st);
}

static void
xchacha20_derive_subkey_nonce(uint8_t subkey[32], uint8_t nonce12[12],
                              const uint8_t npub[24], const uint8_t k[32])
{
    hchacha20(subkey, npub, k);
    nonce12[0] = 0;
    nonce12[1] = 0;
    nonce12[2] = 0;
    nonce12[3] = 0;
    memcpy(nonce12 + 4, npub + 16, 8);
#if defined(DEBUG) && DEBUG
    naion_debug_dump_hex("xchacha20.npub24", npub, 24U);
    naion_debug_dump_hex("xchacha20.key32", k, 32U);
    naion_debug_dump_hex("xchacha20.subkey32", subkey, 32U);
    naion_debug_dump_hex("xchacha20.nonce12", nonce12, 12U);
#endif
}

static void
chacha20_ietf_xor_ic(uint8_t *c, const uint8_t *m, uint64_t mlen,
                     const uint8_t nonce12[12], const uint8_t key[32],
                     uint32_t ic)
{
    uint8_t  block[64];
    uint32_t ctr = ic;
    size_t   i;
    size_t   take;

    while (mlen > 0ULL) {
        chacha20_block(block, key, ctr, nonce12);
        ctr++;
        take = (size_t) ((mlen < 64ULL) ? mlen : 64ULL);
        if (m == NULL) {
            for (i = 0; i < take; i++) {
                c[i] = block[i];
            }
        } else {
            for (i = 0; i < take; i++) {
                c[i] = (uint8_t) (m[i] ^ block[i]);
            }
        }
        c += take;
        if (m != NULL) {
            m += take;
        }
        mlen -= (uint64_t) take;
    }
    naion_memzero(block, sizeof block);
}

static void
poly1305_update_padded(_naion_poly1305_state *st,
                       const uint8_t *m, uint64_t mlen)
{
    static const uint8_t zero[16] = { 0 };
    uint64_t             rem = mlen;
    size_t               chunk;

    while (rem > 0ULL) {
        chunk = (size_t) ((rem > 0xffffffffULL) ? 0xffffffffULL : rem);
        poly1305_update(st, m, chunk);
        m += chunk;
        rem -= (uint64_t) chunk;
    }
    if ((mlen & 15ULL) != 0ULL) {
        poly1305_update(st, zero, (size_t) (16ULL - (mlen & 15ULL)));
    }
}

static int
verify16(const uint8_t x[16], const uint8_t y[16])
{
    uint32_t d = 0U;
    size_t   i;

    for (i = 0; i < 16; i++) {
        d |= (uint32_t) (x[i] ^ y[i]);
    }
    d = (d | (0U - d)) >> 31;
    return (int) (1U ^ d);
}

/* ------------------------------------------------------------------------- */
/* Random provider helper */
/* ------------------------------------------------------------------------- */

static void
naion_system_random_provider(void * const buf, const size_t size)
{
    (void) naion_system_randombytes((unsigned char *) buf, size);
}

static uint64_t
naion_mix64(uint64_t x)
{
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

static uint32_t
naion_rand_derive(uint64_t seed)
{
    uint64_t m = naion_mix64(seed);

    return (uint32_t) (m ^ (m >> 32));
}

static int
naion_fallback_randombytes(unsigned char *buf, size_t size)
{
    static uint32_t g_fallback_counter = 0U;
    static uint32_t g_fallback_global = 0U;
    uint32_t        time_param;
    uint32_t        counter_param;
    uint32_t        global_param;
    uint32_t        stack_param;
    uint32_t        heap_param;
    uint32_t        process_id_param;
    uint32_t        thread_id_param;
    uint32_t        buffer_param;
    uint32_t        seed32;
    uint64_t        state;
    uint32_t        stack_local = 0U;
    size_t          i;

    if (buf == NULL || size == 0U) {
        return SIMPLE_SODIUM_ERR;
    }

    /* 1) TIME */
    time_param = naion_rand_derive((uint64_t) time(NULL));
    /* 2) counter */
    counter_param = naion_rand_derive((uint64_t) g_fallback_counter++);
    /* 3) Global Address */
    global_param = naion_rand_derive((uint64_t) (uintptr_t) &g_fallback_global);
    /* 4) Stack Address */
    stack_param = naion_rand_derive((uint64_t) (uintptr_t) &stack_local);
    /* 5) Heap Address ^ Heap Unknown Value (8bytes) */
    {
        void    *heap_ptr = malloc(sizeof(uint64_t));
        uint64_t heap_addr = (uint64_t) (uintptr_t) heap_ptr;
        uint64_t heap_val = 0ULL;
        if (heap_ptr != NULL) {
            memcpy(&heap_val, heap_ptr, sizeof heap_val);
            free(heap_ptr);
        }
        heap_param = naion_rand_derive(heap_addr) ^ naion_rand_derive(heap_val);
    }
    /* 6) ProcessID */
#if defined(_WIN32)
    process_id_param = naion_rand_derive((uint64_t) GetCurrentProcessId());
#else
    process_id_param = naion_rand_derive((uint64_t) getpid());
#endif
    /* 7) ThreadID */
#if defined(_WIN32)
    thread_id_param = naion_rand_derive((uint64_t) GetCurrentThreadId());
#elif defined(__linux__) && defined(SYS_gettid)
    thread_id_param = naion_rand_derive((uint64_t) syscall(SYS_gettid));
#else
    thread_id_param = naion_rand_derive((uint64_t) (uintptr_t) &buf);
#endif
    /* 8) Buffer Unknown Value (1bytes) ^ Size */
    buffer_param = naion_rand_derive((uint64_t) buf[0]) ^ naion_rand_derive((uint64_t) size);

    seed32 = time_param ^ counter_param ^ global_param ^ stack_param ^
             heap_param ^ process_id_param ^ thread_id_param ^ buffer_param;
    state = naion_mix64(((uint64_t) seed32 << 32) ^
                        (uint64_t) (uintptr_t) buf ^ (uint64_t) size);

    for (i = 0U; i < size; i++) {
        state = naion_mix64(state + (uint64_t) i + 0x9e3779b97f4a7c15ULL);
        buf[i] = (unsigned char) (state & 0xffU);
    }

    return SIMPLE_SODIUM_OK;
}

#if defined(_WIN32)
static int
naion_system_randombytes(unsigned char *buf, size_t size)
{
    HMODULE hmod;
    size_t  off = 0U;

    if (buf == NULL || size == 0U) {
        return SIMPLE_SODIUM_ERR;
    }

#ifndef BCRYPT_USE_SYSTEM_PREFERRED_RNG
#define BCRYPT_USE_SYSTEM_PREFERRED_RNG 0x00000002UL
#endif
    hmod = LoadLibraryA("bcrypt.dll");
    if (hmod != NULL) {
        typedef LONG (WINAPI *bcrypt_genrandom_fn)(void *, unsigned char *, unsigned long, unsigned long);
        bcrypt_genrandom_fn fn = (bcrypt_genrandom_fn) GetProcAddress(hmod, "BCryptGenRandom");
        if (fn != NULL) {
            while (off < size) {
                unsigned long chunk = (unsigned long) ((size - off) > 0xffffffffUL ? 0xffffffffUL : (size - off));
                if (fn(NULL, buf + off, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
                    break;
                }
                off += (size_t) chunk;
            }
            FreeLibrary(hmod);
            if (off == size) {
                return SIMPLE_SODIUM_OK;
            }
            off = 0U;
        } else {
            FreeLibrary(hmod);
        }
    }

    hmod = LoadLibraryA("advapi32.dll");
    if (hmod != NULL) {
        typedef BOOL (WINAPI *crypt_acquire_fn)(HCRYPTPROV *, LPCSTR, LPCSTR, DWORD, DWORD);
        typedef BOOL (WINAPI *crypt_genrandom_fn)(HCRYPTPROV, DWORD, BYTE *);
        typedef BOOL (WINAPI *crypt_release_fn)(HCRYPTPROV, DWORD);
        crypt_acquire_fn acquire_fn = (crypt_acquire_fn) GetProcAddress(hmod, "CryptAcquireContextA");
        crypt_genrandom_fn gen_fn = (crypt_genrandom_fn) GetProcAddress(hmod, "CryptGenRandom");
        crypt_release_fn release_fn = (crypt_release_fn) GetProcAddress(hmod, "CryptReleaseContext");
        if (acquire_fn != NULL && gen_fn != NULL && release_fn != NULL) {
            HCRYPTPROV hprov = 0;
            if (acquire_fn(&hprov, NULL, NULL, PROV_RSA_FULL,
                           CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
                while (off < size) {
                    DWORD chunk = (DWORD) ((size - off) > 0xffffffffUL ? 0xffffffffUL : (size - off));
                    if (!gen_fn(hprov, chunk, (BYTE *) (buf + off))) {
                        break;
                    }
                    off += (size_t) chunk;
                }
                (void) release_fn(hprov, 0U);
            }
        }
        FreeLibrary(hmod);
    }

    return off == size ? SIMPLE_SODIUM_OK : SIMPLE_SODIUM_ERR;
}
#else
static int
naion_try_getrandom(unsigned char *buf, size_t size)
{
#if defined(NAION_HAVE_GETRANDOM)
    size_t off = 0U;

    while (off < size) {
        ssize_t n = getrandom(buf + off, size - off, 0U);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            return SIMPLE_SODIUM_ERR;
        }
        if (n == 0) {
            return SIMPLE_SODIUM_ERR;
        }
        off += (size_t) n;
    }
    return SIMPLE_SODIUM_OK;
#else
    (void) buf;
    (void) size;
    return SIMPLE_SODIUM_ERR;
#endif
}

static int
naion_try_arc4random(unsigned char *buf, size_t size)
{
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__) || defined(__DragonFly__)
    arc4random_buf(buf, size);
    return SIMPLE_SODIUM_OK;
#else
    (void) buf;
    (void) size;
    return SIMPLE_SODIUM_ERR;
#endif
}

static int
naion_system_randombytes(unsigned char *buf, size_t size)
{
    const char *devs[2] = { "/dev/urandom", "/dev/random" };
    int         idx;

    if (buf == NULL || size == 0U) {
        return SIMPLE_SODIUM_ERR;
    }
    if (naion_try_getrandom(buf, size) == SIMPLE_SODIUM_OK) {
        return SIMPLE_SODIUM_OK;
    }
    if (naion_try_arc4random(buf, size) == SIMPLE_SODIUM_OK) {
        return SIMPLE_SODIUM_OK;
    }
    for (idx = 0; idx < 2; idx++) {
        int    fd = open(devs[idx], O_RDONLY);
        size_t off = 0U;
        if (fd < 0) {
            continue;
        }
        while (off < size) {
            ssize_t n = read(fd, buf + off, size - off);
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }
            if (n == 0) {
                break;
            }
            off += (size_t) n;
        }
        (void) close(fd);
        if (off == size) {
            return SIMPLE_SODIUM_OK;
        }
    }

    return SIMPLE_SODIUM_ERR;
}
#endif

static int
fill_random(unsigned char *buf, size_t size)
{
    naion_random_provider_fn provider;

    if (buf == NULL || size == 0U) {
        return SIMPLE_SODIUM_ERR;
    }
    provider = naion_get_random_provider();
    if (provider == naion_system_random_provider) {
        if (naion_system_randombytes(buf, size) == SIMPLE_SODIUM_OK) {
            return SIMPLE_SODIUM_OK;
        }
        return naion_fallback_randombytes(buf, size);
    }
    provider(buf, size);
    return SIMPLE_SODIUM_OK;
}

void
_naion_internal_randombytes_buf(void * const buf, const size_t size)
{
    if (fill_random((unsigned char *) buf, size) != SIMPLE_SODIUM_OK) {
        naion_memzero(buf, size);
    }
}

int
naion_memcmp(const void *b1_, const void *b2_, size_t len)
{
    const unsigned char *b1 = (const unsigned char *) b1_;
    const unsigned char *b2 = (const unsigned char *) b2_;
    unsigned char        d = 0U;
    size_t               i;

    for (i = 0U; i < len; i++) {
        d |= (unsigned char) (b1[i] ^ b2[i]);
    }
    return (int) ((1U & ((d - 1U) >> 8U)) - 1U);
}

int
naion_verify_32(const unsigned char *x, const unsigned char *y)
{
    return naion_memcmp(x, y, 32U);
}

int
naion_is_zero(const unsigned char *n, const size_t nlen)
{
    unsigned char d = 0U;
    size_t        i;

    for (i = 0U; i < nlen; i++) {
        d |= n[i];
    }
    return (int) (1U & ((d - 1U) >> 8U));
}

int
naion_init(void)
{
    /* TODO: add platform-specific one-time init work if needed. */
    return SIMPLE_SODIUM_OK;
}

#if NAION_LAYER_SYMM
void
naion_set_random_provider(naion_random_provider_fn provider)
{
    g_random_provider = provider;
}

naion_random_provider_fn
naion_get_random_provider(void)
{
    return g_random_provider != NULL ? g_random_provider : naion_system_random_provider;
}

void
naion_memzero(void *pnt, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *) pnt;
    while (len-- > 0U) {
        *p++ = 0U;
    }
}

int
naion_generichash(unsigned char *out, size_t outlen,
                   const unsigned char *in, unsigned long long inlen,
                   const unsigned char *key, size_t keylen)
{
    if (out == NULL || !size_in_range(outlen, naion_generichash_BYTES_MIN, naion_generichash_BYTES_MAX)) {
        return SIMPLE_SODIUM_ERR;
    }
    if (in == NULL && inlen > 0ULL) {
        return SIMPLE_SODIUM_ERR;
    }
    if (keylen != 0U && (key == NULL || !size_in_range(keylen, naion_generichash_KEYBYTES_MIN, naion_generichash_KEYBYTES_MAX))) {
        return SIMPLE_SODIUM_ERR;
    }
    if (keylen == 0U && key != NULL) {
        return SIMPLE_SODIUM_ERR;
    }

    return _naion_blake2b(out, (uint8_t) outlen, in, (uint64_t) inlen, key, (uint8_t) keylen);
}

int
naion_generichash_init(naion_generichash_state *state,
                        const unsigned char *key, size_t keylen,
                        size_t outlen)
{
    if (state == NULL || !size_in_range(outlen, naion_generichash_BYTES_MIN, naion_generichash_BYTES_MAX)) {
        return SIMPLE_SODIUM_ERR;
    }
    if (keylen != 0U && (key == NULL || !size_in_range(keylen, naion_generichash_KEYBYTES_MIN, naion_generichash_KEYBYTES_MAX))) {
        return SIMPLE_SODIUM_ERR;
    }
    if (keylen == 0U && key != NULL) {
        return SIMPLE_SODIUM_ERR;
    }
    if (sizeof(_naion_blake2b_state) > sizeof(state->opaque)) {
        return SIMPLE_SODIUM_ERR;
    }

    if (keylen == 0U) {
        return _naion_blake2b_init((_naion_blake2b_state *) (void *) state->opaque,
                                   (uint8_t) outlen);
    }
    return _naion_blake2b_init_key((_naion_blake2b_state *) (void *) state->opaque,
                                   (uint8_t) outlen, key, (uint8_t) keylen);
}

int
naion_generichash_update(naion_generichash_state *state,
                          const unsigned char *in, unsigned long long inlen)
{
    if (state == NULL || (in == NULL && inlen > 0ULL)) {
        return SIMPLE_SODIUM_ERR;
    }

    return _naion_blake2b_update((_naion_blake2b_state *) (void *) state->opaque,
                                 in, (uint64_t) inlen);
}

int
naion_generichash_final(naion_generichash_state *state,
                         unsigned char *out, size_t outlen)
{
    if (state == NULL || out == NULL ||
        !size_in_range(outlen, naion_generichash_BYTES_MIN, naion_generichash_BYTES_MAX)) {
        return SIMPLE_SODIUM_ERR;
    }

    return _naion_blake2b_final((_naion_blake2b_state *) (void *) state->opaque,
                                out, (uint8_t) outlen);
}

int
naion_stream_xchacha20(unsigned char *c, unsigned long long clen,
                        const unsigned char *n, const unsigned char *k)
{
    if (c == NULL || n == NULL || k == NULL) {
        return SIMPLE_SODIUM_ERR;
    }
    return xchacha20_xor_ic(c, NULL, (uint64_t) clen, n, 0ULL, k);
}

int
naion_stream_xchacha20_xor(unsigned char *c, const unsigned char *m,
                            unsigned long long mlen,
                            const unsigned char *n, const unsigned char *k)
{
    if (c == NULL || n == NULL || k == NULL || (m == NULL && mlen > 0ULL)) {
        return SIMPLE_SODIUM_ERR;
    }

    return xchacha20_xor_ic(c, m, (uint64_t) mlen, n, 0ULL, k);
}

int
naion_stream_xchacha20_xor_ic(unsigned char *c, const unsigned char *m,
                               unsigned long long mlen,
                               const unsigned char *n, uint64_t ic,
                               const unsigned char *k)
{
    if (c == NULL || n == NULL || k == NULL || (m == NULL && mlen > 0ULL)) {
        return SIMPLE_SODIUM_ERR;
    }
    return xchacha20_xor_ic(c, m, (uint64_t) mlen, n, ic, k);
}

#endif /* NAION_LAYER_SYMM */

/* ========================================================================= */
/* Layer 2 implementations — AEAD-IETF + secretbox + box symmetric core    */
/* ========================================================================= */
#if NAION_LAYER_AEAD

/*
 * Combined AEAD layout matches libsodium: ciphertext || mac.
 * This intentionally differs from naion_box_*_easy()/secretbox_easy(),
 * whose combined buffers are mac || ciphertext.
 */
int
naion_aead_xchacha20poly1305_ietf_encrypt(
    unsigned char *c, unsigned long long *clen_p,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k)
{
    if (clen_p != NULL) {
        *clen_p = 0ULL;
    }
    if (c == NULL || clen_p == NULL || npub == NULL || k == NULL || nsec != NULL ||
        (m == NULL && mlen > 0ULL) || (ad == NULL && adlen > 0ULL)) {
        return SIMPLE_SODIUM_ERR;
    }
    if (mlen > 0ULL && m == NULL) {
        return SIMPLE_SODIUM_ERR;
    }
    if (naion_aead_xchacha20poly1305_ietf_encrypt_detached(
            c, c + mlen, NULL,
            m, mlen, ad, adlen, NULL, npub, k) != SIMPLE_SODIUM_OK) {
        return SIMPLE_SODIUM_ERR;
    }
    *clen_p = mlen + naion_aead_xchacha20poly1305_ietf_ABYTES;
    return SIMPLE_SODIUM_OK;
}

/*
 * Expects libsodium-style combined AEAD input: ciphertext || mac.
 * Do not feed naion_box_*_easy()/secretbox_easy() mac || ciphertext
 * buffers here without reordering.
 */
int
naion_aead_xchacha20poly1305_ietf_decrypt(
    unsigned char *m, unsigned long long *mlen_p,
    unsigned char *nsec,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k)
{
    if (mlen_p != NULL) {
        *mlen_p = 0ULL;
    }
    if (m == NULL || mlen_p == NULL || c == NULL || npub == NULL || k == NULL ||
        nsec != NULL || clen < naion_aead_xchacha20poly1305_ietf_ABYTES ||
        (ad == NULL && adlen > 0ULL)) {
        return SIMPLE_SODIUM_ERR;
    }
    if (naion_aead_xchacha20poly1305_ietf_decrypt_detached(
            m, NULL,
            c,
            clen - naion_aead_xchacha20poly1305_ietf_ABYTES,
            c + (clen - naion_aead_xchacha20poly1305_ietf_ABYTES), ad, adlen, npub, k) != SIMPLE_SODIUM_OK) {
        return SIMPLE_SODIUM_ERR;
    }
    *mlen_p = clen - naion_aead_xchacha20poly1305_ietf_ABYTES;
    return SIMPLE_SODIUM_OK;
}

int
naion_aead_xchacha20poly1305_ietf_encrypt_detached(
    unsigned char *c, unsigned char *mac, unsigned long long *maclen_p,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k)
{
    if (maclen_p != NULL) {
        *maclen_p = 0ULL;
    }
    if (c == NULL || mac == NULL || npub == NULL || k == NULL || nsec != NULL ||
        (m == NULL && mlen > 0ULL) || (ad == NULL && adlen > 0ULL)) {
        return SIMPLE_SODIUM_ERR;
    }
    {
        uint8_t               subkey[32];
        uint8_t               nonce12[12];
        uint8_t               block0[64];
        uint8_t               lens[16];
        _naion_poly1305_state st;

        xchacha20_derive_subkey_nonce(subkey, nonce12, npub, k);
        chacha20_block(block0, subkey, 0U, nonce12);
        poly1305_init(&st, block0);

        chacha20_ietf_xor_ic(c, m, (uint64_t) mlen, nonce12, subkey, 1U);

        poly1305_update_padded(&st, ad, adlen);
        poly1305_update_padded(&st, c, mlen);
        store64_le(lens + 0, (uint64_t) adlen);
        store64_le(lens + 8, (uint64_t) mlen);
        poly1305_update(&st, lens, sizeof lens);
        poly1305_finish(&st, mac);

        naion_memzero(subkey, sizeof subkey);
        naion_memzero(block0, sizeof block0);
        naion_memzero(lens, sizeof lens);
    }
    if (maclen_p != NULL) {
        *maclen_p = naion_aead_xchacha20poly1305_ietf_ABYTES;
    }
    return SIMPLE_SODIUM_OK;
}

int
naion_aead_xchacha20poly1305_ietf_decrypt_detached(
    unsigned char *m,
    unsigned char *nsec,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *mac,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k)
{
    if (m == NULL || c == NULL || mac == NULL || npub == NULL || k == NULL ||
        nsec != NULL || (ad == NULL && adlen > 0ULL)) {
        return SIMPLE_SODIUM_ERR;
    }
    {
        uint8_t               subkey[32];
        uint8_t               nonce12[12];
        uint8_t               block0[64];
        uint8_t               lens[16];
        uint8_t               computed_mac[16];
        _naion_poly1305_state st;

        xchacha20_derive_subkey_nonce(subkey, nonce12, npub, k);
        chacha20_block(block0, subkey, 0U, nonce12);
        poly1305_init(&st, block0);

        poly1305_update_padded(&st, ad, adlen);
        poly1305_update_padded(&st, c, clen);
        store64_le(lens + 0, (uint64_t) adlen);
        store64_le(lens + 8, (uint64_t) clen);
        poly1305_update(&st, lens, sizeof lens);
        poly1305_finish(&st, computed_mac);

        if (verify16(mac, computed_mac) != 1) {
            naion_memzero(subkey, sizeof subkey);
            naion_memzero(block0, sizeof block0);
            naion_memzero(lens, sizeof lens);
            naion_memzero(computed_mac, sizeof computed_mac);
            return SIMPLE_SODIUM_ERR;
        }

        chacha20_ietf_xor_ic(m, c, clen, nonce12, subkey, 1U);
        naion_memzero(subkey, sizeof subkey);
        naion_memzero(block0, sizeof block0);
        naion_memzero(lens, sizeof lens);
        naion_memzero(computed_mac, sizeof computed_mac);
    }
    return SIMPLE_SODIUM_OK;
}

int
naion_secretbox_xchacha20poly1305_easy(unsigned char *c,
                                        const unsigned char *m,
                                        unsigned long long mlen,
                                        const unsigned char *n,
                                        const unsigned char *k)
{
    return naion_box_curve25519xchacha20poly1305_easy_afternm(c, m, mlen, n, k);
}

int
naion_secretbox_xchacha20poly1305_open_easy(unsigned char *m,
                                             const unsigned char *c,
                                             unsigned long long clen,
                                             const unsigned char *n,
                                             const unsigned char *k)
{
    return naion_box_curve25519xchacha20poly1305_open_easy_afternm(m, c, clen, n, k);
}

int
naion_secretbox_xchacha20poly1305_detached(unsigned char *c,
                                            unsigned char *mac,
                                            const unsigned char *m,
                                            unsigned long long mlen,
                                            const unsigned char *n,
                                            const unsigned char *k)
{
    unsigned char      *combined;
    unsigned long long  combined_len;
    int                 ret;

    if (c == NULL || mac == NULL || n == NULL || k == NULL ||
        (m == NULL && mlen > 0ULL)) {
        return SIMPLE_SODIUM_ERR;
    }
    if (mlen > (unsigned long long) (SIZE_MAX - naion_secretbox_xchacha20poly1305_MACBYTES)) {
        return SIMPLE_SODIUM_ERR;
    }
    combined_len = mlen + naion_secretbox_xchacha20poly1305_MACBYTES;
    combined = (unsigned char *) malloc((size_t) combined_len);
    if (combined == NULL) {
        return SIMPLE_SODIUM_ERR;
    }
    ret = naion_secretbox_xchacha20poly1305_easy(combined, m, mlen, n, k);
    if (ret == SIMPLE_SODIUM_OK) {
        memcpy(mac, combined, naion_secretbox_xchacha20poly1305_MACBYTES);
        if (mlen > 0ULL) {
            memcpy(c,
                   combined + naion_secretbox_xchacha20poly1305_MACBYTES,
                   (size_t) mlen);
        }
    }
    naion_memzero(combined, (size_t) combined_len);
    free(combined);
    return ret;
}

int
naion_secretbox_xchacha20poly1305_open_detached(unsigned char *m,
                                                 const unsigned char *c,
                                                 const unsigned char *mac,
                                                 unsigned long long clen,
                                                 const unsigned char *n,
                                                 const unsigned char *k)
{
    unsigned char      *combined;
    unsigned long long  combined_len;
    int                 ret;

    if (m == NULL || c == NULL || mac == NULL || n == NULL || k == NULL) {
        return SIMPLE_SODIUM_ERR;
    }
    if (clen > (unsigned long long) (SIZE_MAX - naion_secretbox_xchacha20poly1305_MACBYTES)) {
        return SIMPLE_SODIUM_ERR;
    }
    combined_len = clen + naion_secretbox_xchacha20poly1305_MACBYTES;
    combined = (unsigned char *) malloc((size_t) combined_len);
    if (combined == NULL) {
        return SIMPLE_SODIUM_ERR;
    }
    memcpy(combined, mac, naion_secretbox_xchacha20poly1305_MACBYTES);
    if (clen > 0ULL) {
        memcpy(combined + naion_secretbox_xchacha20poly1305_MACBYTES,
               c, (size_t) clen);
    }
    ret = naion_secretbox_xchacha20poly1305_open_easy(m, combined, combined_len, n, k);
    naion_memzero(combined, (size_t) combined_len);
    free(combined);
    return ret;
}

/* Box symmetric core: pure XChaCha20-Poly1305 (no Curve25519). Lives at the
 * AEAD layer because secretbox delegates to it; the asymmetric box wrappers
 * (beforenm/easy/seal) that add X25519 key agreement live at Layer 3. */
int
naion_box_curve25519xchacha20poly1305_easy_afternm(
    unsigned char *c, const unsigned char *m, unsigned long long mlen,
    const unsigned char *n, const unsigned char *k)
{
    if (c == NULL || n == NULL || k == NULL || (m == NULL && mlen > 0ULL)) {
        return SIMPLE_SODIUM_ERR;
    }
#if defined(DEBUG) && DEBUG
    naion_debug_dump_hex("box.easy_afternm.nonce", n, 24U);
    naion_debug_dump_hex("box.easy_afternm.k_nm", k, 32U);
    if (m != NULL) {
        naion_debug_dump_hex("box.easy_afternm.msg", m, (size_t) mlen);
    }
#endif

    {
        uint8_t               block0[64];
        _naion_poly1305_state st;
        uint64_t              rem;
        size_t                first_take;
        int                   ret;

        memset(block0, 0, sizeof block0);
        first_take = (size_t) ((mlen < 32ULL) ? mlen : 32ULL);
        if (first_take > 0U) {
            memcpy(block0 + 32U, m, first_take);
        }
        ret = naion_stream_xchacha20_xor_ic(block0, block0,
                                            (unsigned long long) (32U + first_take),
                                            n, 0ULL, k);
        if (ret != SIMPLE_SODIUM_OK) {
            naion_memzero(block0, sizeof block0);
            return SIMPLE_SODIUM_ERR;
        }
        poly1305_init(&st, block0);
        if (first_take > 0U) {
            memcpy(c + naion_box_curve25519xchacha20poly1305_MACBYTES,
                   block0 + 32U, first_take);
        }
        rem = mlen - (uint64_t) first_take;
        if (rem > 0ULL) {
            ret = naion_stream_xchacha20_xor_ic(
                c + naion_box_curve25519xchacha20poly1305_MACBYTES + first_take,
                m + first_take,
                rem,
                n, 1ULL, k);
            if (ret != SIMPLE_SODIUM_OK) {
                naion_memzero(block0, sizeof block0);
                naion_memzero(&st, sizeof st);
                return SIMPLE_SODIUM_ERR;
            }
        }

        poly1305_update(&st,
                        c + naion_box_curve25519xchacha20poly1305_MACBYTES,
                        (size_t) mlen);
        poly1305_finish(&st, c);
        ret = SIMPLE_SODIUM_OK;

        naion_memzero(block0, sizeof block0);
        naion_memzero(&st, sizeof st);
#if defined(DEBUG) && DEBUG
        if (ret == SIMPLE_SODIUM_OK) {
            naion_debug_dump_hex("box.easy_afternm.mac", c, 16U);
            naion_debug_dump_hex("box.easy_afternm.cipher",
                                 c + naion_box_curve25519xchacha20poly1305_MACBYTES,
                                 (size_t) mlen);
        } else {
            printf("[naion][dbg] box.easy_afternm ret=%d\n", ret);
        }
#endif
        return ret;
    }
}

int
naion_box_curve25519xchacha20poly1305_open_easy_afternm(
    unsigned char *m, const unsigned char *c, unsigned long long clen,
    const unsigned char *n, const unsigned char *k)
{
    if (m == NULL || c == NULL || n == NULL || k == NULL ||
        clen < naion_box_curve25519xchacha20poly1305_MACBYTES) {
        return SIMPLE_SODIUM_ERR;
    }
#if defined(DEBUG) && DEBUG
    naion_debug_dump_hex("box.open_easy_afternm.nonce", n, 24U);
    naion_debug_dump_hex("box.open_easy_afternm.k_nm", k, 32U);
    naion_debug_dump_hex("box.open_easy_afternm.mac", c, 16U);
    naion_debug_dump_hex("box.open_easy_afternm.cipher",
                         c + naion_box_curve25519xchacha20poly1305_MACBYTES,
                         (size_t) (clen - naion_box_curve25519xchacha20poly1305_MACBYTES));
#endif

    {
        uint8_t               block0[64];
        uint8_t               computed_mac[16];
        _naion_poly1305_state st;
        const unsigned char  *cipher =
            c + naion_box_curve25519xchacha20poly1305_MACBYTES;
        const unsigned long long mlen =
            clen - naion_box_curve25519xchacha20poly1305_MACBYTES;
        size_t                first_take;
        uint64_t              rem;
        int                   ret;

        memset(block0, 0, sizeof block0);
        first_take = (size_t) ((mlen < 32ULL) ? mlen : 32ULL);
        if (first_take > 0U) {
            memcpy(block0 + 32U, cipher, first_take);
        }
        ret = naion_stream_xchacha20_xor_ic(block0, block0, sizeof block0, n, 0ULL, k);
        if (ret != SIMPLE_SODIUM_OK) {
            naion_memzero(block0, sizeof block0);
            return SIMPLE_SODIUM_ERR;
        }
        poly1305_init(&st, block0);
        poly1305_update(&st, cipher, (size_t) mlen);
        poly1305_finish(&st, computed_mac);

        if (verify16(c, computed_mac) != 1) {
            naion_memzero(block0, sizeof block0);
            naion_memzero(computed_mac, sizeof computed_mac);
            naion_memzero(&st, sizeof st);
            return SIMPLE_SODIUM_ERR;
        }
        if (first_take > 0U) {
            memcpy(m, block0 + 32U, first_take);
        }
        rem = mlen - (uint64_t) first_take;
        if (rem > 0ULL) {
            ret = naion_stream_xchacha20_xor_ic(m + first_take, cipher + first_take, rem, n, 1ULL, k);
        } else {
            ret = SIMPLE_SODIUM_OK;
        }
        naion_memzero(block0, sizeof block0);
        naion_memzero(computed_mac, sizeof computed_mac);
        naion_memzero(&st, sizeof st);
        if (ret != SIMPLE_SODIUM_OK) {
            return SIMPLE_SODIUM_ERR;
        }
        ret = SIMPLE_SODIUM_OK;
#if defined(DEBUG) && DEBUG
        if (ret == SIMPLE_SODIUM_OK) {
            naion_debug_dump_hex("box.open_easy_afternm.msg",
                                 m,
                                 (size_t) (clen - naion_box_curve25519xchacha20poly1305_MACBYTES));
        } else {
            printf("[naion][dbg] box.open_easy_afternm ret=%d\n", ret);
        }
#endif
        return ret;
    }
}

#if NAION_XSALSA20
int
naion_secretbox_xsalsa20poly1305_easy(unsigned char *c,
                                      const unsigned char *m,
                                      unsigned long long mlen,
                                      const unsigned char *n,
                                      const unsigned char *k)
{
    return naion_box_curve25519xsalsa20poly1305_easy_afternm(c, m, mlen, n, k);
}

int
naion_secretbox_xsalsa20poly1305_open_easy(unsigned char *m,
                                           const unsigned char *c,
                                           unsigned long long clen,
                                           const unsigned char *n,
                                           const unsigned char *k)
{
    return naion_box_curve25519xsalsa20poly1305_open_easy_afternm(m, c, clen, n, k);
}

int
naion_secretbox_xsalsa20poly1305_detached(unsigned char *c,
                                          unsigned char *mac,
                                          const unsigned char *m,
                                          unsigned long long mlen,
                                          const unsigned char *n,
                                          const unsigned char *k)
{
    unsigned char      *combined;
    unsigned long long  combined_len;
    int                 ret;

    if (c == NULL || mac == NULL || n == NULL || k == NULL ||
        (m == NULL && mlen > 0ULL)) {
        return SIMPLE_SODIUM_ERR;
    }
    if (mlen > (unsigned long long) (SIZE_MAX - naion_secretbox_xsalsa20poly1305_MACBYTES)) {
        return SIMPLE_SODIUM_ERR;
    }
    combined_len = mlen + naion_secretbox_xsalsa20poly1305_MACBYTES;
    combined = (unsigned char *) malloc((size_t) combined_len);
    if (combined == NULL) {
        return SIMPLE_SODIUM_ERR;
    }
    ret = naion_secretbox_xsalsa20poly1305_easy(combined, m, mlen, n, k);
    if (ret == SIMPLE_SODIUM_OK) {
        memcpy(mac, combined, naion_secretbox_xsalsa20poly1305_MACBYTES);
        if (mlen > 0ULL) {
            memcpy(c,
                   combined + naion_secretbox_xsalsa20poly1305_MACBYTES,
                   (size_t) mlen);
        }
    }
    naion_memzero(combined, (size_t) combined_len);
    free(combined);
    return ret;
}

int
naion_secretbox_xsalsa20poly1305_open_detached(unsigned char *m,
                                                const unsigned char *c,
                                               const unsigned char *mac,
                                                unsigned long long clen,
                                                const unsigned char *n,
                                                const unsigned char *k)
{
    unsigned char      *combined;
    unsigned long long  combined_len;
    int                 ret;

    if (m == NULL || c == NULL || mac == NULL || n == NULL || k == NULL) {
        return SIMPLE_SODIUM_ERR;
    }
    if (clen > (unsigned long long) (SIZE_MAX - naion_secretbox_xsalsa20poly1305_MACBYTES)) {
        return SIMPLE_SODIUM_ERR;
    }
    combined_len = clen + naion_secretbox_xsalsa20poly1305_MACBYTES;
    combined = (unsigned char *) malloc((size_t) combined_len);
    if (combined == NULL) {
        return SIMPLE_SODIUM_ERR;
    }
    memcpy(combined, mac, naion_secretbox_xsalsa20poly1305_MACBYTES);
    if (clen > 0ULL) {
        memcpy(combined + naion_secretbox_xsalsa20poly1305_MACBYTES,
               c, (size_t) clen);
    }
    ret = naion_secretbox_xsalsa20poly1305_open_easy(m, combined, combined_len, n, k);
    naion_memzero(combined, (size_t) combined_len);
    free(combined);
    return ret;
}
#endif /* NAION_XSALSA20 */

#endif /* NAION_LAYER_AEAD */

/* ========================================================================= */
/* Layer 3 implementations — X25519/KX + asymmetric box + Ed25519 + CSM    */
/* ========================================================================= */
#if NAION_LAYER_CSM

int
naion_scalarmult_curve25519(unsigned char *q,
                             const unsigned char *n,
                             const unsigned char *p)
{
    if (q == NULL || n == NULL || p == NULL) {
        return SIMPLE_SODIUM_ERR;
    }

    return _naion_x25519_scalarmult(q, n, p);
}

int
naion_scalarmult_curve25519_base(unsigned char *q, const unsigned char *n)
{
    if (q == NULL || n == NULL) {
        return SIMPLE_SODIUM_ERR;
    }

    return _naion_x25519_scalarmult_base(q, n);
}

int
naion_kx_keypair(unsigned char *pk, unsigned char *sk)
{
    if (pk == NULL || sk == NULL) {
        return SIMPLE_SODIUM_ERR;
    }

    if (fill_random(sk, naion_kx_SECRETKEYBYTES) != SIMPLE_SODIUM_OK) {
        return SIMPLE_SODIUM_ERR;
    }
    return naion_scalarmult_curve25519_base(pk, sk);
}

int
naion_kx_seed_keypair(unsigned char *pk, unsigned char *sk,
                       const unsigned char *seed)
{
    if (pk == NULL || sk == NULL || seed == NULL) {
        return SIMPLE_SODIUM_ERR;
    }

    if (naion_generichash(sk, naion_kx_SECRETKEYBYTES,
                           seed, naion_kx_SEEDBYTES, NULL, 0U) !=
        SIMPLE_SODIUM_OK) {
        return SIMPLE_SODIUM_ERR;
    }
    return naion_scalarmult_curve25519_base(pk, sk);
}

int
naion_kx_client_session_keys(unsigned char *rx, unsigned char *tx,
                              const unsigned char *client_pk,
                              const unsigned char *client_sk,
                              const unsigned char *server_pk)
{
    naion_generichash_state h;
    unsigned char            q[naion_scalarmult_curve25519_BYTES];
    unsigned char            keys[2 * naion_kx_SESSIONKEYBYTES];
    int                      i;

    if ((rx == NULL && tx == NULL) || client_pk == NULL ||
        client_sk == NULL || server_pk == NULL) {
        return SIMPLE_SODIUM_ERR;
    }
    if (rx == NULL) {
        rx = tx;
    }
    if (tx == NULL) {
        tx = rx;
    }
    if (naion_scalarmult_curve25519(q, client_sk, server_pk) != SIMPLE_SODIUM_OK) {
        return SIMPLE_SODIUM_ERR;
    }
    if (naion_generichash_init(&h, NULL, 0U, sizeof keys) != SIMPLE_SODIUM_OK) {
        naion_memzero(q, sizeof q);
        return SIMPLE_SODIUM_ERR;
    }
    if (naion_generichash_update(&h, q, sizeof q) != SIMPLE_SODIUM_OK ||
        naion_generichash_update(&h, client_pk, naion_kx_PUBLICKEYBYTES) != SIMPLE_SODIUM_OK ||
        naion_generichash_update(&h, server_pk, naion_kx_PUBLICKEYBYTES) != SIMPLE_SODIUM_OK ||
        naion_generichash_final(&h, keys, sizeof keys) != SIMPLE_SODIUM_OK) {
        naion_memzero(q, sizeof q);
        naion_memzero(keys, sizeof keys);
        naion_memzero(&h, sizeof h);
        return SIMPLE_SODIUM_ERR;
    }
    naion_memzero(q, sizeof q);
    naion_memzero(&h, sizeof h);
    for (i = 0; i < (int) naion_kx_SESSIONKEYBYTES; i++) {
        rx[i] = keys[i];
        tx[i] = keys[i + naion_kx_SESSIONKEYBYTES];
    }
    naion_memzero(keys, sizeof keys);

    return SIMPLE_SODIUM_OK;
}

int
naion_kx_server_session_keys(unsigned char *rx, unsigned char *tx,
                              const unsigned char *server_pk,
                              const unsigned char *server_sk,
                              const unsigned char *client_pk)
{
    naion_generichash_state h;
    unsigned char            q[naion_scalarmult_curve25519_BYTES];
    unsigned char            keys[2 * naion_kx_SESSIONKEYBYTES];
    int                      i;

    if ((rx == NULL && tx == NULL) || server_pk == NULL ||
        server_sk == NULL || client_pk == NULL) {
        return SIMPLE_SODIUM_ERR;
    }
    if (rx == NULL) {
        rx = tx;
    }
    if (tx == NULL) {
        tx = rx;
    }
    if (naion_scalarmult_curve25519(q, server_sk, client_pk) != SIMPLE_SODIUM_OK) {
        return SIMPLE_SODIUM_ERR;
    }
    if (naion_generichash_init(&h, NULL, 0U, sizeof keys) != SIMPLE_SODIUM_OK) {
        naion_memzero(q, sizeof q);
        return SIMPLE_SODIUM_ERR;
    }
    if (naion_generichash_update(&h, q, sizeof q) != SIMPLE_SODIUM_OK ||
        naion_generichash_update(&h, client_pk, naion_kx_PUBLICKEYBYTES) != SIMPLE_SODIUM_OK ||
        naion_generichash_update(&h, server_pk, naion_kx_PUBLICKEYBYTES) != SIMPLE_SODIUM_OK ||
        naion_generichash_final(&h, keys, sizeof keys) != SIMPLE_SODIUM_OK) {
        naion_memzero(q, sizeof q);
        naion_memzero(keys, sizeof keys);
        naion_memzero(&h, sizeof h);
        return SIMPLE_SODIUM_ERR;
    }
    naion_memzero(q, sizeof q);
    naion_memzero(&h, sizeof h);
    for (i = 0; i < (int) naion_kx_SESSIONKEYBYTES; i++) {
        tx[i] = keys[i];
        rx[i] = keys[i + naion_kx_SESSIONKEYBYTES];
    }
    naion_memzero(keys, sizeof keys);

    return SIMPLE_SODIUM_OK;
}

int
naion_box_curve25519xchacha20poly1305_keypair(unsigned char *pk,
                                                unsigned char *sk)
{
    if (pk == NULL || sk == NULL) {
        return SIMPLE_SODIUM_ERR;
    }

    if (fill_random(sk, naion_box_curve25519xchacha20poly1305_SECRETKEYBYTES) != SIMPLE_SODIUM_OK) {
        return SIMPLE_SODIUM_ERR;
    }
    return naion_scalarmult_curve25519_base(pk, sk);
}

int
naion_box_curve25519xchacha20poly1305_seed_keypair(
    unsigned char *pk, unsigned char *sk, const unsigned char *seed)
{
    if (pk == NULL || sk == NULL || seed == NULL) {
        return SIMPLE_SODIUM_ERR;
    }

    if (naion_generichash(sk, naion_box_curve25519xchacha20poly1305_SECRETKEYBYTES,
                           seed, naion_box_curve25519xchacha20poly1305_SEEDBYTES,
                           NULL, 0U) != SIMPLE_SODIUM_OK) {
        return SIMPLE_SODIUM_ERR;
    }
    return naion_scalarmult_curve25519_base(pk, sk);
}

int
naion_box_curve25519xchacha20poly1305_beforenm(unsigned char *k,
                                                  const unsigned char *pk,
                                                  const unsigned char *sk)
{
    if (k == NULL || pk == NULL || sk == NULL) {
        return SIMPLE_SODIUM_ERR;
    }

    static const uint8_t zero16[16] = { 0 };
    unsigned char        s[32];

    if (naion_scalarmult_curve25519(s, sk, pk) != SIMPLE_SODIUM_OK) {
        return SIMPLE_SODIUM_ERR;
    }
#if defined(DEBUG) && DEBUG
    naion_debug_dump_hex("box.beforenm.pk", pk, 32U);
    naion_debug_dump_hex("box.beforenm.sk", sk, 32U);
    naion_debug_dump_hex("box.beforenm.shared_s", s, 32U);
#endif
    hchacha20(k, zero16, s);
#if defined(DEBUG) && DEBUG
    naion_debug_dump_hex("box.beforenm.k_nm", k, 32U);
    naion_trace_dump_hex_always("beforenm.pk", pk, 32U);
    naion_trace_dump_hex_always("beforenm.sk", sk, 32U);
    naion_trace_dump_hex_always("beforenm.shared_s", s, 32U);
    naion_trace_dump_hex_always("beforenm.k_nm", k, 32U);
#endif
    naion_memzero(s, sizeof s);
    return SIMPLE_SODIUM_OK;
}

int
naion_box_curve25519xchacha20poly1305_easy(unsigned char *c,
                                             const unsigned char *m,
                                             unsigned long long mlen,
                                             const unsigned char *n,
                                             const unsigned char *pk,
                                             const unsigned char *sk)
{
    if (c == NULL || n == NULL || pk == NULL || sk == NULL ||
        (m == NULL && mlen > 0ULL)) {
        return SIMPLE_SODIUM_ERR;
    }

    {
        unsigned char k_nm[naion_box_curve25519xchacha20poly1305_BEFORENMBYTES];
        int           ret;

        ret = naion_box_curve25519xchacha20poly1305_beforenm(k_nm, pk, sk);
        if (ret != SIMPLE_SODIUM_OK) {
            naion_memzero(k_nm, sizeof k_nm);
            return SIMPLE_SODIUM_ERR;
        }
        ret = naion_box_curve25519xchacha20poly1305_easy_afternm(c, m, mlen, n, k_nm);
#if defined(DEBUG) && DEBUG
        naion_trace_dump_hex_always("easy.nonce", n, 24U);
        naion_trace_dump_hex_always("easy.k_nm", k_nm, 32U);
        naion_trace_dump_hex_always("easy.mac", c, 16U);
        naion_trace_dump_hex_always("easy.cipher", c + 16U, (size_t) mlen);
        printf("[naion][trace] easy.ret=%d\n", ret);
#endif
        naion_memzero(k_nm, sizeof k_nm);
        return ret;
    }
}

int
naion_box_curve25519xchacha20poly1305_open_easy(
    unsigned char *m, const unsigned char *c, unsigned long long clen,
    const unsigned char *n, const unsigned char *pk, const unsigned char *sk)
{
    if (m == NULL || c == NULL || n == NULL || pk == NULL || sk == NULL ||
        clen < naion_box_curve25519xchacha20poly1305_MACBYTES) {
        return SIMPLE_SODIUM_ERR;
    }

    {
        unsigned char k_nm[naion_box_curve25519xchacha20poly1305_BEFORENMBYTES];
        int           ret;

        ret = naion_box_curve25519xchacha20poly1305_beforenm(k_nm, pk, sk);
        if (ret != SIMPLE_SODIUM_OK) {
            naion_memzero(k_nm, sizeof k_nm);
            return SIMPLE_SODIUM_ERR;
        }
        ret = naion_box_curve25519xchacha20poly1305_open_easy_afternm(m, c, clen, n, k_nm);
#if defined(DEBUG) && DEBUG
        naion_trace_dump_hex_always("open_easy.nonce", n, 24U);
        naion_trace_dump_hex_always("open_easy.k_nm", k_nm, 32U);
        naion_trace_dump_hex_always("open_easy.mac", c, 16U);
        naion_trace_dump_hex_always("open_easy.cipher", c + 16U,
                                    (size_t) (clen - naion_box_curve25519xchacha20poly1305_MACBYTES));
        printf("[naion][trace] open_easy.ret=%d\n", ret);
        if (ret == SIMPLE_SODIUM_OK) {
            naion_trace_dump_hex_always("open_easy.msg", m,
                                        (size_t) (clen - naion_box_curve25519xchacha20poly1305_MACBYTES));
        }
#endif
        naion_memzero(k_nm, sizeof k_nm);
        return ret;
    }
}

int
naion_box_curve25519xchacha20poly1305_seal(unsigned char *c,
                                             const unsigned char *m,
                                             unsigned long long mlen,
                                             const unsigned char *pk)
{
    if (c == NULL || pk == NULL || (m == NULL && mlen > 0ULL)) {
        return SIMPLE_SODIUM_ERR;
    }
    {
        unsigned char              esk[naion_box_curve25519xchacha20poly1305_SECRETKEYBYTES];
        unsigned char              epk[naion_box_curve25519xchacha20poly1305_PUBLICKEYBYTES];
        unsigned char              nonce[naion_box_curve25519xchacha20poly1305_NONCEBYTES];
        naion_generichash_state   st;
        int                        ret;

        if (fill_random(esk, sizeof esk) != SIMPLE_SODIUM_OK) {
            naion_memzero(esk, sizeof esk);
            return SIMPLE_SODIUM_ERR;
        }

        if (naion_scalarmult_curve25519_base(epk, esk) != SIMPLE_SODIUM_OK) {
            naion_memzero(esk, sizeof esk);
            naion_memzero(epk, sizeof epk);
            return SIMPLE_SODIUM_ERR;
        }
        memcpy(c, epk, naion_box_curve25519xchacha20poly1305_PUBLICKEYBYTES);

        if (naion_generichash_init(&st, NULL, 0U, sizeof nonce) != SIMPLE_SODIUM_OK ||
            naion_generichash_update(&st, epk, sizeof epk) != SIMPLE_SODIUM_OK ||
            naion_generichash_update(&st, pk,
                                      naion_box_curve25519xchacha20poly1305_PUBLICKEYBYTES) != SIMPLE_SODIUM_OK ||
            naion_generichash_final(&st, nonce, sizeof nonce) != SIMPLE_SODIUM_OK) {
            naion_memzero(&st, sizeof st);
            naion_memzero(esk, sizeof esk);
            naion_memzero(epk, sizeof epk);
            naion_memzero(nonce, sizeof nonce);
            return SIMPLE_SODIUM_ERR;
        }
        naion_memzero(&st, sizeof st);

        ret = naion_box_curve25519xchacha20poly1305_easy(
            c + naion_box_curve25519xchacha20poly1305_PUBLICKEYBYTES,
            m, mlen, nonce, pk, esk);

        naion_memzero(esk, sizeof esk);
        naion_memzero(epk, sizeof epk);
        naion_memzero(nonce, sizeof nonce);
        return ret;
    }
}

int
naion_box_curve25519xchacha20poly1305_seal_open(
    unsigned char *m, const unsigned char *c, unsigned long long clen,
    const unsigned char *pk, const unsigned char *sk)
{
    if (m == NULL || c == NULL || pk == NULL || sk == NULL ||
        clen < naion_box_curve25519xchacha20poly1305_SEALBYTES) {
        return SIMPLE_SODIUM_ERR;
    }

    {
        unsigned char            nonce[naion_box_curve25519xchacha20poly1305_NONCEBYTES];
        const unsigned char     *epk = c;
        naion_generichash_state st;
        int                      ret;

        if (naion_generichash_init(&st, NULL, 0U, sizeof nonce) != SIMPLE_SODIUM_OK ||
            naion_generichash_update(&st, epk,
                                      naion_box_curve25519xchacha20poly1305_PUBLICKEYBYTES) != SIMPLE_SODIUM_OK ||
            naion_generichash_update(&st, pk,
                                      naion_box_curve25519xchacha20poly1305_PUBLICKEYBYTES) != SIMPLE_SODIUM_OK ||
            naion_generichash_final(&st, nonce, sizeof nonce) != SIMPLE_SODIUM_OK) {
            naion_memzero(&st, sizeof st);
            naion_memzero(nonce, sizeof nonce);
            return SIMPLE_SODIUM_ERR;
        }
        naion_memzero(&st, sizeof st);

        ret = naion_box_curve25519xchacha20poly1305_open_easy(
            m,
            c + naion_box_curve25519xchacha20poly1305_PUBLICKEYBYTES,
            clen - naion_box_curve25519xchacha20poly1305_PUBLICKEYBYTES,
            nonce, epk, sk);

        naion_memzero(nonce, sizeof nonce);
        return ret;
    }
}

#if NAION_XSALSA20
int
naion_box_curve25519xsalsa20poly1305_keypair(unsigned char *pk,
                                              unsigned char *sk)
{
    return naion_box_curve25519xchacha20poly1305_keypair(pk, sk);
}

int
naion_box_curve25519xsalsa20poly1305_seed_keypair(
    unsigned char *pk, unsigned char *sk, const unsigned char *seed)
{
    return naion_box_curve25519xchacha20poly1305_seed_keypair(pk, sk, seed);
}

int
naion_box_curve25519xsalsa20poly1305_beforenm(unsigned char *k,
                                               const unsigned char *pk,
                                               const unsigned char *sk)
{
    static const uint8_t zero16[16] = { 0 };
    unsigned char        s[32];

    if (k == NULL || pk == NULL || sk == NULL) {
        return SIMPLE_SODIUM_ERR;
    }
    if (naion_scalarmult_curve25519(s, sk, pk) != SIMPLE_SODIUM_OK) {
        return SIMPLE_SODIUM_ERR;
    }
    hsalsa20(k, zero16, s);
    naion_memzero(s, sizeof s);
    return SIMPLE_SODIUM_OK;
}

int
naion_box_curve25519xsalsa20poly1305_easy(unsigned char *c,
                                          const unsigned char *m,
                                          unsigned long long mlen,
                                          const unsigned char *n,
                                          const unsigned char *pk,
                                          const unsigned char *sk)
{
    unsigned char k_nm[naion_box_curve25519xsalsa20poly1305_BEFORENMBYTES];
    int           ret;

    if (c == NULL || n == NULL || pk == NULL || sk == NULL ||
        (m == NULL && mlen > 0ULL)) {
        return SIMPLE_SODIUM_ERR;
    }
    ret = naion_box_curve25519xsalsa20poly1305_beforenm(k_nm, pk, sk);
    if (ret != SIMPLE_SODIUM_OK) {
        naion_memzero(k_nm, sizeof k_nm);
        return SIMPLE_SODIUM_ERR;
    }
    ret = naion_box_curve25519xsalsa20poly1305_easy_afternm(c, m, mlen, n, k_nm);
    naion_memzero(k_nm, sizeof k_nm);
    return ret;
}

int
naion_box_curve25519xsalsa20poly1305_open_easy(
    unsigned char *m, const unsigned char *c, unsigned long long clen,
    const unsigned char *n, const unsigned char *pk, const unsigned char *sk)
{
    unsigned char k_nm[naion_box_curve25519xsalsa20poly1305_BEFORENMBYTES];
    int           ret;

    if (m == NULL || c == NULL || n == NULL || pk == NULL || sk == NULL ||
        clen < naion_box_curve25519xsalsa20poly1305_MACBYTES) {
        return SIMPLE_SODIUM_ERR;
    }
    ret = naion_box_curve25519xsalsa20poly1305_beforenm(k_nm, pk, sk);
    if (ret != SIMPLE_SODIUM_OK) {
        naion_memzero(k_nm, sizeof k_nm);
        return SIMPLE_SODIUM_ERR;
    }
    ret = naion_box_curve25519xsalsa20poly1305_open_easy_afternm(m, c, clen, n, k_nm);
    naion_memzero(k_nm, sizeof k_nm);
    return ret;
}

int
naion_box_curve25519xsalsa20poly1305_easy_afternm(
    unsigned char *c, const unsigned char *m, unsigned long long mlen,
    const unsigned char *n, const unsigned char *k)
{
    uint8_t               block0[64];
    _naion_poly1305_state st;
    uint64_t              rem;
    size_t                first_take;
    int                   ret;

    if (c == NULL || n == NULL || k == NULL || (m == NULL && mlen > 0ULL)) {
        return SIMPLE_SODIUM_ERR;
    }

    memset(block0, 0, sizeof block0);
    first_take = (size_t) ((mlen < 32ULL) ? mlen : 32ULL);
    if (first_take > 0U) {
        memcpy(block0 + 32U, m, first_take);
    }
    ret = xsalsa20_xor_ic(block0, block0, (unsigned long long) (32U + first_take), n, 0ULL, k);
    if (ret != SIMPLE_SODIUM_OK) {
        naion_memzero(block0, sizeof block0);
        return SIMPLE_SODIUM_ERR;
    }
    poly1305_init(&st, block0);
    if (first_take > 0U) {
        memcpy(c + naion_box_curve25519xsalsa20poly1305_MACBYTES,
               block0 + 32U, first_take);
    }
    rem = mlen - (uint64_t) first_take;
    if (rem > 0ULL) {
        ret = xsalsa20_xor_ic(
            c + naion_box_curve25519xsalsa20poly1305_MACBYTES + first_take,
            m + first_take, rem, n, 1ULL, k);
        if (ret != SIMPLE_SODIUM_OK) {
            naion_memzero(block0, sizeof block0);
            naion_memzero(&st, sizeof st);
            return SIMPLE_SODIUM_ERR;
        }
    }

    poly1305_update(&st,
                    c + naion_box_curve25519xsalsa20poly1305_MACBYTES,
                    (size_t) mlen);
    poly1305_finish(&st, c);
    naion_memzero(block0, sizeof block0);
    naion_memzero(&st, sizeof st);
    return SIMPLE_SODIUM_OK;
}

int
naion_box_curve25519xsalsa20poly1305_open_easy_afternm(
    unsigned char *m, const unsigned char *c, unsigned long long clen,
    const unsigned char *n, const unsigned char *k)
{
    uint8_t               block0[64];
    uint8_t               computed_mac[16];
    _naion_poly1305_state st;
    const unsigned char  *cipher;
    unsigned long long    mlen;
    size_t                first_take;
    uint64_t              rem;
    int                   ret;

    if (m == NULL || c == NULL || n == NULL || k == NULL ||
        clen < naion_box_curve25519xsalsa20poly1305_MACBYTES) {
        return SIMPLE_SODIUM_ERR;
    }

    cipher = c + naion_box_curve25519xsalsa20poly1305_MACBYTES;
    mlen = clen - naion_box_curve25519xsalsa20poly1305_MACBYTES;
    memset(block0, 0, sizeof block0);

    first_take = (size_t) ((mlen < 32ULL) ? mlen : 32ULL);
    if (first_take > 0U) {
        memcpy(block0 + 32U, cipher, first_take);
    }
    ret = xsalsa20_xor_ic(block0, block0, sizeof block0, n, 0ULL, k);
    if (ret != SIMPLE_SODIUM_OK) {
        naion_memzero(block0, sizeof block0);
        return SIMPLE_SODIUM_ERR;
    }
    poly1305_init(&st, block0);
    poly1305_update(&st, cipher, (size_t) mlen);
    poly1305_finish(&st, computed_mac);

    if (verify16(c, computed_mac) != 1) {
        naion_memzero(block0, sizeof block0);
        naion_memzero(computed_mac, sizeof computed_mac);
        naion_memzero(&st, sizeof st);
        return SIMPLE_SODIUM_ERR;
    }
    if (first_take > 0U) {
        memcpy(m, block0 + 32U, first_take);
    }
    rem = mlen - (uint64_t) first_take;
    if (rem > 0ULL) {
        ret = xsalsa20_xor_ic(m + first_take, cipher + first_take, rem, n, 1ULL, k);
    } else {
        ret = SIMPLE_SODIUM_OK;
    }

    naion_memzero(block0, sizeof block0);
    naion_memzero(computed_mac, sizeof computed_mac);
    naion_memzero(&st, sizeof st);
    if (ret != SIMPLE_SODIUM_OK) {
        return SIMPLE_SODIUM_ERR;
    }
    return SIMPLE_SODIUM_OK;
}

int
naion_box_curve25519xsalsa20poly1305_seal(unsigned char *c,
                                          const unsigned char *m,
                                          unsigned long long mlen,
                                          const unsigned char *pk)
{
    unsigned char            esk[naion_box_curve25519xsalsa20poly1305_SECRETKEYBYTES];
    unsigned char            epk[naion_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES];
    unsigned char            nonce[naion_box_curve25519xsalsa20poly1305_NONCEBYTES];
    naion_generichash_state  st;
    int                      ret;

    if (c == NULL || pk == NULL || (m == NULL && mlen > 0ULL)) {
        return SIMPLE_SODIUM_ERR;
    }
    if (fill_random(esk, sizeof esk) != SIMPLE_SODIUM_OK) {
        naion_memzero(esk, sizeof esk);
        return SIMPLE_SODIUM_ERR;
    }
    if (naion_scalarmult_curve25519_base(epk, esk) != SIMPLE_SODIUM_OK) {
        naion_memzero(esk, sizeof esk);
        naion_memzero(epk, sizeof epk);
        return SIMPLE_SODIUM_ERR;
    }
    memcpy(c, epk, naion_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES);

    if (naion_generichash_init(&st, NULL, 0U, sizeof nonce) != SIMPLE_SODIUM_OK ||
        naion_generichash_update(&st, epk, sizeof epk) != SIMPLE_SODIUM_OK ||
        naion_generichash_update(&st, pk,
                                 naion_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES) != SIMPLE_SODIUM_OK ||
        naion_generichash_final(&st, nonce, sizeof nonce) != SIMPLE_SODIUM_OK) {
        naion_memzero(&st, sizeof st);
        naion_memzero(esk, sizeof esk);
        naion_memzero(epk, sizeof epk);
        naion_memzero(nonce, sizeof nonce);
        return SIMPLE_SODIUM_ERR;
    }
    naion_memzero(&st, sizeof st);

    ret = naion_box_curve25519xsalsa20poly1305_easy(
        c + naion_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES,
        m, mlen, nonce, pk, esk);

    naion_memzero(esk, sizeof esk);
    naion_memzero(epk, sizeof epk);
    naion_memzero(nonce, sizeof nonce);
    return ret;
}

int
naion_box_curve25519xsalsa20poly1305_seal_open(
    unsigned char *m, const unsigned char *c, unsigned long long clen,
    const unsigned char *pk, const unsigned char *sk)
{
    unsigned char            nonce[naion_box_curve25519xsalsa20poly1305_NONCEBYTES];
    const unsigned char     *epk = c;
    naion_generichash_state  st;
    int                      ret;

    if (m == NULL || c == NULL || pk == NULL || sk == NULL ||
        clen < naion_box_curve25519xsalsa20poly1305_SEALBYTES) {
        return SIMPLE_SODIUM_ERR;
    }
    if (naion_generichash_init(&st, NULL, 0U, sizeof nonce) != SIMPLE_SODIUM_OK ||
        naion_generichash_update(&st, epk,
                                 naion_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES) != SIMPLE_SODIUM_OK ||
        naion_generichash_update(&st, pk,
                                 naion_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES) != SIMPLE_SODIUM_OK ||
        naion_generichash_final(&st, nonce, sizeof nonce) != SIMPLE_SODIUM_OK) {
        naion_memzero(&st, sizeof st);
        naion_memzero(nonce, sizeof nonce);
        return SIMPLE_SODIUM_ERR;
    }
    naion_memzero(&st, sizeof st);

    ret = naion_box_curve25519xsalsa20poly1305_open_easy(
        m,
        c + naion_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES,
        clen - naion_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES,
        nonce, epk, sk);

    naion_memzero(nonce, sizeof nonce);
    return ret;
}
#endif /* NAION_XSALSA20 */

/* ------------------------------------------------------------------ */
/* Runtime XChaCha20/XSalsa20 selector + generic naion_box_* dispatch */
/* ------------------------------------------------------------------ */
void
naion_box_set_use_xchacha20(int use_xchacha20)
{
#if NAION_XSALSA20
    gUseXChaCha20 = (use_xchacha20 != 0) ? 1 : 0;
#else
    /* No-op: only XChaCha20 is available. */
    (void) use_xchacha20;
#endif
}

int
naion_box_get_use_xchacha20(void)
{
#if NAION_XSALSA20
    return (gUseXChaCha20 != 0) ? 1 : 0;
#else
    return 1; /* XChaCha20 is always selected when XSalsa20 is absent. */
#endif
}

void
naion_set_use_xchacha20(int use_xchacha20)
{
    naion_box_set_use_xchacha20(use_xchacha20);
}

int
naion_get_use_xchacha20(void)
{
    return naion_box_get_use_xchacha20();
}

size_t
naion_box_seedbytes(void)
{
    return (size_t) naion_box_curve25519xchacha20poly1305_SEEDBYTES;
}

size_t
naion_box_publickeybytes(void)
{
    return (size_t) naion_box_curve25519xchacha20poly1305_PUBLICKEYBYTES;
}

size_t
naion_box_secretkeybytes(void)
{
    return (size_t) naion_box_curve25519xchacha20poly1305_SECRETKEYBYTES;
}

size_t
naion_box_beforenmbytes(void)
{
    return (size_t) naion_box_curve25519xchacha20poly1305_BEFORENMBYTES;
}

size_t
naion_box_noncebytes(void)
{
    return (size_t) naion_box_curve25519xchacha20poly1305_NONCEBYTES;
}

size_t
naion_box_macbytes(void)
{
    return (size_t) naion_box_curve25519xchacha20poly1305_MACBYTES;
}

size_t
naion_box_sealbytes(void)
{
    return (size_t) naion_box_curve25519xchacha20poly1305_SEALBYTES;
}

int
naion_box_keypair(unsigned char *pk, unsigned char *sk)
{
#if NAION_XSALSA20
    if (naion_box_get_use_xchacha20() == 0) {
        return naion_box_curve25519xsalsa20poly1305_keypair(pk, sk);
    }
#endif
    return naion_box_curve25519xchacha20poly1305_keypair(pk, sk);
}

int
naion_box_seed_keypair(unsigned char *pk, unsigned char *sk, const unsigned char *seed)
{
#if NAION_XSALSA20
    if (naion_box_get_use_xchacha20() == 0) {
        return naion_box_curve25519xsalsa20poly1305_seed_keypair(pk, sk, seed);
    }
#endif
    return naion_box_curve25519xchacha20poly1305_seed_keypair(pk, sk, seed);
}

int
naion_box_beforenm(unsigned char *k, const unsigned char *pk, const unsigned char *sk)
{
#if NAION_XSALSA20
    if (naion_box_get_use_xchacha20() == 0) {
        return naion_box_curve25519xsalsa20poly1305_beforenm(k, pk, sk);
    }
#endif
    return naion_box_curve25519xchacha20poly1305_beforenm(k, pk, sk);
}

int
naion_box_easy(unsigned char *c, const unsigned char *m, unsigned long long mlen,
               const unsigned char *n, const unsigned char *pk, const unsigned char *sk)
{
#if NAION_XSALSA20
    if (naion_box_get_use_xchacha20() == 0) {
        return naion_box_curve25519xsalsa20poly1305_easy(c, m, mlen, n, pk, sk);
    }
#endif
    return naion_box_curve25519xchacha20poly1305_easy(c, m, mlen, n, pk, sk);
}

int
naion_box_open_easy(unsigned char *m, const unsigned char *c, unsigned long long clen,
                    const unsigned char *n, const unsigned char *pk, const unsigned char *sk)
{
#if NAION_XSALSA20
    if (naion_box_get_use_xchacha20() == 0) {
        return naion_box_curve25519xsalsa20poly1305_open_easy(m, c, clen, n, pk, sk);
    }
#endif
    return naion_box_curve25519xchacha20poly1305_open_easy(m, c, clen, n, pk, sk);
}

int
naion_box_easy_afternm(unsigned char *c, const unsigned char *m, unsigned long long mlen,
                       const unsigned char *n, const unsigned char *k)
{
#if NAION_XSALSA20
    if (naion_box_get_use_xchacha20() == 0) {
        return naion_box_curve25519xsalsa20poly1305_easy_afternm(c, m, mlen, n, k);
    }
#endif
    return naion_box_curve25519xchacha20poly1305_easy_afternm(c, m, mlen, n, k);
}

int
naion_box_open_easy_afternm(unsigned char *m, const unsigned char *c, unsigned long long clen,
                            const unsigned char *n, const unsigned char *k)
{
#if NAION_XSALSA20
    if (naion_box_get_use_xchacha20() == 0) {
        return naion_box_curve25519xsalsa20poly1305_open_easy_afternm(m, c, clen, n, k);
    }
#endif
    return naion_box_curve25519xchacha20poly1305_open_easy_afternm(m, c, clen, n, k);
}

int
naion_box_seal(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *pk)
{
#if NAION_XSALSA20
    if (naion_box_get_use_xchacha20() == 0) {
        return naion_box_curve25519xsalsa20poly1305_seal(c, m, mlen, pk);
    }
#endif
    return naion_box_curve25519xchacha20poly1305_seal(c, m, mlen, pk);
}

int
naion_box_seal_open(unsigned char *m, const unsigned char *c, unsigned long long clen,
                    const unsigned char *pk, const unsigned char *sk)
{
#if NAION_XSALSA20
    if (naion_box_get_use_xchacha20() == 0) {
        return naion_box_curve25519xsalsa20poly1305_seal_open(m, c, clen, pk, sk);
    }
#endif
    return naion_box_curve25519xchacha20poly1305_seal_open(m, c, clen, pk, sk);
}

int
naion_sign_ed25519_keypair(unsigned char *pk, unsigned char *sk)
{
    if (pk == NULL || sk == NULL) {
        return SIMPLE_SODIUM_ERR;
    }

    {
        unsigned char seed[naion_sign_ed25519_SEEDBYTES];
        int           ret;

        if (fill_random(seed, sizeof seed) != SIMPLE_SODIUM_OK) {
            naion_memzero(seed, sizeof seed);
            return SIMPLE_SODIUM_ERR;
        }
        ret = naion_sign_ed25519_seed_keypair(pk, sk, seed);
        naion_memzero(seed, sizeof seed);
        return ret;
    }
}

int
naion_sign_ed25519_seed_keypair(unsigned char *pk, unsigned char *sk,
                                 const unsigned char *seed)
{
    if (pk == NULL || sk == NULL || seed == NULL) {
        return SIMPLE_SODIUM_ERR;
    }
    return _naion_ed25519_seed_keypair_internal(pk, sk, seed);
}

int
naion_sign_ed25519(unsigned char *sm, unsigned long long *smlen_p,
                    const unsigned char *m, unsigned long long mlen,
                    const unsigned char *sk)
{
    if (smlen_p != NULL) {
        *smlen_p = 0ULL;
    }
    if (sm == NULL || smlen_p == NULL || sk == NULL || (m == NULL && mlen > 0ULL)) {
        return SIMPLE_SODIUM_ERR;
    }

    if (naion_sign_ed25519_detached(sm, NULL, m, mlen, sk) != SIMPLE_SODIUM_OK) {
        return SIMPLE_SODIUM_ERR;
    }
    if (mlen > 0ULL) {
        memmove(sm + naion_sign_ed25519_BYTES, m, (size_t) mlen);
    }
    *smlen_p = mlen + naion_sign_ed25519_BYTES;
    return SIMPLE_SODIUM_OK;
}

int
naion_sign_ed25519_open(unsigned char *m, unsigned long long *mlen_p,
                         const unsigned char *sm, unsigned long long smlen,
                         const unsigned char *pk)
{
    if (mlen_p != NULL) {
        *mlen_p = 0ULL;
    }
    if (m == NULL || mlen_p == NULL || sm == NULL || pk == NULL ||
        smlen < naion_sign_ed25519_BYTES) {
        return SIMPLE_SODIUM_ERR;
    }

    if (naion_sign_ed25519_verify_detached(sm,
                                            sm + naion_sign_ed25519_BYTES,
                                            smlen - naion_sign_ed25519_BYTES,
                                            pk) != SIMPLE_SODIUM_OK) {
        return SIMPLE_SODIUM_ERR;
    }
    if (smlen > naion_sign_ed25519_BYTES) {
        memmove(m, sm + naion_sign_ed25519_BYTES,
                (size_t) (smlen - naion_sign_ed25519_BYTES));
    }
    *mlen_p = smlen - naion_sign_ed25519_BYTES;
    return SIMPLE_SODIUM_OK;
}

int
naion_sign_ed25519_detached(unsigned char *sig,
                             unsigned long long *siglen_p,
                             const unsigned char *m,
                             unsigned long long mlen,
                             const unsigned char *sk)
{
    if (siglen_p != NULL) {
        *siglen_p = 0ULL;
    }
    if (sig == NULL || sk == NULL || (m == NULL && mlen > 0ULL)) {
        return SIMPLE_SODIUM_ERR;
    }
    return _naion_ed25519_detached_sign_internal(sig, siglen_p, m, mlen, sk);
}

int
naion_sign_ed25519_verify_detached(const unsigned char *sig,
                                    const unsigned char *m,
                                    unsigned long long mlen,
                                    const unsigned char *pk)
{
    if (sig == NULL || pk == NULL || (m == NULL && mlen > 0ULL)) {
        return SIMPLE_SODIUM_ERR;
    }
    return _naion_ed25519_detached_verify_internal(sig, m, mlen, pk);
}

int
naion_sign_ed25519_sk_to_seed(unsigned char *seed,
                               const unsigned char *sk)
{
    if (seed == NULL || sk == NULL) {
        return SIMPLE_SODIUM_ERR;
    }

    memmove(seed, sk, naion_sign_ed25519_SEEDBYTES);
    return SIMPLE_SODIUM_OK;
}

int
naion_sign_ed25519_sk_to_pk(unsigned char *pk,
                             const unsigned char *sk)
{
    if (pk == NULL || sk == NULL) {
        return SIMPLE_SODIUM_ERR;
    }

    memmove(pk, sk + naion_sign_ed25519_SEEDBYTES,
            naion_sign_ed25519_PUBLICKEYBYTES);
    return SIMPLE_SODIUM_OK;
}

int
naion_sign_ed25519_pk_to_curve25519(unsigned char *curve25519_pk,
                                     const unsigned char *ed25519_pk)
{
    if (curve25519_pk == NULL || ed25519_pk == NULL) {
        return SIMPLE_SODIUM_ERR;
    }
    return _naion_ed25519_pk_to_curve25519_fallback(curve25519_pk, ed25519_pk);
}

int
naion_sign_ed25519_sk_to_curve25519(unsigned char *curve25519_sk,
                                     const unsigned char *ed25519_sk)
{
    unsigned char h[64];

    if (curve25519_sk == NULL || ed25519_sk == NULL) {
        return SIMPLE_SODIUM_ERR;
    }

    /* libsodium-compatible fallback: X25519 sk = clamp(SHA512(ed25519_seed)[0..31]) */
    _naion_sha512_hash(h, ed25519_sk, 32U);
    h[0] &= 248U;
    h[31] &= 127U;
    h[31] |= 64U;
    memcpy(curve25519_sk, h, naion_scalarmult_curve25519_BYTES);
    naion_memzero(h, sizeof h);
    return SIMPLE_SODIUM_OK;
}

/* ------------------------------------------------------------------------- */
/* CSM (client/server secure messaging) implementation.                     */
/* Merged from the former csm.h. Uses the unified goto cleanup pattern:      */
/* __ERROR__ zeroes sensitive material on failure, __FREE__ releases all     */
/* resources on every exit path, with a single return statement.             */
/* ------------------------------------------------------------------------- */

#define NAION_CSM__SIGN_BYTES      naion_sign_ed25519_BYTES
#define NAION_CSM__ED_PK_BYTES     naion_sign_ed25519_PUBLICKEYBYTES
#define NAION_CSM__X_PK_BYTES      naion_box_PUBLICKEYBYTES_MAX
#define NAION_CSM__X_SK_BYTES      naion_box_SECRETKEYBYTES_MAX
#define NAION_CSM__NONCE_BYTES     naion_box_NONCEBYTES_MAX
#define NAION_CSM__MAC_BYTES       naion_box_MACBYTES_MAX
#define NAION_CSM__AEAD_KEY_BYTES  naion_aead_xchacha20poly1305_ietf_KEYBYTES

static int naion_csm_internal_randombytes(uint8_t *buf, size_t size) {
    naion_random_provider_fn provider;
    if (buf == NULL) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    if (size == 0U) {
        return NAION_CSM_OK;
    }
    provider = naion_get_random_provider();
    if (provider == NULL) {
        return NAION_CSM_ERR_RANDOM_PROVIDER;
    }
    provider(buf, size);
    return NAION_CSM_OK;
}

static int naion_csm_internal_seal(
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t peer_xpk[NAION_CSM__X_PK_BYTES],
    const uint8_t self_xsk[NAION_CSM__X_SK_BYTES],
    const uint8_t aad[NAION_CSM__X_PK_BYTES],
    uint8_t *out_nonce_cipher
) {
    int ret;
    uint8_t nonce[NAION_CSM__NONCE_BYTES];
    uint8_t ekey[NAION_CSM__AEAD_KEY_BYTES];
    unsigned long long mac_len = 0ULL;
    if (peer_xpk == NULL || self_xsk == NULL || aad == NULL || out_nonce_cipher == NULL) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    if (plaintext_len > 0U && plaintext == NULL) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    ret = naion_csm_internal_randombytes(nonce, sizeof(nonce));
    if (ret != NAION_CSM_OK) {
        return ret;
    }
    ret = naion_box_curve25519xchacha20poly1305_beforenm(ekey, peer_xpk, self_xsk);
    if (ret != 0) {
        naion_memzero(nonce, sizeof(nonce));
        naion_memzero(ekey, sizeof(ekey));
        return NAION_CSM_ERR_CRYPTO;
    }
    memmove(out_nonce_cipher, nonce, sizeof(nonce));
    ret = naion_aead_xchacha20poly1305_ietf_encrypt_detached(
        out_nonce_cipher + NAION_CSM__NONCE_BYTES + NAION_CSM__MAC_BYTES,
        out_nonce_cipher + NAION_CSM__NONCE_BYTES,
        &mac_len,
        plaintext,
        (unsigned long long) plaintext_len,
        aad,
        (unsigned long long) NAION_CSM__X_PK_BYTES,
        NULL,
        nonce,
        ekey
    );
    if (ret != 0 || mac_len != (unsigned long long) NAION_CSM__MAC_BYTES) {
        naion_memzero(nonce, sizeof(nonce));
        naion_memzero(ekey, sizeof(ekey));
        return NAION_CSM_ERR_CRYPTO;
    }
    naion_memzero(nonce, sizeof(nonce));
    naion_memzero(ekey, sizeof(ekey));
    return NAION_CSM_OK;
}

static int naion_csm_internal_open(
    const uint8_t *nonce_cipher,
    size_t nonce_cipher_len,
    const uint8_t peer_xpk[NAION_CSM__X_PK_BYTES],
    const uint8_t self_xsk[NAION_CSM__X_SK_BYTES],
    const uint8_t aad[NAION_CSM__X_PK_BYTES],
    uint8_t *out_plaintext,
    size_t *out_plaintext_len
) {
    size_t plaintext_len;
    int ret;
    const uint8_t *nonce;
    const uint8_t *mac;
    const uint8_t *ciphertext;
    uint8_t ekey[NAION_CSM__AEAD_KEY_BYTES];
    if (nonce_cipher == NULL || peer_xpk == NULL || self_xsk == NULL || aad == NULL ||
        out_plaintext == NULL || out_plaintext_len == NULL) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    if (nonce_cipher_len <= (size_t) (NAION_CSM__NONCE_BYTES + NAION_CSM__MAC_BYTES)) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    plaintext_len = nonce_cipher_len - (size_t) NAION_CSM__NONCE_BYTES - (size_t) NAION_CSM__MAC_BYTES;
    nonce = nonce_cipher;
    mac = nonce_cipher + NAION_CSM__NONCE_BYTES;
    ciphertext = nonce_cipher + NAION_CSM__NONCE_BYTES + NAION_CSM__MAC_BYTES;
    ret = naion_box_curve25519xchacha20poly1305_beforenm(ekey, peer_xpk, self_xsk);
    if (ret != 0) {
        naion_memzero(ekey, sizeof(ekey));
        return NAION_CSM_ERR_CRYPTO;
    }
    ret = naion_aead_xchacha20poly1305_ietf_decrypt_detached(
        out_plaintext,
        NULL,
        ciphertext,
        (unsigned long long) plaintext_len,
        mac,
        aad,
        (unsigned long long) NAION_CSM__X_PK_BYTES,
        nonce,
        ekey
    );
    naion_memzero(ekey, sizeof(ekey));
    if (ret != 0) {
        return NAION_CSM_ERR_CRYPTO;
    }
    *out_plaintext_len = plaintext_len;
    return NAION_CSM_OK;
}

static int naion_csm_internal_sign(
    const uint8_t *buffer,
    size_t buffer_len,
    const uint8_t ed_secret_key[naion_sign_ed25519_SECRETKEYBYTES],
    uint8_t out_signature[NAION_CSM__SIGN_BYTES]
) {
    int ret;
    unsigned long long signature_len = 0ULL;
    if (buffer == NULL || ed_secret_key == NULL || out_signature == NULL) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    ret = naion_sign_ed25519_detached(
        out_signature,
        &signature_len,
        buffer,
        (unsigned long long) buffer_len,
        ed_secret_key
    );
    if (ret != 0 || signature_len != (unsigned long long) NAION_CSM__SIGN_BYTES) {
        return NAION_CSM_ERR_CRYPTO;
    }
    return NAION_CSM_OK;
}

static int naion_csm_internal_verify(
    const uint8_t signature[NAION_CSM__SIGN_BYTES],
    const uint8_t *buffer,
    size_t buffer_len,
    const uint8_t ed_public_key[NAION_CSM__ED_PK_BYTES]
) {
    int ret;
    if (signature == NULL || buffer == NULL || ed_public_key == NULL) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    ret = naion_sign_ed25519_verify_detached(
        signature,
        buffer,
        (unsigned long long) buffer_len,
        ed_public_key
    );
    return (ret == 0) ? NAION_CSM_OK : NAION_CSM_ERR_VERIFY_FAILED;
}

int naion_csm_init(void) {
    return (naion_init() == 0) ? NAION_CSM_OK : NAION_CSM_ERR_CRYPTO;
}

void naion_csm_client_wipe(naion_csm_client *client) {
    if (client != NULL) {
        naion_memzero(client, sizeof(*client));
    }
}

void naion_csm_server_wipe(naion_csm_server *server) {
    if (server != NULL) {
        naion_memzero(server, sizeof(*server));
    }
}

int naion_csm_client_create(
    naion_csm_client *client,
    const uint8_t ed_seed_client[naion_sign_ed25519_SEEDBYTES],
    const uint8_t ed_public_key_server[naion_sign_ed25519_PUBLICKEYBYTES]
) {
    int ret;
    if (client == NULL || ed_seed_client == NULL || ed_public_key_server == NULL) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    memset(client, 0, sizeof(*client));
    memmove(client->ed_seed, ed_seed_client, naion_sign_ed25519_SEEDBYTES);
    memmove(client->server_ed_public_key, ed_public_key_server, naion_sign_ed25519_PUBLICKEYBYTES);
    ret = naion_sign_ed25519_seed_keypair(
        client->ed_public_key,
        client->ed_secret_key,
        client->ed_seed
    );
    return (ret == 0) ? NAION_CSM_OK : NAION_CSM_ERR_CRYPTO;
}

int naion_csm_server_create(
    naion_csm_server *server,
    const uint8_t ed_seed_server[naion_sign_ed25519_SEEDBYTES]
) {
    int ret;
    if (server == NULL || ed_seed_server == NULL) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    memset(server, 0, sizeof(*server));
    memmove(server->ed_seed, ed_seed_server, naion_sign_ed25519_SEEDBYTES);
    ret = naion_sign_ed25519_seed_keypair(
        server->ed_public_key,
        server->ed_secret_key,
        server->ed_seed
    );
    if (ret != 0) {
        return NAION_CSM_ERR_CRYPTO;
    }
    server->client_public_key_initialized = 0;
    return NAION_CSM_OK;
}

size_t naion_csm_client_encrypt_size(size_t plaintext_len) {
    return (size_t) NAION_CSM__SIGN_BYTES +
           (size_t) NAION_CSM__X_PK_BYTES +
           (size_t) NAION_CSM__NONCE_BYTES +
           (size_t) NAION_CSM__MAC_BYTES +
           (size_t) NAION_CSM__ED_PK_BYTES +
           plaintext_len;
}

size_t naion_csm_client_decrypt_max_plaintext_size(size_t packet_len) {
    size_t fixed = (size_t) NAION_CSM__SIGN_BYTES +
                   (size_t) NAION_CSM__X_PK_BYTES +
                   (size_t) NAION_CSM__NONCE_BYTES +
                   (size_t) NAION_CSM__MAC_BYTES;
    if (packet_len <= fixed) {
        return 0U;
    }
    return packet_len - fixed;
}

size_t naion_csm_server_encrypt_size(size_t plaintext_len) {
    return (size_t) NAION_CSM__SIGN_BYTES +
           (size_t) NAION_CSM__X_PK_BYTES +
           (size_t) NAION_CSM__NONCE_BYTES +
           (size_t) NAION_CSM__MAC_BYTES +
           plaintext_len;
}

size_t naion_csm_server_decrypt_max_plaintext_size(size_t packet_len) {
    size_t fixed = (size_t) NAION_CSM__SIGN_BYTES +
                   (size_t) NAION_CSM__X_PK_BYTES +
                   (size_t) NAION_CSM__NONCE_BYTES +
                   (size_t) NAION_CSM__MAC_BYTES +
                   (size_t) NAION_CSM__ED_PK_BYTES;
    if (packet_len <= fixed) {
        return 0U;
    }
    return packet_len - fixed;
}

int naion_csm_client_encrypt(
    const naion_csm_client *client,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *out_packet,
    size_t out_packet_cap,
    size_t *out_packet_len
) {
    uint8_t server_xpk[NAION_CSM__X_PK_BYTES];
    uint8_t session_xsk[NAION_CSM__X_SK_BYTES];
    uint8_t session_xpk[NAION_CSM__X_PK_BYTES];
    uint8_t *sig;
    uint8_t *body;
    uint8_t *body_payload;
    size_t body_payload_len;
    size_t plain_payload_len;
    uint8_t *plain_payload = NULL;
    int ret = NAION_CSM_ERR_CRYPTO;

    if (out_packet_len != NULL) {
        *out_packet_len = 0U;
    }
    if (client == NULL || out_packet == NULL || out_packet_len == NULL) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    if (plaintext == NULL && plaintext_len > 0U) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    if (plaintext_len == 0U) {
        return NAION_CSM_ERR_NO_DATA;
    }
    if (out_packet_cap < naion_csm_client_encrypt_size(plaintext_len)) {
        return NAION_CSM_ERR_BUFFER_TOO_SMALL;
    }

    if (naion_sign_ed25519_pk_to_curve25519(server_xpk, client->server_ed_public_key) != 0) {
        goto __ERROR__;
    }
    if (naion_box_keypair(session_xpk, session_xsk) != 0) {
        goto __ERROR__;
    }

    sig = out_packet;
    body = out_packet + NAION_CSM__SIGN_BYTES;
    memmove(body, session_xpk, NAION_CSM__X_PK_BYTES);
    body_payload = body + NAION_CSM__X_PK_BYTES;
    body_payload_len = (size_t) NAION_CSM__NONCE_BYTES + (size_t) NAION_CSM__MAC_BYTES + (size_t) NAION_CSM__ED_PK_BYTES + plaintext_len;
    plain_payload_len = (size_t) NAION_CSM__ED_PK_BYTES + plaintext_len;
    plain_payload = (uint8_t *) malloc(plain_payload_len);
    if (plain_payload == NULL) {
        goto __ERROR__;
    }
    memmove(plain_payload, client->ed_public_key, NAION_CSM__ED_PK_BYTES);
    memmove(plain_payload + NAION_CSM__ED_PK_BYTES, plaintext, plaintext_len);
    if (naion_csm_internal_seal(
            plain_payload,
            plain_payload_len,
            server_xpk,
            session_xsk,
            session_xpk,
            body_payload) != NAION_CSM_OK) {
        goto __ERROR__;
    }
    if (naion_csm_internal_sign(body, (size_t) NAION_CSM__X_PK_BYTES + body_payload_len,
                                client->ed_secret_key, sig) != NAION_CSM_OK) {
        goto __ERROR__;
    }
    *out_packet_len = naion_csm_client_encrypt_size(plaintext_len);
    ret = NAION_CSM_OK;
    goto __FREE__;

__ERROR__:
    if (plain_payload != NULL) {
        naion_memzero(plain_payload, plain_payload_len);
    }
    naion_memzero(server_xpk, sizeof(server_xpk));
    naion_memzero(session_xsk, sizeof(session_xsk));
    naion_memzero(session_xpk, sizeof(session_xpk));
__FREE__:
    if (plain_payload != NULL) {
        free(plain_payload);
    }
    return ret;
}

int naion_csm_client_decrypt(
    const naion_csm_client *client,
    const uint8_t *packet,
    size_t packet_len,
    uint8_t *out_plaintext,
    size_t out_plaintext_cap,
    size_t *out_plaintext_len
) {
    size_t min_size = (size_t) NAION_CSM__SIGN_BYTES +
                      (size_t) NAION_CSM__X_PK_BYTES +
                      (size_t) NAION_CSM__NONCE_BYTES +
                      (size_t) NAION_CSM__MAC_BYTES;
    const uint8_t *sig;
    const uint8_t *body;
    const uint8_t *session_xpk;
    const uint8_t *nonce_cipher;
    size_t nonce_cipher_len;
    uint8_t client_xsk[NAION_CSM__X_SK_BYTES];
    uint8_t *opened_buf = NULL;
    size_t opened_cap = 0U;
    size_t plaintext_len = 0;
    int ret = NAION_CSM_ERR_CRYPTO;

    if (out_plaintext_len != NULL) {
        *out_plaintext_len = 0U;
    }
    if (client == NULL || packet == NULL || out_plaintext == NULL || out_plaintext_len == NULL) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    if (packet_len <= min_size) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    if (out_plaintext_cap < naion_csm_client_decrypt_max_plaintext_size(packet_len)) {
        return NAION_CSM_ERR_BUFFER_TOO_SMALL;
    }
    sig = packet;
    body = packet + NAION_CSM__SIGN_BYTES;
    if (naion_csm_internal_verify(sig, body, packet_len - (size_t) NAION_CSM__SIGN_BYTES,
                                  client->server_ed_public_key) != NAION_CSM_OK) {
        return NAION_CSM_ERR_VERIFY_FAILED;
    }
    if (naion_sign_ed25519_sk_to_curve25519(client_xsk, client->ed_secret_key) != 0) {
        goto __ERROR__;
    }
    session_xpk = body;
    nonce_cipher = body + NAION_CSM__X_PK_BYTES;
    nonce_cipher_len = packet_len - (size_t) NAION_CSM__SIGN_BYTES - (size_t) NAION_CSM__X_PK_BYTES;
    opened_cap = packet_len -
                 (size_t) NAION_CSM__SIGN_BYTES -
                 (size_t) NAION_CSM__X_PK_BYTES -
                 (size_t) NAION_CSM__NONCE_BYTES -
                 (size_t) NAION_CSM__MAC_BYTES;
    opened_buf = (uint8_t *) malloc(opened_cap);
    if (opened_buf == NULL) {
        goto __ERROR__;
    }
    if (naion_csm_internal_open(
            nonce_cipher,
            nonce_cipher_len,
            session_xpk,
            client_xsk,
            session_xpk,
            opened_buf,
            &plaintext_len) != NAION_CSM_OK) {
        goto __ERROR__;
    }
    memmove(out_plaintext, opened_buf, plaintext_len);
    *out_plaintext_len = plaintext_len;
    ret = NAION_CSM_OK;
    goto __FREE__;

__ERROR__:
    if (opened_buf != NULL) {
        naion_memzero(opened_buf, opened_cap);
    }
    naion_memzero(client_xsk, sizeof(client_xsk));
__FREE__:
    if (opened_buf != NULL) {
        free(opened_buf);
    }
    return ret;
}

int naion_csm_server_decrypt(
    naion_csm_server *server,
    const uint8_t *packet,
    size_t packet_len,
    uint8_t *out_plaintext,
    size_t out_plaintext_cap,
    size_t *out_plaintext_len
) {
    size_t min_size = (size_t) NAION_CSM__SIGN_BYTES +
                      (size_t) NAION_CSM__X_PK_BYTES +
                      (size_t) NAION_CSM__NONCE_BYTES +
                      (size_t) NAION_CSM__MAC_BYTES +
                      (size_t) NAION_CSM__ED_PK_BYTES;
    const uint8_t *sig;
    const uint8_t *body;
    const uint8_t *session_xpk;
    const uint8_t *nonce_cipher;
    size_t nonce_cipher_len;
    uint8_t server_xsk[NAION_CSM__X_SK_BYTES];
    uint8_t client_ed_public_key[NAION_CSM__ED_PK_BYTES];
    uint8_t *opened_buf = NULL;
    size_t opened_cap = 0U;
    size_t opened_len = 0;
    int ret = NAION_CSM_ERR_CRYPTO;

    if (out_plaintext_len != NULL) {
        *out_plaintext_len = 0U;
    }
    if (server == NULL || packet == NULL || out_plaintext == NULL || out_plaintext_len == NULL) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    if (packet_len <= min_size) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    if (out_plaintext_cap < naion_csm_server_decrypt_max_plaintext_size(packet_len)) {
        return NAION_CSM_ERR_BUFFER_TOO_SMALL;
    }
    if (naion_sign_ed25519_sk_to_curve25519(server_xsk, server->ed_secret_key) != 0) {
        goto __ERROR__;
    }
    sig = packet;
    body = packet + NAION_CSM__SIGN_BYTES;
    session_xpk = body;
    nonce_cipher = body + NAION_CSM__X_PK_BYTES;
    nonce_cipher_len = packet_len - (size_t) NAION_CSM__SIGN_BYTES - (size_t) NAION_CSM__X_PK_BYTES;
    opened_cap = nonce_cipher_len - (size_t) NAION_CSM__NONCE_BYTES - (size_t) NAION_CSM__MAC_BYTES;
    opened_buf = (uint8_t *) malloc(opened_cap);
    if (opened_buf == NULL) {
        goto __ERROR__;
    }

    if (naion_csm_internal_open(
            nonce_cipher,
            nonce_cipher_len,
            session_xpk,
            server_xsk,
            session_xpk,
            opened_buf,
            &opened_len) != NAION_CSM_OK) {
        goto __ERROR__;
    }
    if (opened_len <= (size_t) NAION_CSM__ED_PK_BYTES) {
        goto __ERROR__;
    }

    memmove(client_ed_public_key, opened_buf, NAION_CSM__ED_PK_BYTES);
    if (naion_csm_internal_verify(sig, body, packet_len - (size_t) NAION_CSM__SIGN_BYTES,
                                  client_ed_public_key) != NAION_CSM_OK) {
        goto __ERROR__;
    }
    memmove(server->client_ed_public_key, client_ed_public_key, NAION_CSM__ED_PK_BYTES);
    server->client_public_key_initialized = 1;
    memmove(
        out_plaintext,
        opened_buf + NAION_CSM__ED_PK_BYTES,
        opened_len - (size_t) NAION_CSM__ED_PK_BYTES
    );
    *out_plaintext_len = opened_len - (size_t) NAION_CSM__ED_PK_BYTES;
    ret = NAION_CSM_OK;
    goto __FREE__;

__ERROR__:
    if (opened_buf != NULL) {
        naion_memzero(opened_buf, opened_cap);
    }
    naion_memzero(client_ed_public_key, sizeof(client_ed_public_key));
    naion_memzero(server_xsk, sizeof(server_xsk));
__FREE__:
    if (opened_buf != NULL) {
        free(opened_buf);
    }
    return ret;
}

int naion_csm_server_encrypt(
    const naion_csm_server *server,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *out_packet,
    size_t out_packet_cap,
    size_t *out_packet_len
) {
    uint8_t client_xpk[NAION_CSM__X_PK_BYTES];
    uint8_t session_xsk[NAION_CSM__X_SK_BYTES];
    uint8_t session_xpk[NAION_CSM__X_PK_BYTES];
    uint8_t *sig;
    uint8_t *body;
    uint8_t *body_payload;
    size_t body_payload_len;
    int ret = NAION_CSM_ERR_CRYPTO;

    if (out_packet_len != NULL) {
        *out_packet_len = 0U;
    }
    if (server == NULL || out_packet == NULL || out_packet_len == NULL) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    if (plaintext == NULL && plaintext_len > 0U) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    if (plaintext_len == 0U) {
        return NAION_CSM_ERR_NO_DATA;
    }
    if (!server->client_public_key_initialized) {
        return NAION_CSM_ERR_STATE;
    }
    if (out_packet_cap < naion_csm_server_encrypt_size(plaintext_len)) {
        return NAION_CSM_ERR_BUFFER_TOO_SMALL;
    }
    if (naion_sign_ed25519_pk_to_curve25519(client_xpk, server->client_ed_public_key) != 0) {
        goto __ERROR__;
    }
    if (naion_box_keypair(session_xpk, session_xsk) != 0) {
        goto __ERROR__;
    }

    sig = out_packet;
    body = out_packet + NAION_CSM__SIGN_BYTES;
    memmove(body, session_xpk, NAION_CSM__X_PK_BYTES);
    body_payload = body + NAION_CSM__X_PK_BYTES;
    body_payload_len = (size_t) NAION_CSM__NONCE_BYTES + (size_t) NAION_CSM__MAC_BYTES + plaintext_len;
    if (naion_csm_internal_seal(
            plaintext,
            plaintext_len,
            client_xpk,
            session_xsk,
            session_xpk,
            body_payload) != NAION_CSM_OK) {
        goto __ERROR__;
    }
    if (naion_csm_internal_sign(body, (size_t) NAION_CSM__X_PK_BYTES + body_payload_len,
                                server->ed_secret_key, sig) != NAION_CSM_OK) {
        goto __ERROR__;
    }
    *out_packet_len = naion_csm_server_encrypt_size(plaintext_len);
    ret = NAION_CSM_OK;
    goto __FREE__;

__ERROR__:
    naion_memzero(client_xpk, sizeof(client_xpk));
    naion_memzero(session_xsk, sizeof(session_xsk));
    naion_memzero(session_xpk, sizeof(session_xpk));
__FREE__:
    return ret;
}

#endif /* NAION_LAYER_CSM */

/* ========================================================================= */
/* Layer 4 implementations — CSM + CA-certificate handshake                */
/* ========================================================================= */
#if NAION_LAYER_CSM_CA

int naion_csm_ca_client_create(naion_csm_ca_client *client,
                                const uint8_t ed_seed[naion_sign_ed25519_SEEDBYTES],
                                const uint8_t ca_ed_pk[naion_sign_ed25519_PUBLICKEYBYTES]) {
    int ret;
    if (client == NULL || ed_seed == NULL || ca_ed_pk == NULL) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    memset(client, 0, sizeof(*client));
    memmove(client->ed_seed, ed_seed, naion_sign_ed25519_SEEDBYTES);
    memmove(client->ca_ed_public_key, ca_ed_pk, naion_sign_ed25519_PUBLICKEYBYTES);
    ret = naion_sign_ed25519_seed_keypair(
        client->ed_public_key, client->ed_secret_key, client->ed_seed);
    client->server_key_verified = 0;
    return (ret == 0) ? NAION_CSM_OK : NAION_CSM_ERR_CRYPTO;
}

int naion_csm_ca_server_create(naion_csm_ca_server *server,
                                const uint8_t ed_seed[naion_sign_ed25519_SEEDBYTES],
                                const uint8_t ca_signature[naion_sign_ed25519_BYTES]) {
    int ret;
    if (server == NULL || ed_seed == NULL || ca_signature == NULL) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    memset(server, 0, sizeof(*server));
    memmove(server->ed_seed, ed_seed, naion_sign_ed25519_SEEDBYTES);
    memmove(server->ca_signature, ca_signature, naion_sign_ed25519_BYTES);
    ret = naion_sign_ed25519_seed_keypair(
        server->ed_public_key, server->ed_secret_key, server->ed_seed);
    server->client_key_verified = 0;
    return (ret == 0) ? NAION_CSM_OK : NAION_CSM_ERR_CRYPTO;
}

size_t naion_csm_ca_handshake_response_size(void) {
    return NAION_CSM_CA_CERT_BYTES;
}

int naion_csm_ca_handshake_response(const naion_csm_ca_server *server,
                                     uint8_t out_m1[NAION_CSM_CA_CERT_BYTES],
                                     size_t out_cap, size_t *out_len) {
    if (out_len != NULL) {
        *out_len = 0U;
    }
    if (server == NULL || out_m1 == NULL || out_len == NULL) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    if (out_cap < NAION_CSM_CA_CERT_BYTES) {
        return NAION_CSM_ERR_BUFFER_TOO_SMALL;
    }
    memmove(out_m1, server->ed_public_key, naion_sign_ed25519_PUBLICKEYBYTES);
    memmove(out_m1 + naion_sign_ed25519_PUBLICKEYBYTES,
            server->ca_signature, naion_sign_ed25519_BYTES);
    *out_len = NAION_CSM_CA_CERT_BYTES;
    return NAION_CSM_OK;
}

int naion_csm_ca_handshake_verify(naion_csm_ca_client *client,
                                   const uint8_t *m1, size_t m1_len) {
    if (client == NULL || m1 == NULL) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    if (m1_len != NAION_CSM_CA_CERT_BYTES) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    if (naion_sign_ed25519_verify_detached(
            m1 + naion_sign_ed25519_PUBLICKEYBYTES,
            m1,
            naion_sign_ed25519_PUBLICKEYBYTES,
            client->ca_ed_public_key) != 0) {
        return NAION_CSM_ERR_VERIFY_FAILED;
    }
    memmove(client->server_ed_public_key, m1, naion_sign_ed25519_PUBLICKEYBYTES);
    client->server_key_verified = 1;
    return NAION_CSM_OK;
}

size_t naion_csm_ca_client_encrypt_size(size_t plaintext_len) {
    return naion_csm_client_encrypt_size(plaintext_len);
}

size_t naion_csm_ca_client_decrypt_max_plaintext_size(size_t packet_len) {
    return naion_csm_client_decrypt_max_plaintext_size(packet_len);
}

size_t naion_csm_ca_server_encrypt_size(size_t plaintext_len) {
    return naion_csm_server_encrypt_size(plaintext_len);
}

size_t naion_csm_ca_server_decrypt_max_plaintext_size(size_t packet_len) {
    return naion_csm_server_decrypt_max_plaintext_size(packet_len);
}

int naion_csm_ca_client_encrypt(naion_csm_ca_client *client,
                                 const uint8_t *plaintext, size_t plaintext_len,
                                 uint8_t *out, size_t out_cap, size_t *out_len) {
    naion_csm_client view;
    int ret;
    if (client == NULL) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    if (!client->server_key_verified) {
        if (out_len != NULL) {
            *out_len = 0U;
        }
        return NAION_CSM_ERR_STATE;
    }
    /* Reuse the Layer 3 client encryptor over the same key layout. */
    memmove(view.ed_seed, client->ed_seed, naion_sign_ed25519_SEEDBYTES);
    memmove(view.ed_secret_key, client->ed_secret_key, naion_sign_ed25519_SECRETKEYBYTES);
    memmove(view.ed_public_key, client->ed_public_key, naion_sign_ed25519_PUBLICKEYBYTES);
    memmove(view.server_ed_public_key, client->server_ed_public_key, naion_sign_ed25519_PUBLICKEYBYTES);
    ret = naion_csm_client_encrypt(&view, plaintext, plaintext_len, out, out_cap, out_len);
    naion_memzero(&view, sizeof(view));
    return ret;
}

int naion_csm_ca_client_decrypt(const naion_csm_ca_client *client,
                                 const uint8_t *packet, size_t packet_len,
                                 uint8_t *out, size_t out_cap, size_t *out_len) {
    naion_csm_client view;
    int ret;
    if (client == NULL) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    if (!client->server_key_verified) {
        if (out_len != NULL) {
            *out_len = 0U;
        }
        return NAION_CSM_ERR_STATE;
    }
    memmove(view.ed_seed, client->ed_seed, naion_sign_ed25519_SEEDBYTES);
    memmove(view.ed_secret_key, client->ed_secret_key, naion_sign_ed25519_SECRETKEYBYTES);
    memmove(view.ed_public_key, client->ed_public_key, naion_sign_ed25519_PUBLICKEYBYTES);
    memmove(view.server_ed_public_key, client->server_ed_public_key, naion_sign_ed25519_PUBLICKEYBYTES);
    ret = naion_csm_client_decrypt(&view, packet, packet_len, out, out_cap, out_len);
    naion_memzero(&view, sizeof(view));
    return ret;
}

int naion_csm_ca_server_encrypt(const naion_csm_ca_server *server,
                                 const uint8_t *plaintext, size_t plaintext_len,
                                 uint8_t *out, size_t out_cap, size_t *out_len) {
    naion_csm_server view;
    int ret;
    if (server == NULL) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    if (!server->client_key_verified) {
        if (out_len != NULL) {
            *out_len = 0U;
        }
        return NAION_CSM_ERR_STATE;
    }
    memmove(view.ed_seed, server->ed_seed, naion_sign_ed25519_SEEDBYTES);
    memmove(view.ed_secret_key, server->ed_secret_key, naion_sign_ed25519_SECRETKEYBYTES);
    memmove(view.ed_public_key, server->ed_public_key, naion_sign_ed25519_PUBLICKEYBYTES);
    memmove(view.client_ed_public_key, server->client_ed_public_key, naion_sign_ed25519_PUBLICKEYBYTES);
    view.client_public_key_initialized = server->client_key_verified;
    ret = naion_csm_server_encrypt(&view, plaintext, plaintext_len, out, out_cap, out_len);
    naion_memzero(&view, sizeof(view));
    return ret;
}

int naion_csm_ca_server_decrypt(naion_csm_ca_server *server,
                                 const uint8_t *packet, size_t packet_len,
                                 uint8_t *out, size_t out_cap, size_t *out_len) {
    naion_csm_server view;
    int ret;
    if (server == NULL) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    memmove(view.ed_seed, server->ed_seed, naion_sign_ed25519_SEEDBYTES);
    memmove(view.ed_secret_key, server->ed_secret_key, naion_sign_ed25519_SECRETKEYBYTES);
    memmove(view.ed_public_key, server->ed_public_key, naion_sign_ed25519_PUBLICKEYBYTES);
    memmove(view.client_ed_public_key, server->client_ed_public_key, naion_sign_ed25519_PUBLICKEYBYTES);
    view.client_public_key_initialized = server->client_key_verified;
    ret = naion_csm_server_decrypt(&view, packet, packet_len, out, out_cap, out_len);
    /* Reflect any client key learnt from the first packet back to the CA server. */
    memmove(server->client_ed_public_key, view.client_ed_public_key, naion_sign_ed25519_PUBLICKEYBYTES);
    server->client_key_verified = view.client_public_key_initialized;
    naion_memzero(&view, sizeof(view));
    return ret;
}

void naion_csm_ca_client_wipe(naion_csm_ca_client *client) {
    if (client != NULL) {
        naion_memzero(client, sizeof(*client));
    }
}

void naion_csm_ca_server_wipe(naion_csm_ca_server *server) {
    if (server != NULL) {
        naion_memzero(server, sizeof(*server));
    }
}

#endif /* NAION_LAYER_CSM_CA */

/* ========================================================================= */
/* Layer 5 implementations — CSM-Session (ephemeral-ephemeral DH, PFS)      */
/* ========================================================================= */
#if NAION_LAYER_CSM_SESSION

/*
 * Packet layout (post-handshake):
 *   [0..63]   Ed25519 detached signature over body
 *   [64..87]  24-byte XChaCha20-Poly1305 nonce
 *   [88..103] 16-byte Poly1305 MAC
 *   [104..]   ciphertext (same length as plaintext)
 *
 * Both sides hold the other's Ed25519 public key from the handshake, so decrypt
 * is verify-then-AEAD symmetrically (no decrypt-then-verify as in Layer 3/4).
 */

int naion_csm_sess_client_create(
    naion_csm_sess_client *client,
    const uint8_t ed_seed[naion_sign_ed25519_SEEDBYTES],
    const uint8_t ca_ed_pk[naion_sign_ed25519_PUBLICKEYBYTES]) {
    int ret;
    if (client == NULL || ed_seed == NULL || ca_ed_pk == NULL) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    memset(client, 0, sizeof(*client));
    memmove(client->ed_seed, ed_seed, naion_sign_ed25519_SEEDBYTES);
    memmove(client->ca_ed_public_key, ca_ed_pk, naion_sign_ed25519_PUBLICKEYBYTES);
    ret = naion_sign_ed25519_seed_keypair(
        client->ed_public_key, client->ed_secret_key, client->ed_seed);
    client->handshake_complete = 0;
    return (ret == 0) ? NAION_CSM_OK : NAION_CSM_ERR_CRYPTO;
}

int naion_csm_sess_server_create(
    naion_csm_sess_server *server,
    const uint8_t ed_seed[naion_sign_ed25519_SEEDBYTES],
    const uint8_t ca_signature[naion_sign_ed25519_BYTES]) {
    int ret;
    if (server == NULL || ed_seed == NULL || ca_signature == NULL) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    memset(server, 0, sizeof(*server));
    memmove(server->ed_seed, ed_seed, naion_sign_ed25519_SEEDBYTES);
    memmove(server->ca_signature, ca_signature, naion_sign_ed25519_BYTES);
    ret = naion_sign_ed25519_seed_keypair(
        server->ed_public_key, server->ed_secret_key, server->ed_seed);
    server->handshake_complete = 0;
    return (ret == 0) ? NAION_CSM_OK : NAION_CSM_ERR_CRYPTO;
}

void naion_csm_sess_client_wipe(naion_csm_sess_client *client) {
    if (client != NULL) {
        naion_memzero(client, sizeof(*client));
    }
}

void naion_csm_sess_server_wipe(naion_csm_sess_server *server) {
    if (server != NULL) {
        naion_memzero(server, sizeof(*server));
    }
}

/*
 * Derive the session AEAD key from the ephemeral X25519 shared secret.
 * naion_box_curve25519xchacha20poly1305_beforenm computes
 *   HChaCha20(X25519(my_xsk, peer_xpk), zero_nonce)
 * which matches the plan03 §4.5 session_aead_key definition exactly.
 */
static int
naion_csm_sess_derive_aead_key(uint8_t aead_key[NAION_CSM_SESS_SESSION_AEAD_KEY_BYTES],
                                const uint8_t my_xsk[NAION_CSM_SESS_SESSION_XSK_BYTES],
                                const uint8_t peer_xpk[NAION_CSM_SESS_SESSION_XPK_BYTES]) {
    int ret = naion_box_curve25519xchacha20poly1305_beforenm(aead_key, peer_xpk, my_xsk);
    if (ret != 0) {
        naion_memzero(aead_key, NAION_CSM_SESS_SESSION_AEAD_KEY_BYTES);
        return NAION_CSM_ERR_CRYPTO;
    }
    return NAION_CSM_OK;
}

/* CLIENT_HELLO = client_session_xpk(32) || client_ed_pk(32) || sig(64) */
int naion_csm_sess_client_hello(
    naion_csm_sess_client *client,
    uint8_t out_client_hello[NAION_CSM_SESS_CLIENT_HELLO_BYTES]) {
    int ret = NAION_CSM_ERR_CRYPTO;
    uint8_t sig[naion_sign_ed25519_BYTES];
    unsigned long long sig_len = 0ULL;

    if (client == NULL || out_client_hello == NULL) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    if (naion_box_keypair(client->client_session_xpk, client->client_session_xsk) != 0) {
        return NAION_CSM_ERR_CRYPTO;
    }
    memmove(out_client_hello, client->client_session_xpk, NAION_CSM_SESS_SESSION_XPK_BYTES);
    memmove(out_client_hello + NAION_CSM_SESS_SESSION_XPK_BYTES,
            client->ed_public_key, naion_sign_ed25519_PUBLICKEYBYTES);
    if (naion_sign_ed25519_detached(
            sig, &sig_len,
            client->client_session_xpk, (unsigned long long) NAION_CSM_SESS_SESSION_XPK_BYTES,
            client->ed_secret_key) != 0 ||
        sig_len != (unsigned long long) naion_sign_ed25519_BYTES) {
        goto __ERROR__;
    }
    memmove(out_client_hello + NAION_CSM_SESS_SESSION_XPK_BYTES + naion_sign_ed25519_PUBLICKEYBYTES,
            sig, naion_sign_ed25519_BYTES);
    client->handshake_complete = 0;
    ret = NAION_CSM_OK;
    goto __FREE__;

__ERROR__:
    naion_memzero(client->client_session_xsk, sizeof(client->client_session_xsk));
    naion_memzero(client->client_session_xpk, sizeof(client->client_session_xpk));
    naion_memzero(sig, sizeof(sig));
__FREE__:
    return ret;
}

/*
 * SERVER_RESPONSE (m1) =
 *   server_session_xpk(32) || sign(server_session_xpk, server_ed_sk)(64) ||
 *   server_ed_pk(32) || ca_signature(64)
 *
 * Verifies the CLIENT_HELLO signature over client_session_xpk with
 * client_ed_pk first; on failure the server state is left untouched (no session
 * allocation, plan03 §1.1 step 4 / §6.1).
 */
int naion_csm_sess_server_handshake(
    naion_csm_sess_server *server,
    const uint8_t client_hello[NAION_CSM_SESS_CLIENT_HELLO_BYTES],
    uint8_t out_m1[NAION_CSM_SESS_SERVER_RESPONSE_BYTES],
    size_t out_cap, size_t *out_len) {
    int ret = NAION_CSM_ERR_CRYPTO;
    const uint8_t *client_session_xpk;
    const uint8_t *client_ed_pk;
    const uint8_t *client_hello_sig;
    uint8_t sig[naion_sign_ed25519_BYTES];
    unsigned long long sig_len = 0ULL;

    if (out_len != NULL) {
        *out_len = 0U;
    }
    if (server == NULL || client_hello == NULL || out_m1 == NULL || out_len == NULL) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    if (out_cap < NAION_CSM_SESS_SERVER_RESPONSE_BYTES) {
        return NAION_CSM_ERR_BUFFER_TOO_SMALL;
    }

    client_session_xpk = client_hello;
    client_ed_pk = client_hello + NAION_CSM_SESS_SESSION_XPK_BYTES;
    client_hello_sig = client_hello + NAION_CSM_SESS_SESSION_XPK_BYTES + naion_sign_ed25519_PUBLICKEYBYTES;

    if (naion_is_zero(client_session_xpk, NAION_CSM_SESS_SESSION_XPK_BYTES)) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    if (naion_sign_ed25519_verify_detached(
            client_hello_sig,
            client_session_xpk, (unsigned long long) NAION_CSM_SESS_SESSION_XPK_BYTES,
            client_ed_pk) != 0) {
        return NAION_CSM_ERR_VERIFY_FAILED;
    }

    if (naion_box_keypair(server->server_session_xpk, server->server_session_xsk) != 0) {
        return NAION_CSM_ERR_CRYPTO;
    }
    if (naion_sign_ed25519_detached(
            sig, &sig_len,
            server->server_session_xpk, (unsigned long long) NAION_CSM_SESS_SESSION_XPK_BYTES,
            server->ed_secret_key) != 0 ||
        sig_len != (unsigned long long) naion_sign_ed25519_BYTES) {
        goto __ERROR__;
    }
    memmove(out_m1, server->server_session_xpk, NAION_CSM_SESS_SESSION_XPK_BYTES);
    memmove(out_m1 + NAION_CSM_SESS_SESSION_XPK_BYTES, sig, naion_sign_ed25519_BYTES);
    memmove(out_m1 + NAION_CSM_SESS_SESSION_XPK_BYTES + naion_sign_ed25519_BYTES,
            server->ed_public_key, naion_sign_ed25519_PUBLICKEYBYTES);
    memmove(out_m1 + NAION_CSM_SESS_SESSION_XPK_BYTES + naion_sign_ed25519_BYTES + naion_sign_ed25519_PUBLICKEYBYTES,
            server->ca_signature, naion_sign_ed25519_BYTES);

    if (naion_csm_sess_derive_aead_key(server->session_aead_key,
                                        server->server_session_xsk,
                                        client_session_xpk) != NAION_CSM_OK) {
        goto __ERROR__;
    }
    memmove(server->client_session_xpk, client_session_xpk, NAION_CSM_SESS_SESSION_XPK_BYTES);
    memmove(server->client_ed_public_key, client_ed_pk, naion_sign_ed25519_PUBLICKEYBYTES);
    server->handshake_complete = 1;

    *out_len = NAION_CSM_SESS_SERVER_RESPONSE_BYTES;
    ret = NAION_CSM_OK;
    goto __FREE__;

__ERROR__:
    naion_memzero(server->server_session_xsk, sizeof(server->server_session_xsk));
    naion_memzero(server->server_session_xpk, sizeof(server->server_session_xpk));
    naion_memzero(server->session_aead_key, sizeof(server->session_aead_key));
__FREE__:
    naion_memzero(sig, sizeof(sig));
    return ret;
}

/*
 * Client verifies the two-level certificate chain:
 *   CA(ca_ed_pk) -> server_ed_pk -> server_session_xpk
 * then derives the matching session AEAD key.
 */
int naion_csm_sess_client_finish(
    naion_csm_sess_client *client,
    const uint8_t *m1, size_t m1_len) {
    const uint8_t *server_session_xpk;
    const uint8_t *server_sig;
    const uint8_t *server_ed_pk;
    const uint8_t *ca_sig;

    if (client == NULL || m1 == NULL) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    if (m1_len != NAION_CSM_SESS_SERVER_RESPONSE_BYTES) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }

    server_session_xpk = m1;
    server_sig = m1 + NAION_CSM_SESS_SESSION_XPK_BYTES;
    server_ed_pk = m1 + NAION_CSM_SESS_SESSION_XPK_BYTES + naion_sign_ed25519_BYTES;
    ca_sig = m1 + NAION_CSM_SESS_SESSION_XPK_BYTES + naion_sign_ed25519_BYTES + naion_sign_ed25519_PUBLICKEYBYTES;

    if (naion_is_zero(server_session_xpk, NAION_CSM_SESS_SESSION_XPK_BYTES)) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    /* CA -> server_ed_pk */
    if (naion_sign_ed25519_verify_detached(
            ca_sig,
            server_ed_pk, (unsigned long long) naion_sign_ed25519_PUBLICKEYBYTES,
            client->ca_ed_public_key) != 0) {
        return NAION_CSM_ERR_VERIFY_FAILED;
    }
    /* server_ed_pk -> server_session_xpk */
    if (naion_sign_ed25519_verify_detached(
            server_sig,
            server_session_xpk, (unsigned long long) NAION_CSM_SESS_SESSION_XPK_BYTES,
            server_ed_pk) != 0) {
        return NAION_CSM_ERR_VERIFY_FAILED;
    }

    if (naion_csm_sess_derive_aead_key(client->session_aead_key,
                                        client->client_session_xsk,
                                        server_session_xpk) != NAION_CSM_OK) {
        return NAION_CSM_ERR_CRYPTO;
    }
    memmove(client->server_session_xpk, server_session_xpk, NAION_CSM_SESS_SESSION_XPK_BYTES);
    memmove(client->server_ed_public_key, server_ed_pk, naion_sign_ed25519_PUBLICKEYBYTES);
    client->handshake_complete = 1;
    return NAION_CSM_OK;
}

size_t naion_csm_sess_client_encrypt_size(size_t plaintext_len) {
    return (size_t) NAION_CSM_SESS_PACKET_OVERHEAD + plaintext_len;
}

size_t naion_csm_sess_client_decrypt_max_plaintext_size(size_t packet_len) {
    if (packet_len <= (size_t) NAION_CSM_SESS_PACKET_OVERHEAD) {
        return 0U;
    }
    return packet_len - (size_t) NAION_CSM_SESS_PACKET_OVERHEAD;
}

size_t naion_csm_sess_server_encrypt_size(size_t plaintext_len) {
    return (size_t) NAION_CSM_SESS_PACKET_OVERHEAD + plaintext_len;
}

size_t naion_csm_sess_server_decrypt_max_plaintext_size(size_t packet_len) {
    if (packet_len <= (size_t) NAION_CSM_SESS_PACKET_OVERHEAD) {
        return 0U;
    }
    return packet_len - (size_t) NAION_CSM_SESS_PACKET_OVERHEAD;
}

/* Internal: AEAD-encrypt with the precomputed session key, no DH. */
static int
naion_csm_sess_seal(const uint8_t *plaintext, size_t plaintext_len,
                     const uint8_t aead_key[NAION_CSM_SESS_SESSION_AEAD_KEY_BYTES],
                     uint8_t *out_nonce_mac_ct) {
    int ret;
    uint8_t nonce[naion_box_NONCEBYTES_MAX];
    unsigned long long mac_len = 0ULL;
    uint8_t *out_mac;
    uint8_t *out_ct;

    ret = naion_csm_internal_randombytes(nonce, sizeof(nonce));
    if (ret != NAION_CSM_OK) {
        return ret;
    }
    memmove(out_nonce_mac_ct, nonce, sizeof(nonce));
    out_mac = out_nonce_mac_ct + naion_box_NONCEBYTES_MAX;
    out_ct = out_nonce_mac_ct + naion_box_NONCEBYTES_MAX + naion_box_MACBYTES_MAX;
    ret = naion_aead_xchacha20poly1305_ietf_encrypt_detached(
        out_ct, out_mac, &mac_len,
        plaintext, (unsigned long long) plaintext_len,
        NULL, 0ULL, NULL, nonce, aead_key);
    naion_memzero(nonce, sizeof(nonce));
    if (ret != 0 || mac_len != (unsigned long long) naion_box_MACBYTES_MAX) {
        return NAION_CSM_ERR_CRYPTO;
    }
    return NAION_CSM_OK;
}

/* Internal: AEAD-decrypt with the precomputed session key, no DH. */
static int
naion_csm_sess_open(const uint8_t *nonce_mac_ct, size_t nonce_mac_ct_len,
                     const uint8_t aead_key[NAION_CSM_SESS_SESSION_AEAD_KEY_BYTES],
                     uint8_t *out_plaintext, size_t *out_plaintext_len) {
    int ret;
    const uint8_t *nonce;
    const uint8_t *mac;
    const uint8_t *ct;
    size_t plaintext_len;

    if (nonce_mac_ct_len <= (size_t)(naion_box_NONCEBYTES_MAX + naion_box_MACBYTES_MAX)) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    plaintext_len = nonce_mac_ct_len - (size_t) naion_box_NONCEBYTES_MAX - (size_t) naion_box_MACBYTES_MAX;
    nonce = nonce_mac_ct;
    mac = nonce_mac_ct + naion_box_NONCEBYTES_MAX;
    ct = nonce_mac_ct + naion_box_NONCEBYTES_MAX + naion_box_MACBYTES_MAX;
    ret = naion_aead_xchacha20poly1305_ietf_decrypt_detached(
        out_plaintext, NULL,
        ct, (unsigned long long) plaintext_len,
        mac, NULL, 0ULL, nonce, aead_key);
    if (ret != 0) {
        return NAION_CSM_ERR_CRYPTO;
    }
    *out_plaintext_len = plaintext_len;
    return NAION_CSM_OK;
}

int naion_csm_sess_client_encrypt(
    naion_csm_sess_client *client,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *out, size_t out_cap, size_t *out_len) {
    uint8_t *sig;
    uint8_t *body;
    size_t body_len;

    if (out_len != NULL) {
        *out_len = 0U;
    }
    if (client == NULL || out == NULL || out_len == NULL) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    if (plaintext == NULL && plaintext_len > 0U) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    if (plaintext_len == 0U) {
        return NAION_CSM_ERR_NO_DATA;
    }
    if (!client->handshake_complete) {
        return NAION_CSM_ERR_STATE;
    }
    if (out_cap < naion_csm_sess_client_encrypt_size(plaintext_len)) {
        return NAION_CSM_ERR_BUFFER_TOO_SMALL;
    }

    sig = out;
    body = out + naion_sign_ed25519_BYTES;
    body_len = (size_t) naion_box_NONCEBYTES_MAX + (size_t) naion_box_MACBYTES_MAX + plaintext_len;
    if (naion_csm_sess_seal(plaintext, plaintext_len, client->session_aead_key, body) != NAION_CSM_OK) {
        return NAION_CSM_ERR_CRYPTO;
    }
    if (naion_csm_internal_sign(body, body_len, client->ed_secret_key, sig) != NAION_CSM_OK) {
        naion_memzero(body, body_len);
        return NAION_CSM_ERR_CRYPTO;
    }
    *out_len = naion_csm_sess_client_encrypt_size(plaintext_len);
    return NAION_CSM_OK;
}

int naion_csm_sess_client_decrypt(
    const naion_csm_sess_client *client,
    const uint8_t *packet, size_t packet_len,
    uint8_t *out, size_t out_cap, size_t *out_len) {
    const uint8_t *sig;
    const uint8_t *body;
    size_t body_len;
    size_t plaintext_len = 0U;
    int ret = NAION_CSM_ERR_CRYPTO;

    if (out_len != NULL) {
        *out_len = 0U;
    }
    if (client == NULL || packet == NULL || out == NULL || out_len == NULL) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    if (!client->handshake_complete) {
        return NAION_CSM_ERR_STATE;
    }
    if (packet_len <= (size_t) NAION_CSM_SESS_PACKET_OVERHEAD) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    if (out_cap < naion_csm_sess_client_decrypt_max_plaintext_size(packet_len)) {
        return NAION_CSM_ERR_BUFFER_TOO_SMALL;
    }

    sig = packet;
    body = packet + naion_sign_ed25519_BYTES;
    body_len = packet_len - (size_t) naion_sign_ed25519_BYTES;
    /* verify-then-decrypt: cheap reject of forged packets before any AEAD work */
    if (naion_csm_internal_verify(sig, body, body_len, client->server_ed_public_key) != NAION_CSM_OK) {
        return NAION_CSM_ERR_VERIFY_FAILED;
    }
    ret = naion_csm_sess_open(body, body_len, client->session_aead_key, out, &plaintext_len);
    if (ret != NAION_CSM_OK) {
        return ret;
    }
    *out_len = plaintext_len;
    return NAION_CSM_OK;
}

int naion_csm_sess_server_encrypt(
    const naion_csm_sess_server *server,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *out, size_t out_cap, size_t *out_len) {
    uint8_t *sig;
    uint8_t *body;
    size_t body_len;

    if (out_len != NULL) {
        *out_len = 0U;
    }
    if (server == NULL || out == NULL || out_len == NULL) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    if (plaintext == NULL && plaintext_len > 0U) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    if (plaintext_len == 0U) {
        return NAION_CSM_ERR_NO_DATA;
    }
    if (!server->handshake_complete) {
        return NAION_CSM_ERR_STATE;
    }
    if (out_cap < naion_csm_sess_server_encrypt_size(plaintext_len)) {
        return NAION_CSM_ERR_BUFFER_TOO_SMALL;
    }

    sig = out;
    body = out + naion_sign_ed25519_BYTES;
    body_len = (size_t) naion_box_NONCEBYTES_MAX + (size_t) naion_box_MACBYTES_MAX + plaintext_len;
    if (naion_csm_sess_seal(plaintext, plaintext_len, server->session_aead_key, body) != NAION_CSM_OK) {
        return NAION_CSM_ERR_CRYPTO;
    }
    if (naion_csm_internal_sign(body, body_len, server->ed_secret_key, sig) != NAION_CSM_OK) {
        naion_memzero(body, body_len);
        return NAION_CSM_ERR_CRYPTO;
    }
    *out_len = naion_csm_sess_server_encrypt_size(plaintext_len);
    return NAION_CSM_OK;
}

int naion_csm_sess_server_decrypt(
    naion_csm_sess_server *server,
    const uint8_t *packet, size_t packet_len,
    uint8_t *out, size_t out_cap, size_t *out_len) {
    const uint8_t *sig;
    const uint8_t *body;
    size_t body_len;
    size_t plaintext_len = 0U;
    int ret = NAION_CSM_ERR_CRYPTO;

    if (out_len != NULL) {
        *out_len = 0U;
    }
    if (server == NULL || packet == NULL || out == NULL || out_len == NULL) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    if (!server->handshake_complete) {
        return NAION_CSM_ERR_STATE;
    }
    if (packet_len <= (size_t) NAION_CSM_SESS_PACKET_OVERHEAD) {
        return NAION_CSM_ERR_INVALID_ARGUMENT;
    }
    if (out_cap < naion_csm_sess_server_decrypt_max_plaintext_size(packet_len)) {
        return NAION_CSM_ERR_BUFFER_TOO_SMALL;
    }

    sig = packet;
    body = packet + naion_sign_ed25519_BYTES;
    body_len = packet_len - (size_t) naion_sign_ed25519_BYTES;
    if (naion_csm_internal_verify(sig, body, body_len, server->client_ed_public_key) != NAION_CSM_OK) {
        return NAION_CSM_ERR_VERIFY_FAILED;
    }
    ret = naion_csm_sess_open(body, body_len, server->session_aead_key, out, &plaintext_len);
    if (ret != NAION_CSM_OK) {
        return ret;
    }
    *out_len = plaintext_len;
    return NAION_CSM_OK;
}

#endif /* NAION_LAYER_CSM_SESSION */

#endif /* NAION_IMPLEMENTATION */
#endif /* NAION_H */
