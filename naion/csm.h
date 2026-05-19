#ifndef CSM_SINGLE_HEADER_LIBRARY_H
#define CSM_SINGLE_HEADER_LIBRARY_H

// CSM = client-server-model
// Client/server secure messaging model based on naion (libsodium-style APIs).
// The client holds the server public key.
// The server initially has no client key material.

#include <stddef.h>
#include <stdint.h>

#include "naion.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CSM_OK = 0,
    CSM_ERR_INVALID_ARGUMENT = -1,
    CSM_ERR_BUFFER_TOO_SMALL = -2,
    CSM_ERR_CRYPTO = -3,
    CSM_ERR_VERIFY_FAILED = -4,
    CSM_ERR_STATE = -5,
    CSM_ERR_RANDOM_PROVIDER = -6,
    CSM_ERR_NO_DATA = -7
};

typedef struct csm_client {
    uint8_t ed_seed[naion_sign_ed25519_SEEDBYTES];
    uint8_t ed_secret_key[naion_sign_ed25519_SECRETKEYBYTES];
    uint8_t ed_public_key[naion_sign_ed25519_PUBLICKEYBYTES];
    uint8_t server_ed_public_key[naion_sign_ed25519_PUBLICKEYBYTES];
} csm_client;

typedef struct csm_server {
    uint8_t ed_seed[naion_sign_ed25519_SEEDBYTES];
    uint8_t ed_secret_key[naion_sign_ed25519_SECRETKEYBYTES];
    uint8_t ed_public_key[naion_sign_ed25519_PUBLICKEYBYTES];
    uint8_t client_ed_public_key[naion_sign_ed25519_PUBLICKEYBYTES];
    int client_public_key_initialized;
} csm_server;

int csm_init(void);
void csm_client_wipe(csm_client *client);
void csm_server_wipe(csm_server *server);

int csm_client_create(
    csm_client *client,
    const uint8_t ed_seed_client[naion_sign_ed25519_SEEDBYTES],
    const uint8_t ed_public_key_server[naion_sign_ed25519_PUBLICKEYBYTES]
);

int csm_server_create(
    csm_server *server,
    const uint8_t ed_seed_server[naion_sign_ed25519_SEEDBYTES]
);

size_t csm_client_encrypt_size(size_t plaintext_len);
size_t csm_client_decrypt_max_plaintext_size(size_t packet_len);
size_t csm_server_encrypt_size(size_t plaintext_len);
size_t csm_server_decrypt_max_plaintext_size(size_t packet_len);

int csm_client_encrypt(
    const csm_client *client,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *out_packet,
    size_t out_packet_cap,
    size_t *out_packet_len
);

int csm_client_decrypt(
    const csm_client *client,
    const uint8_t *packet,
    size_t packet_len,
    uint8_t *out_plaintext,
    size_t out_plaintext_cap,
    size_t *out_plaintext_len
);

int csm_server_decrypt(
    csm_server *server,
    const uint8_t *packet,
    size_t packet_len,
    uint8_t *out_plaintext,
    size_t out_plaintext_cap,
    size_t *out_plaintext_len
);

int csm_server_encrypt(
    const csm_server *server,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *out_packet,
    size_t out_packet_cap,
    size_t *out_packet_len
);

#ifdef __cplusplus
}
#endif

#if defined(CSM_IMPLEMENTATION)

#include <string.h>
#include <stdlib.h>
#ifdef __cplusplus
extern "C" {
#endif

enum {
    CSM__SIGN_BYTES = naion_sign_ed25519_BYTES,
    CSM__ED_PK_BYTES = naion_sign_ed25519_PUBLICKEYBYTES,
    CSM__X_PK_BYTES = naion_box_PUBLICKEYBYTES_MAX,
    CSM__X_SK_BYTES = naion_box_SECRETKEYBYTES_MAX,
    CSM__NONCE_BYTES = naion_box_NONCEBYTES_MAX,
    CSM__MAC_BYTES = naion_box_MACBYTES_MAX,
    CSM__AEAD_KEY_BYTES = naion_aead_xchacha20poly1305_ietf_KEYBYTES
};

static int csm__randombytes(uint8_t *buf, size_t size) {
    naion_random_provider_fn provider;
    if (buf == NULL) {
        return CSM_ERR_INVALID_ARGUMENT;
    }
    if (size == 0U) {
        return CSM_OK;
    }
    provider = naion_get_random_provider();
    if (provider == NULL) {
        return CSM_ERR_RANDOM_PROVIDER;
    }
    provider(buf, size);
    return CSM_OK;
}

static int csm__seal(
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t peer_xpk[CSM__X_PK_BYTES],
    const uint8_t self_xsk[CSM__X_SK_BYTES],
    const uint8_t aad[CSM__X_PK_BYTES],
    uint8_t *out_nonce_cipher
) {
    int ret;
    uint8_t nonce[CSM__NONCE_BYTES];
    uint8_t ekey[CSM__AEAD_KEY_BYTES];
    unsigned long long mac_len = 0ULL;
    if (peer_xpk == NULL || self_xsk == NULL || aad == NULL || out_nonce_cipher == NULL) {
        return CSM_ERR_INVALID_ARGUMENT;
    }
    if (plaintext_len > 0U && plaintext == NULL) {
        return CSM_ERR_INVALID_ARGUMENT;
    }
    ret = csm__randombytes(nonce, sizeof(nonce));
    if (ret != CSM_OK) {
        return ret;
    }
    ret = naion_box_curve25519xchacha20poly1305_beforenm(ekey, peer_xpk, self_xsk);
    if (ret != 0) {
        naion_memzero(nonce, sizeof(nonce));
        naion_memzero(ekey, sizeof(ekey));
        return CSM_ERR_CRYPTO;
    }
    memmove(out_nonce_cipher, nonce, sizeof(nonce));
    ret = naion_aead_xchacha20poly1305_ietf_encrypt_detached(
        out_nonce_cipher + CSM__NONCE_BYTES + CSM__MAC_BYTES,
        out_nonce_cipher + CSM__NONCE_BYTES,
        &mac_len,
        plaintext,
        (unsigned long long) plaintext_len,
        aad,
        (unsigned long long) CSM__X_PK_BYTES,
        NULL,
        nonce,
        ekey
    );
    if (ret != 0 || mac_len != (unsigned long long) CSM__MAC_BYTES) {
        naion_memzero(nonce, sizeof(nonce));
        naion_memzero(ekey, sizeof(ekey));
        return CSM_ERR_CRYPTO;
    }
    naion_memzero(nonce, sizeof(nonce));
    naion_memzero(ekey, sizeof(ekey));
    return CSM_OK;
}

static int csm__open(
    const uint8_t *nonce_cipher,
    size_t nonce_cipher_len,
    const uint8_t peer_xpk[CSM__X_PK_BYTES],
    const uint8_t self_xsk[CSM__X_SK_BYTES],
    const uint8_t aad[CSM__X_PK_BYTES],
    uint8_t *out_plaintext,
    size_t *out_plaintext_len
) {
    size_t plaintext_len;
    int ret;
    const uint8_t *nonce;
    const uint8_t *mac;
    const uint8_t *ciphertext;
    uint8_t ekey[CSM__AEAD_KEY_BYTES];
    if (nonce_cipher == NULL || peer_xpk == NULL || self_xsk == NULL || aad == NULL ||
        out_plaintext == NULL || out_plaintext_len == NULL) {
        return CSM_ERR_INVALID_ARGUMENT;
    }
    if (nonce_cipher_len <= (size_t) (CSM__NONCE_BYTES + CSM__MAC_BYTES)) {
        return CSM_ERR_INVALID_ARGUMENT;
    }
    plaintext_len = nonce_cipher_len - (size_t) CSM__NONCE_BYTES - (size_t) CSM__MAC_BYTES;
    nonce = nonce_cipher;
    mac = nonce_cipher + CSM__NONCE_BYTES;
    ciphertext = nonce_cipher + CSM__NONCE_BYTES + CSM__MAC_BYTES;
    ret = naion_box_curve25519xchacha20poly1305_beforenm(ekey, peer_xpk, self_xsk);
    if (ret != 0) {
        naion_memzero(ekey, sizeof(ekey));
        return CSM_ERR_CRYPTO;
    }
    ret = naion_aead_xchacha20poly1305_ietf_decrypt_detached(
        out_plaintext,
        NULL,
        ciphertext,
        (unsigned long long) plaintext_len,
        mac,
        aad,
        (unsigned long long) CSM__X_PK_BYTES,
        nonce,
        ekey
    );
    naion_memzero(ekey, sizeof(ekey));
    if (ret != 0) {
        return CSM_ERR_CRYPTO;
    }
    *out_plaintext_len = plaintext_len;
    return CSM_OK;
}

static int csm__sign(
    const uint8_t *buffer,
    size_t buffer_len,
    const uint8_t ed_secret_key[naion_sign_ed25519_SECRETKEYBYTES],
    uint8_t out_signature[CSM__SIGN_BYTES]
) {
    int ret;
    unsigned long long signature_len = 0ULL;
    if (buffer == NULL || ed_secret_key == NULL || out_signature == NULL) {
        return CSM_ERR_INVALID_ARGUMENT;
    }
    ret = naion_sign_ed25519_detached(
        out_signature,
        &signature_len,
        buffer,
        (unsigned long long) buffer_len,
        ed_secret_key
    );
    if (ret != 0 || signature_len != (unsigned long long) CSM__SIGN_BYTES) {
        return CSM_ERR_CRYPTO;
    }
    return CSM_OK;
}

static int csm__verify(
    const uint8_t signature[CSM__SIGN_BYTES],
    const uint8_t *buffer,
    size_t buffer_len,
    const uint8_t ed_public_key[CSM__ED_PK_BYTES]
) {
    int ret;
    if (signature == NULL || buffer == NULL || ed_public_key == NULL) {
        return CSM_ERR_INVALID_ARGUMENT;
    }
    ret = naion_sign_ed25519_verify_detached(
        signature,
        buffer,
        (unsigned long long) buffer_len,
        ed_public_key
    );
    return (ret == 0) ? CSM_OK : CSM_ERR_VERIFY_FAILED;
}

int csm_init(void) {
    return (naion_init() == 0) ? CSM_OK : CSM_ERR_CRYPTO;
}

void csm_client_wipe(csm_client *client) {
    if (client != NULL) {
        naion_memzero(client, sizeof(*client));
    }
}

void csm_server_wipe(csm_server *server) {
    if (server != NULL) {
        naion_memzero(server, sizeof(*server));
    }
}

int csm_client_create(
    csm_client *client,
    const uint8_t ed_seed_client[naion_sign_ed25519_SEEDBYTES],
    const uint8_t ed_public_key_server[naion_sign_ed25519_PUBLICKEYBYTES]
) {
    int ret;
    if (client == NULL || ed_seed_client == NULL || ed_public_key_server == NULL) {
        return CSM_ERR_INVALID_ARGUMENT;
    }
    memset(client, 0, sizeof(*client));
    memmove(client->ed_seed, ed_seed_client, naion_sign_ed25519_SEEDBYTES);
    memmove(client->server_ed_public_key, ed_public_key_server, naion_sign_ed25519_PUBLICKEYBYTES);
    ret = naion_sign_ed25519_seed_keypair(
        client->ed_public_key,
        client->ed_secret_key,
        client->ed_seed
    );
    return (ret == 0) ? CSM_OK : CSM_ERR_CRYPTO;
}

int csm_server_create(
    csm_server *server,
    const uint8_t ed_seed_server[naion_sign_ed25519_SEEDBYTES]
) {
    int ret;
    if (server == NULL || ed_seed_server == NULL) {
        return CSM_ERR_INVALID_ARGUMENT;
    }
    memset(server, 0, sizeof(*server));
    memmove(server->ed_seed, ed_seed_server, naion_sign_ed25519_SEEDBYTES);
    ret = naion_sign_ed25519_seed_keypair(
        server->ed_public_key,
        server->ed_secret_key,
        server->ed_seed
    );
    if (ret != 0) {
        return CSM_ERR_CRYPTO;
    }
    server->client_public_key_initialized = 0;
    return CSM_OK;
}

size_t csm_client_encrypt_size(size_t plaintext_len) {
    return (size_t) CSM__SIGN_BYTES +
           (size_t) CSM__X_PK_BYTES +
           (size_t) CSM__NONCE_BYTES +
           (size_t) CSM__MAC_BYTES +
           (size_t) CSM__ED_PK_BYTES +
           plaintext_len;
}

size_t csm_client_decrypt_max_plaintext_size(size_t packet_len) {
    size_t fixed = (size_t) CSM__SIGN_BYTES +
                   (size_t) CSM__X_PK_BYTES +
                   (size_t) CSM__NONCE_BYTES +
                   (size_t) CSM__MAC_BYTES;
    if (packet_len <= fixed) {
        return 0U;
    }
    return packet_len - fixed;
}

size_t csm_server_encrypt_size(size_t plaintext_len) {
    return (size_t) CSM__SIGN_BYTES +
           (size_t) CSM__X_PK_BYTES +
           (size_t) CSM__NONCE_BYTES +
           (size_t) CSM__MAC_BYTES +
           plaintext_len;
}

size_t csm_server_decrypt_max_plaintext_size(size_t packet_len) {
    size_t fixed = (size_t) CSM__SIGN_BYTES +
                   (size_t) CSM__X_PK_BYTES +
                   (size_t) CSM__NONCE_BYTES +
                   (size_t) CSM__MAC_BYTES +
                   (size_t) CSM__ED_PK_BYTES;
    if (packet_len <= fixed) {
        return 0U;
    }
    return packet_len - fixed;
}

int csm_client_encrypt(
    const csm_client *client,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *out_packet,
    size_t out_packet_cap,
    size_t *out_packet_len
) {
    int ret;
    uint8_t server_xpk[CSM__X_PK_BYTES];
    uint8_t session_xsk[CSM__X_SK_BYTES];
    uint8_t session_xpk[CSM__X_PK_BYTES];
    uint8_t *sig;
    uint8_t *body;
    uint8_t *body_payload;
    size_t body_payload_len;
    size_t plain_payload_len;
    uint8_t *plain_payload;
    if (out_packet_len != NULL) {
        *out_packet_len = 0U;
    }
    if (client == NULL || out_packet == NULL || out_packet_len == NULL) {
        return CSM_ERR_INVALID_ARGUMENT;
    }
    if (plaintext == NULL && plaintext_len > 0U) {
        return CSM_ERR_INVALID_ARGUMENT;
    }
    if (plaintext_len == 0U) {
        return CSM_ERR_NO_DATA;
    }
    if (out_packet_cap < csm_client_encrypt_size(plaintext_len)) {
        return CSM_ERR_BUFFER_TOO_SMALL;
    }
    ret = naion_sign_ed25519_pk_to_curve25519(server_xpk, client->server_ed_public_key);
    if (ret != 0) {
        naion_memzero(server_xpk, sizeof(server_xpk));
        return CSM_ERR_CRYPTO;
    }
    ret = naion_box_keypair(session_xpk, session_xsk);
    if (ret != 0) {
        naion_memzero(server_xpk, sizeof(server_xpk));
        naion_memzero(session_xsk, sizeof(session_xsk));
        naion_memzero(session_xpk, sizeof(session_xpk));
        return CSM_ERR_CRYPTO;
    }

    sig = out_packet;
    body = out_packet + CSM__SIGN_BYTES;
    memmove(body, session_xpk, CSM__X_PK_BYTES);
    body_payload = body + CSM__X_PK_BYTES;
    body_payload_len = (size_t) CSM__NONCE_BYTES + (size_t) CSM__MAC_BYTES + (size_t) CSM__ED_PK_BYTES + plaintext_len;
    plain_payload_len = (size_t) CSM__ED_PK_BYTES + plaintext_len;
    plain_payload = (uint8_t *) malloc(plain_payload_len);
    if (plain_payload == NULL) {
        naion_memzero(server_xpk, sizeof(server_xpk));
        naion_memzero(session_xsk, sizeof(session_xsk));
        naion_memzero(session_xpk, sizeof(session_xpk));
        return CSM_ERR_CRYPTO;
    }
    memmove(plain_payload, client->ed_public_key, CSM__ED_PK_BYTES);
    memmove(plain_payload + CSM__ED_PK_BYTES, plaintext, plaintext_len);
    ret = csm__seal(
        plain_payload,
        plain_payload_len,
        server_xpk,
        session_xsk,
        session_xpk,
        body_payload
    );
    if (ret != CSM_OK) {
        naion_memzero(plain_payload, plain_payload_len);
        free(plain_payload);
        naion_memzero(server_xpk, sizeof(server_xpk));
        naion_memzero(session_xsk, sizeof(session_xsk));
        naion_memzero(session_xpk, sizeof(session_xpk));
        return ret;
    }
    naion_memzero(plain_payload, plain_payload_len);
    free(plain_payload);
    ret = csm__sign(body, (size_t) CSM__X_PK_BYTES + body_payload_len, client->ed_secret_key, sig);
    if (ret != CSM_OK) {
        naion_memzero(server_xpk, sizeof(server_xpk));
        naion_memzero(session_xsk, sizeof(session_xsk));
        naion_memzero(session_xpk, sizeof(session_xpk));
        return ret;
    }
    *out_packet_len = csm_client_encrypt_size(plaintext_len);
    naion_memzero(server_xpk, sizeof(server_xpk));
    naion_memzero(session_xsk, sizeof(session_xsk));
    naion_memzero(session_xpk, sizeof(session_xpk));
    return CSM_OK;
}

int csm_client_decrypt(
    const csm_client *client,
    const uint8_t *packet,
    size_t packet_len,
    uint8_t *out_plaintext,
    size_t out_plaintext_cap,
    size_t *out_plaintext_len
) {
    size_t min_size = (size_t) CSM__SIGN_BYTES +
                      (size_t) CSM__X_PK_BYTES +
                      (size_t) CSM__NONCE_BYTES +
                      (size_t) CSM__MAC_BYTES;
    const uint8_t *sig;
    const uint8_t *body;
    const uint8_t *session_xpk;
    const uint8_t *nonce_cipher;
    size_t nonce_cipher_len;
    uint8_t client_xsk[CSM__X_SK_BYTES];
    uint8_t *opened_buf = NULL;
    size_t opened_cap = 0U;
    size_t plaintext_len;
    int ret;
    if (out_plaintext_len != NULL) {
        *out_plaintext_len = 0U;
    }
    if (client == NULL || packet == NULL || out_plaintext == NULL || out_plaintext_len == NULL) {
        return CSM_ERR_INVALID_ARGUMENT;
    }
    if (packet_len <= min_size) {
        return CSM_ERR_INVALID_ARGUMENT;
    }
    if (out_plaintext_cap < csm_client_decrypt_max_plaintext_size(packet_len)) {
        return CSM_ERR_BUFFER_TOO_SMALL;
    }
    sig = packet;
    body = packet + CSM__SIGN_BYTES;
    ret = csm__verify(sig, body, packet_len - (size_t) CSM__SIGN_BYTES, client->server_ed_public_key);
    if (ret != CSM_OK) {
        return ret;
    }
    ret = naion_sign_ed25519_sk_to_curve25519(client_xsk, client->ed_secret_key);
    if (ret != 0) {
        naion_memzero(client_xsk, sizeof(client_xsk));
        return CSM_ERR_CRYPTO;
    }
    session_xpk = body;
    nonce_cipher = body + CSM__X_PK_BYTES;
    nonce_cipher_len = packet_len - (size_t) CSM__SIGN_BYTES - (size_t) CSM__X_PK_BYTES;
    opened_cap = packet_len -
                 (size_t) CSM__SIGN_BYTES -
                 (size_t) CSM__X_PK_BYTES -
                 (size_t) CSM__NONCE_BYTES -
                 (size_t) CSM__MAC_BYTES;
    opened_buf = (uint8_t *) malloc(opened_cap);
    if (opened_buf == NULL) {
        naion_memzero(client_xsk, sizeof(client_xsk));
        return CSM_ERR_CRYPTO;
    }
    ret = csm__open(
        nonce_cipher,
        nonce_cipher_len,
        session_xpk,
        client_xsk,
        session_xpk,
        opened_buf,
        &plaintext_len
    );
    naion_memzero(client_xsk, sizeof(client_xsk));
    if (ret != CSM_OK) {
        naion_memzero(opened_buf, opened_cap);
        free(opened_buf);
        return ret;
    }
    memmove(out_plaintext, opened_buf, plaintext_len);
    *out_plaintext_len = plaintext_len;
    naion_memzero(opened_buf, opened_cap);
    free(opened_buf);
    return CSM_OK;
}

int csm_server_decrypt(
    csm_server *server,
    const uint8_t *packet,
    size_t packet_len,
    uint8_t *out_plaintext,
    size_t out_plaintext_cap,
    size_t *out_plaintext_len
) {
    size_t min_size = (size_t) CSM__SIGN_BYTES +
                      (size_t) CSM__X_PK_BYTES +
                      (size_t) CSM__NONCE_BYTES +
                      (size_t) CSM__MAC_BYTES +
                      (size_t) CSM__ED_PK_BYTES;
    const uint8_t *sig;
    const uint8_t *body;
    const uint8_t *session_xpk;
    const uint8_t *nonce_cipher;
    size_t nonce_cipher_len;
    uint8_t server_xsk[CSM__X_SK_BYTES];
    uint8_t client_ed_public_key[CSM__ED_PK_BYTES];
    uint8_t *opened_buf = NULL;
    size_t opened_cap = 0U;
    size_t opened_len;
    int ret;
    if (out_plaintext_len != NULL) {
        *out_plaintext_len = 0U;
    }
    if (server == NULL || packet == NULL || out_plaintext == NULL || out_plaintext_len == NULL) {
        return CSM_ERR_INVALID_ARGUMENT;
    }
    if (packet_len <= min_size) {
        return CSM_ERR_INVALID_ARGUMENT;
    }
    if (out_plaintext_cap < csm_server_decrypt_max_plaintext_size(packet_len)) {
        return CSM_ERR_BUFFER_TOO_SMALL;
    }
    ret = naion_sign_ed25519_sk_to_curve25519(server_xsk, server->ed_secret_key);
    if (ret != 0) {
        naion_memzero(server_xsk, sizeof(server_xsk));
        return CSM_ERR_CRYPTO;
    }
    sig = packet;
    body = packet + CSM__SIGN_BYTES;
    session_xpk = body;
    nonce_cipher = body + CSM__X_PK_BYTES;
    nonce_cipher_len = packet_len - (size_t) CSM__SIGN_BYTES - (size_t) CSM__X_PK_BYTES;
    opened_cap = nonce_cipher_len - (size_t) CSM__NONCE_BYTES - (size_t) CSM__MAC_BYTES;
    opened_buf = (uint8_t *) malloc(opened_cap);
    if (opened_buf == NULL) {
        naion_memzero(server_xsk, sizeof(server_xsk));
        return CSM_ERR_CRYPTO;
    }

    ret = csm__open(
        nonce_cipher,
        nonce_cipher_len,
        session_xpk,
        server_xsk,
        session_xpk,
        opened_buf,
        &opened_len
    );
    naion_memzero(server_xsk, sizeof(server_xsk));
    if (ret != CSM_OK) {
        naion_memzero(opened_buf, opened_cap);
        free(opened_buf);
        return ret;
    }
    if (opened_len <= (size_t) CSM__ED_PK_BYTES) {
        naion_memzero(opened_buf, opened_cap);
        free(opened_buf);
        return CSM_ERR_CRYPTO;
    }

    memmove(client_ed_public_key, opened_buf, CSM__ED_PK_BYTES);
    ret = csm__verify(sig, body, packet_len - (size_t) CSM__SIGN_BYTES, client_ed_public_key);
    if (ret != CSM_OK) {
        naion_memzero(client_ed_public_key, sizeof(client_ed_public_key));
        naion_memzero(opened_buf, opened_cap);
        free(opened_buf);
        return ret;
    }
    memmove(server->client_ed_public_key, client_ed_public_key, CSM__ED_PK_BYTES);
    server->client_public_key_initialized = 1;
    naion_memzero(client_ed_public_key, sizeof(client_ed_public_key));
    memmove(
        out_plaintext,
        opened_buf + CSM__ED_PK_BYTES,
        opened_len - (size_t) CSM__ED_PK_BYTES
    );
    *out_plaintext_len = opened_len - (size_t) CSM__ED_PK_BYTES;
    naion_memzero(opened_buf, opened_cap);
    free(opened_buf);
    return CSM_OK;
}

int csm_server_encrypt(
    const csm_server *server,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *out_packet,
    size_t out_packet_cap,
    size_t *out_packet_len
) {
    int ret;
    uint8_t client_xpk[CSM__X_PK_BYTES];
    uint8_t session_xsk[CSM__X_SK_BYTES];
    uint8_t session_xpk[CSM__X_PK_BYTES];
    uint8_t *sig;
    uint8_t *body;
    uint8_t *body_payload;
    size_t body_payload_len;
    if (out_packet_len != NULL) {
        *out_packet_len = 0U;
    }
    if (server == NULL || out_packet == NULL || out_packet_len == NULL) {
        return CSM_ERR_INVALID_ARGUMENT;
    }
    if (plaintext == NULL && plaintext_len > 0U) {
        return CSM_ERR_INVALID_ARGUMENT;
    }
    if (plaintext_len == 0U) {
        return CSM_ERR_NO_DATA;
    }
    if (!server->client_public_key_initialized) {
        return CSM_ERR_STATE;
    }
    if (out_packet_cap < csm_server_encrypt_size(plaintext_len)) {
        return CSM_ERR_BUFFER_TOO_SMALL;
    }
    ret = naion_sign_ed25519_pk_to_curve25519(client_xpk, server->client_ed_public_key);
    if (ret != 0) {
        naion_memzero(client_xpk, sizeof(client_xpk));
        return CSM_ERR_CRYPTO;
    }
    ret = naion_box_keypair(session_xpk, session_xsk);
    if (ret != 0) {
        naion_memzero(client_xpk, sizeof(client_xpk));
        naion_memzero(session_xsk, sizeof(session_xsk));
        naion_memzero(session_xpk, sizeof(session_xpk));
        return CSM_ERR_CRYPTO;
    }

    sig = out_packet;
    body = out_packet + CSM__SIGN_BYTES;
    memmove(body, session_xpk, CSM__X_PK_BYTES);
    body_payload = body + CSM__X_PK_BYTES;
    body_payload_len = (size_t) CSM__NONCE_BYTES + (size_t) CSM__MAC_BYTES + plaintext_len;
    ret = csm__seal(
        plaintext,
        plaintext_len,
        client_xpk,
        session_xsk,
        session_xpk,
        body_payload
    );
    if (ret != CSM_OK) {
        naion_memzero(client_xpk, sizeof(client_xpk));
        naion_memzero(session_xsk, sizeof(session_xsk));
        naion_memzero(session_xpk, sizeof(session_xpk));
        return ret;
    }
    ret = csm__sign(body, (size_t) CSM__X_PK_BYTES + body_payload_len, server->ed_secret_key, sig);
    if (ret != CSM_OK) {
        naion_memzero(client_xpk, sizeof(client_xpk));
        naion_memzero(session_xsk, sizeof(session_xsk));
        naion_memzero(session_xpk, sizeof(session_xpk));
        return ret;
    }
    *out_packet_len = csm_server_encrypt_size(plaintext_len);
    naion_memzero(client_xpk, sizeof(client_xpk));
    naion_memzero(session_xsk, sizeof(session_xsk));
    naion_memzero(session_xpk, sizeof(session_xpk));
    return CSM_OK;
}

#ifdef __cplusplus
}
#endif
#endif /* CSM_IMPLEMENTATION */

#endif /* CSM_SINGLE_HEADER_LIBRARY_H */
