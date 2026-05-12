#ifndef CSM_SINGLE_HEADER_LIBRARY_H
#define CSM_SINGLE_HEADER_LIBRARY_H

// CSM = client-server-model
// 基于 naion(libsodium) 的客户端-服务端通信模型
// client 拥有 server 的 public_key
// server 初始无 client 相关 key 信息

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
    CSM_ERR_NO_DATA = -7,
    CSM_ERR_INVALID_META = -8,
    CSM_ERR_TIMESTAMP_OUTSIDE_WINDOW = -9,
    CSM_ERR_REPLAY_DETECTED = -10
};

typedef struct csm_packet_meta {
    uint8_t magic[4];
    uint8_t protocol_version;
    uint8_t reserved;
    uint16_t flags;
    uint64_t timestamp_ms;
} csm_packet_meta;

typedef struct csm_client {
    uint8_t ed_seed[naion_sign_ed25519_SEEDBYTES];
    uint8_t ed_secret_key[naion_sign_ed25519_SECRETKEYBYTES];
    uint8_t ed_public_key[naion_sign_ed25519_PUBLICKEYBYTES];
    uint8_t server_ed_public_key[naion_sign_ed25519_PUBLICKEYBYTES];
} csm_client;

typedef struct csm_memory_replay_cache_entry {
    uint8_t key[32];
    uint64_t expiry_ms;
    int used;
} csm_memory_replay_cache_entry;

typedef struct csm_memory_replay_cache {
    uint64_t retention_ms;
    size_t capacity;
    csm_memory_replay_cache_entry *entries;
} csm_memory_replay_cache;

typedef struct csm_server {
    uint8_t ed_seed[naion_sign_ed25519_SEEDBYTES];
    uint8_t ed_secret_key[naion_sign_ed25519_SECRETKEYBYTES];
    uint8_t ed_public_key[naion_sign_ed25519_PUBLICKEYBYTES];
    uint8_t client_ed_public_key[naion_sign_ed25519_PUBLICKEYBYTES];
    int client_public_key_initialized;
    uint64_t timestamp_window_ms;
    csm_memory_replay_cache *replay_cache;
} csm_server;

int csm_init(void);
void csm_client_wipe(csm_client *client);
void csm_server_wipe(csm_server *server);
void csm_server_set_timestamp_window_ms(csm_server *server, uint64_t timestamp_window_ms);
void csm_server_set_replay_cache(csm_server *server, csm_memory_replay_cache *replay_cache);
int csm_memory_replay_cache_init(csm_memory_replay_cache *cache, size_t capacity, uint64_t retention_ms);
void csm_memory_replay_cache_wipe(csm_memory_replay_cache *cache);

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
#include <time.h>

#if defined(_WIN32)
#include <windows.h>
#endif

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
    CSM__PACKET_META_BYTES = 16,
    CSM__PACKET_PROTOCOL_VERSION = 1
};

static const uint8_t CSM__PACKET_MAGIC[4] = { 'I', 'F', 'W', '1' };
static const uint64_t CSM__DEFAULT_REPLAY_RETENTION_MS = 5ULL * 60ULL * 1000ULL;

static uint16_t csm__load_u16_le(const uint8_t *src) {
    return (uint16_t) src[0] | ((uint16_t) src[1] << 8);
}

static uint64_t csm__load_u64_le(const uint8_t *src) {
    return (uint64_t) src[0] |
           ((uint64_t) src[1] << 8) |
           ((uint64_t) src[2] << 16) |
           ((uint64_t) src[3] << 24) |
           ((uint64_t) src[4] << 32) |
           ((uint64_t) src[5] << 40) |
           ((uint64_t) src[6] << 48) |
           ((uint64_t) src[7] << 56);
}

static void csm__store_u16_le(uint8_t *dst, uint16_t value) {
    dst[0] = (uint8_t) (value & 0xFFU);
    dst[1] = (uint8_t) ((value >> 8) & 0xFFU);
}

static void csm__store_u64_le(uint8_t *dst, uint64_t value) {
    dst[0] = (uint8_t) (value & 0xFFU);
    dst[1] = (uint8_t) ((value >> 8) & 0xFFU);
    dst[2] = (uint8_t) ((value >> 16) & 0xFFU);
    dst[3] = (uint8_t) ((value >> 24) & 0xFFU);
    dst[4] = (uint8_t) ((value >> 32) & 0xFFU);
    dst[5] = (uint8_t) ((value >> 40) & 0xFFU);
    dst[6] = (uint8_t) ((value >> 48) & 0xFFU);
    dst[7] = (uint8_t) ((value >> 56) & 0xFFU);
}

static uint64_t csm__current_timestamp_ms(void) {
#if defined(_WIN32)
    FILETIME file_time;
    ULARGE_INTEGER ticks;
    GetSystemTimeAsFileTime(&file_time);
    ticks.LowPart = file_time.dwLowDateTime;
    ticks.HighPart = file_time.dwHighDateTime;
    return (uint64_t) ((ticks.QuadPart - 116444736000000000ULL) / 10000ULL);
#else
    return (uint64_t) time(NULL) * 1000ULL;
#endif
}

static void csm__marshal_packet_meta(uint8_t out[CSM__PACKET_META_BYTES], const csm_packet_meta *meta) {
    memmove(out, meta->magic, 4U);
    out[4] = meta->protocol_version;
    out[5] = meta->reserved;
    csm__store_u16_le(out + 6U, meta->flags);
    csm__store_u64_le(out + 8U, meta->timestamp_ms);
}

static int csm__parse_packet_meta(csm_packet_meta *out_meta, const uint8_t *buffer, size_t buffer_len) {
    if (out_meta == NULL || buffer == NULL) {
        return CSM_ERR_INVALID_ARGUMENT;
    }
    if (buffer_len < (size_t) CSM__PACKET_META_BYTES) {
        return CSM_ERR_INVALID_META;
    }
    if (memcmp(buffer, CSM__PACKET_MAGIC, 4U) != 0) {
        return CSM_ERR_INVALID_META;
    }
    out_meta->magic[0] = buffer[0];
    out_meta->magic[1] = buffer[1];
    out_meta->magic[2] = buffer[2];
    out_meta->magic[3] = buffer[3];
    out_meta->protocol_version = buffer[4];
    out_meta->reserved = buffer[5];
    out_meta->flags = csm__load_u16_le(buffer + 6U);
    out_meta->timestamp_ms = csm__load_u64_le(buffer + 8U);
    if (out_meta->protocol_version != (uint8_t) CSM__PACKET_PROTOCOL_VERSION) {
        return CSM_ERR_INVALID_META;
    }
    return CSM_OK;
}

static int csm__memory_replay_cache_check_and_store(
    csm_memory_replay_cache *cache,
    const uint8_t *client_public_key,
    const uint8_t *signature,
    uint64_t now_ms
) {
    size_t i;
    uint8_t material[CSM__ED_PK_BYTES + CSM__SIGN_BYTES];
    uint8_t digest[32];
    size_t free_index = (size_t) -1;
    if (cache == NULL || client_public_key == NULL || signature == NULL) {
        return CSM_ERR_INVALID_ARGUMENT;
    }
    if (cache->entries == NULL || cache->capacity == 0U) {
        return CSM_OK;
    }
    memmove(material, client_public_key, CSM__ED_PK_BYTES);
    memmove(material + CSM__ED_PK_BYTES, signature, CSM__SIGN_BYTES);
    if (naion_generichash(digest, sizeof(digest), material, sizeof(material), NULL, 0U) != 0) {
        return CSM_ERR_CRYPTO;
    }
    for (i = 0U; i < cache->capacity; ++i) {
        csm_memory_replay_cache_entry *entry = &cache->entries[i];
        if (entry->used && entry->expiry_ms <= now_ms) {
            entry->used = 0;
            entry->expiry_ms = 0U;
            naion_memzero(entry->key, sizeof(entry->key));
        }
        if (!entry->used && free_index == (size_t) -1) {
            free_index = i;
        }
        if (entry->used && memcmp(entry->key, digest, sizeof(digest)) == 0) {
            return CSM_ERR_REPLAY_DETECTED;
        }
    }
    if (free_index == (size_t) -1) {
        free_index = 0U;
    }
    memmove(cache->entries[free_index].key, digest, sizeof(digest));
    cache->entries[free_index].expiry_ms = now_ms + cache->retention_ms;
    cache->entries[free_index].used = 1;
    naion_memzero(material, sizeof(material));
    naion_memzero(digest, sizeof(digest));
    return CSM_OK;
}

static int csm__server_validate_timestamp(const csm_server *server, const csm_packet_meta *meta) {
    uint64_t now_ms;
    uint64_t diff_ms;
    if (server == NULL || meta == NULL) {
        return CSM_ERR_INVALID_ARGUMENT;
    }
    if (server->timestamp_window_ms == 0U) {
        return CSM_OK;
    }
    now_ms = csm__current_timestamp_ms();
    diff_ms = (now_ms >= meta->timestamp_ms) ? (now_ms - meta->timestamp_ms) : (meta->timestamp_ms - now_ms);
    if (diff_ms > server->timestamp_window_ms) {
        return CSM_ERR_TIMESTAMP_OUTSIDE_WINDOW;
    }
    return CSM_OK;
}

static int csm__server_check_replay(csm_server *server, const uint8_t *client_public_key, const uint8_t *signature) {
    if (server == NULL || server->replay_cache == NULL) {
        return CSM_OK;
    }
    return csm__memory_replay_cache_check_and_store(
        server->replay_cache,
        client_public_key,
        signature,
        csm__current_timestamp_ms()
    );
}

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
    uint8_t *out_nonce_cipher
) {
    int ret;
    uint8_t nonce[CSM__NONCE_BYTES];
    if (peer_xpk == NULL || self_xsk == NULL || out_nonce_cipher == NULL) {
        return CSM_ERR_INVALID_ARGUMENT;
    }
    if (plaintext_len > 0U && plaintext == NULL) {
        return CSM_ERR_INVALID_ARGUMENT;
    }
    ret = csm__randombytes(nonce, sizeof(nonce));
    if (ret != CSM_OK) {
        return ret;
    }
    ret = naion_box_easy(
        out_nonce_cipher + CSM__NONCE_BYTES,
        plaintext,
        (unsigned long long) plaintext_len,
        nonce,
        peer_xpk,
        self_xsk
    );
    if (ret != 0) {
        naion_memzero(nonce, sizeof(nonce));
        return CSM_ERR_CRYPTO;
    }
    memmove(out_nonce_cipher, nonce, sizeof(nonce));
    naion_memzero(nonce, sizeof(nonce));
    return CSM_OK;
}

static int csm__open(
    const uint8_t *nonce_cipher,
    size_t nonce_cipher_len,
    const uint8_t peer_xpk[CSM__X_PK_BYTES],
    const uint8_t self_xsk[CSM__X_SK_BYTES],
    uint8_t *out_plaintext,
    size_t *out_plaintext_len
) {
    size_t plaintext_len;
    int ret;
    const uint8_t *nonce;
    const uint8_t *mac_ciphertext;
    if (nonce_cipher == NULL || peer_xpk == NULL || self_xsk == NULL ||
        out_plaintext == NULL || out_plaintext_len == NULL) {
        return CSM_ERR_INVALID_ARGUMENT;
    }
    if (nonce_cipher_len <= (size_t) (CSM__NONCE_BYTES + CSM__MAC_BYTES)) {
        return CSM_ERR_INVALID_ARGUMENT;
    }
    plaintext_len = nonce_cipher_len - (size_t) CSM__NONCE_BYTES - (size_t) CSM__MAC_BYTES;
    nonce = nonce_cipher;
    mac_ciphertext = nonce_cipher + CSM__NONCE_BYTES;
    ret = naion_box_open_easy(
        out_plaintext,
        mac_ciphertext,
        (unsigned long long) (plaintext_len + (size_t) CSM__MAC_BYTES),
        nonce,
        peer_xpk,
        self_xsk
    );
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

int csm_memory_replay_cache_init(csm_memory_replay_cache *cache, size_t capacity, uint64_t retention_ms) {
    if (cache == NULL) {
        return CSM_ERR_INVALID_ARGUMENT;
    }
    csm_memory_replay_cache_wipe(cache);
    if (capacity == 0U) {
        cache->retention_ms = (retention_ms == 0U) ? CSM__DEFAULT_REPLAY_RETENTION_MS : retention_ms;
        return CSM_OK;
    }
    cache->entries = (csm_memory_replay_cache_entry *) calloc(capacity, sizeof(csm_memory_replay_cache_entry));
    if (cache->entries == NULL) {
        return CSM_ERR_CRYPTO;
    }
    cache->capacity = capacity;
    cache->retention_ms = (retention_ms == 0U) ? CSM__DEFAULT_REPLAY_RETENTION_MS : retention_ms;
    return CSM_OK;
}

void csm_memory_replay_cache_wipe(csm_memory_replay_cache *cache) {
    if (cache == NULL) {
        return;
    }
    if (cache->entries != NULL) {
        naion_memzero(cache->entries, cache->capacity * sizeof(csm_memory_replay_cache_entry));
        free(cache->entries);
    }
    cache->entries = NULL;
    cache->capacity = 0U;
    cache->retention_ms = 0U;
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

void csm_server_set_timestamp_window_ms(csm_server *server, uint64_t timestamp_window_ms) {
    if (server == NULL) {
        return;
    }
    server->timestamp_window_ms = timestamp_window_ms;
}

void csm_server_set_replay_cache(csm_server *server, csm_memory_replay_cache *replay_cache) {
    if (server == NULL) {
        return;
    }
    server->replay_cache = replay_cache;
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
    server->timestamp_window_ms = 0U;
    server->replay_cache = NULL;
    return CSM_OK;
}

size_t csm_client_encrypt_size(size_t plaintext_len) {
    return (size_t) CSM__SIGN_BYTES +
           (size_t) CSM__X_PK_BYTES +
           (size_t) CSM__NONCE_BYTES +
           (size_t) CSM__MAC_BYTES +
           (size_t) CSM__PACKET_META_BYTES +
           (size_t) CSM__ED_PK_BYTES +
           plaintext_len;
}

size_t csm_client_decrypt_max_plaintext_size(size_t packet_len) {
    size_t fixed = (size_t) CSM__SIGN_BYTES +
                   (size_t) CSM__X_PK_BYTES +
                   (size_t) CSM__NONCE_BYTES +
                   (size_t) CSM__MAC_BYTES +
                   (size_t) CSM__PACKET_META_BYTES;
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
           (size_t) CSM__PACKET_META_BYTES +
           plaintext_len;
}

size_t csm_server_decrypt_max_plaintext_size(size_t packet_len) {
    size_t fixed = (size_t) CSM__SIGN_BYTES +
                   (size_t) CSM__X_PK_BYTES +
                   (size_t) CSM__NONCE_BYTES +
                   (size_t) CSM__MAC_BYTES +
                   (size_t) CSM__PACKET_META_BYTES +
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
    csm_packet_meta meta;
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
    body_payload_len = (size_t) CSM__NONCE_BYTES + (size_t) CSM__MAC_BYTES + (size_t) CSM__PACKET_META_BYTES + (size_t) CSM__ED_PK_BYTES + plaintext_len;
    plain_payload_len = (size_t) CSM__PACKET_META_BYTES + (size_t) CSM__ED_PK_BYTES + plaintext_len;
    plain_payload = (uint8_t *) malloc(plain_payload_len);
    if (plain_payload == NULL) {
        naion_memzero(server_xpk, sizeof(server_xpk));
        naion_memzero(session_xsk, sizeof(session_xsk));
        naion_memzero(session_xpk, sizeof(session_xpk));
        return CSM_ERR_CRYPTO;
    }
    memmove(meta.magic, CSM__PACKET_MAGIC, 4U);
    meta.protocol_version = (uint8_t) CSM__PACKET_PROTOCOL_VERSION;
    meta.reserved = 0U;
    meta.flags = 0U;
    meta.timestamp_ms = csm__current_timestamp_ms();
    csm__marshal_packet_meta(plain_payload, &meta);
    memmove(plain_payload + CSM__PACKET_META_BYTES, client->ed_public_key, CSM__ED_PK_BYTES);
    memmove(plain_payload + CSM__PACKET_META_BYTES + CSM__ED_PK_BYTES, plaintext, plaintext_len);
    ret = csm__seal(
        plain_payload,
        plain_payload_len,
        server_xpk,
        session_xsk,
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
                      (size_t) CSM__MAC_BYTES +
                      (size_t) CSM__PACKET_META_BYTES;
    const uint8_t *sig;
    const uint8_t *body;
    const uint8_t *session_xpk;
    const uint8_t *nonce_cipher;
    size_t nonce_cipher_len;
    uint8_t client_xsk[CSM__X_SK_BYTES];
    csm_packet_meta meta;
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
        opened_buf,
        &plaintext_len
    );
    naion_memzero(client_xsk, sizeof(client_xsk));
    if (ret != CSM_OK) {
        naion_memzero(opened_buf, opened_cap);
        free(opened_buf);
        return ret;
    }
    ret = csm__parse_packet_meta(&meta, opened_buf, plaintext_len);
    if (ret != CSM_OK) {
        naion_memzero(opened_buf, opened_cap);
        free(opened_buf);
        return ret;
    }
    memmove(out_plaintext, opened_buf + CSM__PACKET_META_BYTES, plaintext_len - (size_t) CSM__PACKET_META_BYTES);
    *out_plaintext_len = plaintext_len - (size_t) CSM__PACKET_META_BYTES;
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
    uint8_t *opened_buf = NULL;
    size_t opened_cap = 0U;
    size_t opened_len;
    csm_packet_meta meta;
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
        opened_buf,
        &opened_len
    );
    naion_memzero(server_xsk, sizeof(server_xsk));
    if (ret != CSM_OK) {
        naion_memzero(opened_buf, opened_cap);
        free(opened_buf);
        return ret;
    }
    ret = csm__parse_packet_meta(&meta, opened_buf, opened_len);
    if (ret != CSM_OK) {
        naion_memzero(opened_buf, opened_cap);
        free(opened_buf);
        return ret;
    }
    if (opened_len <= (size_t) CSM__PACKET_META_BYTES + (size_t) CSM__ED_PK_BYTES) {
        naion_memzero(opened_buf, opened_cap);
        free(opened_buf);
        return CSM_ERR_CRYPTO;
    }

    memmove(server->client_ed_public_key, opened_buf + CSM__PACKET_META_BYTES, CSM__ED_PK_BYTES);
    server->client_public_key_initialized = 1;
    ret = csm__verify(sig, body, packet_len - (size_t) CSM__SIGN_BYTES, server->client_ed_public_key);
    if (ret != CSM_OK) {
        naion_memzero(opened_buf, opened_cap);
        free(opened_buf);
        return ret;
    }
    ret = csm__server_validate_timestamp(server, &meta);
    if (ret != CSM_OK) {
        naion_memzero(opened_buf, opened_cap);
        free(opened_buf);
        return ret;
    }
    ret = csm__server_check_replay(server, server->client_ed_public_key, sig);
    if (ret != CSM_OK) {
        naion_memzero(opened_buf, opened_cap);
        free(opened_buf);
        return ret;
    }
    memmove(
        out_plaintext,
        opened_buf + CSM__PACKET_META_BYTES + CSM__ED_PK_BYTES,
        opened_len - (size_t) CSM__PACKET_META_BYTES - (size_t) CSM__ED_PK_BYTES
    );
    *out_plaintext_len = opened_len - (size_t) CSM__PACKET_META_BYTES - (size_t) CSM__ED_PK_BYTES;
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
    size_t plain_payload_len;
    uint8_t *plain_payload;
    csm_packet_meta meta;
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
    body_payload_len = (size_t) CSM__NONCE_BYTES + (size_t) CSM__MAC_BYTES + (size_t) CSM__PACKET_META_BYTES + plaintext_len;
    plain_payload_len = (size_t) CSM__PACKET_META_BYTES + plaintext_len;
    plain_payload = (uint8_t *) malloc(plain_payload_len);
    if (plain_payload == NULL) {
        naion_memzero(client_xpk, sizeof(client_xpk));
        naion_memzero(session_xsk, sizeof(session_xsk));
        naion_memzero(session_xpk, sizeof(session_xpk));
        return CSM_ERR_CRYPTO;
    }
    memmove(meta.magic, CSM__PACKET_MAGIC, 4U);
    meta.protocol_version = (uint8_t) CSM__PACKET_PROTOCOL_VERSION;
    meta.reserved = 0U;
    meta.flags = 0U;
    meta.timestamp_ms = csm__current_timestamp_ms();
    csm__marshal_packet_meta(plain_payload, &meta);
    memmove(plain_payload + CSM__PACKET_META_BYTES, plaintext, plaintext_len);
    ret = csm__seal(
        plain_payload,
        plain_payload_len,
        client_xpk,
        session_xsk,
        body_payload
    );
    naion_memzero(plain_payload, plain_payload_len);
    free(plain_payload);
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
