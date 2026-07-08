//go:build ignore

#define NAION_IMPLEMENTATION

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "../naion.h"

typedef struct Result {
    unsigned long long elapsed_ns;
    int repeat;
    char *packet_b64;
    char *plaintext_b64;
} Result;

static unsigned long long now_ns(void) {
    LARGE_INTEGER freq;
    LARGE_INTEGER counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return (unsigned long long) ((counter.QuadPart * 1000000000ULL) / freq.QuadPart);
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static int hex_decode(const char *hex, unsigned char **out, size_t *out_len) {
    size_t len;
    size_t i;
    unsigned char *buffer;
    if (hex == NULL || out == NULL || out_len == NULL) {
        return 0;
    }
    len = strlen(hex);
    if ((len % 2U) != 0U) {
        return 0;
    }
    buffer = (unsigned char *) malloc(len / 2U);
    if (buffer == NULL) {
        return 0;
    }
    for (i = 0; i < len / 2U; ++i) {
        const int hi = hex_value(hex[i * 2U]);
        const int lo = hex_value(hex[i * 2U + 1U]);
        if (hi < 0 || lo < 0) {
            free(buffer);
            return 0;
        }
        buffer[i] = (unsigned char) ((hi << 4) | lo);
    }
    *out = buffer;
    *out_len = len / 2U;
    return 1;
}

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *base64_encode(const unsigned char *data, size_t len) {
    size_t out_len = ((len + 2U) / 3U) * 4U;
    char *out = (char *) malloc(out_len + 1U);
    size_t i;
    size_t j = 0U;
    if (out == NULL) {
        return NULL;
    }
    for (i = 0U; i < len; i += 3U) {
        unsigned int value = data[i] << 16;
        value |= (i + 1U < len) ? ((unsigned int) data[i + 1U] << 8) : 0U;
        value |= (i + 2U < len) ? (unsigned int) data[i + 2U] : 0U;
        out[j++] = b64_table[(value >> 18) & 0x3F];
        out[j++] = b64_table[(value >> 12) & 0x3F];
        out[j++] = (i + 1U < len) ? b64_table[(value >> 6) & 0x3F] : '=';
        out[j++] = (i + 2U < len) ? b64_table[value & 0x3F] : '=';
    }
    out[j] = '\0';
    return out;
}

static int b64_index(char c) {
    const char *pos = strchr(b64_table, c);
    if (pos == NULL) {
        return -1;
    }
    return (int) (pos - b64_table);
}

static int base64_decode(const char *text, unsigned char **out, size_t *out_len) {
    size_t len;
    size_t i;
    size_t j = 0U;
    unsigned char *buffer;
    if (text == NULL || out == NULL || out_len == NULL) {
        return 0;
    }
    len = strlen(text);
    if ((len % 4U) != 0U) {
        return 0;
    }
    buffer = (unsigned char *) malloc((len / 4U) * 3U);
    if (buffer == NULL) {
        return 0;
    }
    for (i = 0U; i < len; i += 4U) {
        int a = (text[i] == '=') ? 0 : b64_index(text[i]);
        int b = (text[i + 1U] == '=') ? 0 : b64_index(text[i + 1U]);
        int c = (text[i + 2U] == '=') ? 0 : b64_index(text[i + 2U]);
        int d = (text[i + 3U] == '=') ? 0 : b64_index(text[i + 3U]);
        unsigned int value;
        if (a < 0 || b < 0 || c < 0 || d < 0) {
            free(buffer);
            return 0;
        }
        value = ((unsigned int) a << 18) | ((unsigned int) b << 12) | ((unsigned int) c << 6) | (unsigned int) d;
        buffer[j++] = (unsigned char) ((value >> 16) & 0xFFU);
        if (text[i + 2U] != '=') {
            buffer[j++] = (unsigned char) ((value >> 8) & 0xFFU);
        }
        if (text[i + 3U] != '=') {
            buffer[j++] = (unsigned char) (value & 0xFFU);
        }
    }
    *out = buffer;
    *out_len = j;
    return 1;
}

static const char *arg_value(int argc, char **argv, const char *name) {
    int i;
    for (i = 2; i < argc - 1; ++i) {
        if (strcmp(argv[i], name) == 0) {
            return argv[i + 1];
        }
    }
    return NULL;
}

static int arg_int(int argc, char **argv, const char *name, int default_value) {
    const char *value = arg_value(argc, argv, name);
    if (value == NULL) {
        return default_value;
    }
    return atoi(value);
}

static void sleep_ms(int milliseconds) {
    if (milliseconds <= 0) {
        return;
    }
    Sleep((DWORD) milliseconds);
}

static void fail(const char *message, int code) {
    fprintf(stderr, "%s (code=%d)\n", message, code);
    exit(1);
}

static void emit_result(const Result *result) {
    printf("{\"ok\":true,\"elapsed_ns\":%llu,\"repeat\":%d", result->elapsed_ns, result->repeat);
    if (result->packet_b64 != NULL) {
        printf(",\"packet_b64\":\"%s\"", result->packet_b64);
    }
    if (result->plaintext_b64 != NULL) {
        printf(",\"plaintext_b64\":\"%s\"", result->plaintext_b64);
    }
    printf("}\n");
}

int main(int argc, char **argv) {
    const char *op;
    const char *client_seed_hex;
    const char *server_seed_hex;
    int repeat;
    int sleep_before_decrypt_ms;
    unsigned char *client_seed = NULL;
    unsigned char *server_seed = NULL;
    size_t client_seed_len = 0U;
    size_t server_seed_len = 0U;
    naion_csm_client client;
    naion_csm_server server;
    Result result;

    memset(&client, 0, sizeof(client));
    memset(&server, 0, sizeof(server));
    memset(&result, 0, sizeof(result));

    if (argc < 2) {
        fail("missing op", -1);
    }
    if (naion_csm_init() != NAION_CSM_OK) {
        fail("naion_csm_init failed", -1);
    }

    op = argv[1];
    client_seed_hex = arg_value(argc, argv, "--client-seed");
    server_seed_hex = arg_value(argc, argv, "--server-seed");
    repeat = arg_int(argc, argv, "--repeat", 1);
    sleep_before_decrypt_ms = arg_int(argc, argv, "--sleep-before-decrypt-ms", 0);
    if (client_seed_hex == NULL || server_seed_hex == NULL) {
        fail("client-seed and server-seed are required", -1);
    }
    if (repeat < 1) {
        fail("repeat must be >= 1", -1);
    }
    if (!hex_decode(client_seed_hex, &client_seed, &client_seed_len) ||
        !hex_decode(server_seed_hex, &server_seed, &server_seed_len)) {
        fail("seed hex decode failed", -1);
    }
    if (client_seed_len != naion_sign_ed25519_SEEDBYTES || server_seed_len != naion_sign_ed25519_SEEDBYTES) {
        fail("seed length mismatch", -1);
    }
    if (naion_csm_server_create(&server, server_seed) != NAION_CSM_OK) {
        fail("naion_csm_server_create failed", -1);
    }
    if (naion_csm_client_create(&client, client_seed, server.ed_public_key) != NAION_CSM_OK) {
        fail("naion_csm_client_create failed", -1);
    }

    if (strcmp(op, "client-encrypt") == 0) {
        const char *payload_b64 = arg_value(argc, argv, "--payload-b64");
        unsigned char *payload = NULL;
        size_t payload_len = 0U;
        unsigned char *packet = NULL;
        size_t packet_len = 0U;
        size_t packet_cap = 0U;
        unsigned long long begin;
        if (payload_b64 == NULL || !base64_decode(payload_b64, &payload, &payload_len)) {
            fail("payload base64 decode failed", -1);
        }
        packet_cap = naion_csm_client_encrypt_size(payload_len);
        packet = (unsigned char *) malloc(packet_cap);
        if (packet == NULL) {
            fail("packet alloc failed", -1);
        }
        begin = now_ns();
        {
            int i;
            for (i = 0; i < repeat; ++i) {
                if (naion_csm_client_encrypt(&client, payload, payload_len, packet, packet_cap, &packet_len) != NAION_CSM_OK) {
                    fail("naion_csm_client_encrypt failed", -1);
                }
            }
        }
        result.elapsed_ns = now_ns() - begin;
        result.repeat = repeat;
        result.packet_b64 = base64_encode(packet, packet_len);
        emit_result(&result);
        free(payload);
        free(packet);
    } else if (strcmp(op, "server-decrypt") == 0) {
        const char *packet_b64 = arg_value(argc, argv, "--packet-b64");
        unsigned char *packet = NULL;
        size_t packet_len = 0U;
        unsigned char *plaintext = NULL;
        size_t plaintext_len = 0U;
        size_t plaintext_cap = 0U;
        unsigned long long begin;
        if (packet_b64 == NULL || !base64_decode(packet_b64, &packet, &packet_len)) {
            fail("packet base64 decode failed", -1);
        }
        sleep_ms(sleep_before_decrypt_ms);
        plaintext_cap = naion_csm_server_decrypt_max_plaintext_size(packet_len);
        plaintext = (unsigned char *) malloc(plaintext_cap);
        if (plaintext == NULL) {
            fail("plaintext alloc failed", -1);
        }
        begin = now_ns();
        {
            int i;
            for (i = 0; i < repeat; ++i) {
                if (naion_csm_server_decrypt(&server, packet, packet_len, plaintext, plaintext_cap, &plaintext_len) != NAION_CSM_OK) {
                    fail("naion_csm_server_decrypt failed", -1);
                }
            }
        }
        result.elapsed_ns = now_ns() - begin;
        result.repeat = repeat;
        result.plaintext_b64 = base64_encode(plaintext, plaintext_len);
        emit_result(&result);
        free(packet);
        free(plaintext);
    } else if (strcmp(op, "server-encrypt") == 0) {
        const char *bootstrap_packet_b64 = arg_value(argc, argv, "--bootstrap-packet-b64");
        const char *payload_b64 = arg_value(argc, argv, "--payload-b64");
        unsigned char *bootstrap_packet = NULL;
        size_t bootstrap_packet_len = 0U;
        unsigned char *bootstrap_plain = NULL;
        size_t bootstrap_plain_len = 0U;
        size_t bootstrap_plain_cap = 0U;
        unsigned char *payload = NULL;
        size_t payload_len = 0U;
        unsigned char *packet = NULL;
        size_t packet_len = 0U;
        size_t packet_cap = 0U;
        unsigned long long begin;
        if (bootstrap_packet_b64 == NULL || !base64_decode(bootstrap_packet_b64, &bootstrap_packet, &bootstrap_packet_len)) {
            fail("bootstrap packet decode failed", -1);
        }
        bootstrap_plain_cap = naion_csm_server_decrypt_max_plaintext_size(bootstrap_packet_len);
        bootstrap_plain = (unsigned char *) malloc(bootstrap_plain_cap);
        if (bootstrap_plain == NULL) {
            fail("bootstrap plain alloc failed", -1);
        }
        if (naion_csm_server_decrypt(&server, bootstrap_packet, bootstrap_packet_len, bootstrap_plain, bootstrap_plain_cap, &bootstrap_plain_len) != NAION_CSM_OK) {
            fail("bootstrap server decrypt failed", -1);
        }
        if (payload_b64 == NULL || !base64_decode(payload_b64, &payload, &payload_len)) {
            fail("payload decode failed", -1);
        }
        packet_cap = naion_csm_server_encrypt_size(payload_len);
        packet = (unsigned char *) malloc(packet_cap);
        if (packet == NULL) {
            fail("packet alloc failed", -1);
        }
        begin = now_ns();
        {
            int i;
            for (i = 0; i < repeat; ++i) {
                if (naion_csm_server_encrypt(&server, payload, payload_len, packet, packet_cap, &packet_len) != NAION_CSM_OK) {
                    fail("naion_csm_server_encrypt failed", -1);
                }
            }
        }
        result.elapsed_ns = now_ns() - begin;
        result.repeat = repeat;
        result.packet_b64 = base64_encode(packet, packet_len);
        emit_result(&result);
        free(bootstrap_packet);
        free(bootstrap_plain);
        free(payload);
        free(packet);
    } else if (strcmp(op, "client-decrypt") == 0) {
        const char *packet_b64 = arg_value(argc, argv, "--packet-b64");
        unsigned char *packet = NULL;
        size_t packet_len = 0U;
        unsigned char *plaintext = NULL;
        size_t plaintext_len = 0U;
        size_t plaintext_cap = 0U;
        unsigned long long begin;
        if (packet_b64 == NULL || !base64_decode(packet_b64, &packet, &packet_len)) {
            fail("packet decode failed", -1);
        }
        sleep_ms(sleep_before_decrypt_ms);
        plaintext_cap = naion_csm_client_decrypt_max_plaintext_size(packet_len);
        plaintext = (unsigned char *) malloc(plaintext_cap);
        if (plaintext == NULL) {
            fail("plaintext alloc failed", -1);
        }
        begin = now_ns();
        {
            int i;
            for (i = 0; i < repeat; ++i) {
                if (naion_csm_client_decrypt(&client, packet, packet_len, plaintext, plaintext_cap, &plaintext_len) != NAION_CSM_OK) {
                    fail("naion_csm_client_decrypt failed", -1);
                }
            }
        }
        result.elapsed_ns = now_ns() - begin;
        result.repeat = repeat;
        result.plaintext_b64 = base64_encode(plaintext, plaintext_len);
        emit_result(&result);
        free(packet);
        free(plaintext);
    } else {
        fail("unknown op", -1);
    }

    free(client_seed);
    free(server_seed);
    free(result.packet_b64);
    free(result.plaintext_b64);
    naion_csm_client_wipe(&client);
    naion_csm_server_wipe(&server);
    return 0;
}
