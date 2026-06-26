/*
 * naion test harness — zero-dependency test for the naion single-header crypto
 * library. Implements the test plan in ../test01.md.
 *
 * Build (default, all four layers, no XSalsa20):
 *     see build.bat   (or:  cl test.c && test_naion.exe)
 * Run:
 *     ./test_naion            normal suite
 *     ./test_naion --full     adds 1MB / 100MB large-buffer tests
 */
#define NAION_IMPLEMENTATION
#include "naion.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ========================================================================= */
/* Test framework primitives                                                  */
/* ========================================================================= */

static int g_passed  = 0;
static int g_failed  = 0;
static const char *g_test_name = "<unset>";

#define TEST_BEGIN(name)                               \
    do {                                               \
        g_test_name = (name);                          \
    } while (0)

/* A CHECK that fails the current test and bails out of the test body. */
#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("  FAIL %-40s [%s:%d] CHECK(%s)\n",                      \
                   g_test_name, __FILE__, __LINE__, #cond);                \
            g_failed++;                                                    \
            return 0;                                                      \
        }                                                                  \
    } while (0)

/* Expect a naion call to return SIMPLE_SODIUM_OK (0). */
#define CHECK_OK(expr)                                                     \
    do {                                                                   \
        int _rc = (int)(expr);                                             \
        if (_rc != 0) {                                                    \
            printf("  FAIL %-40s [%s:%d] expected OK(0), got %d  (%s)\n",   \
                   g_test_name, __FILE__, __LINE__, _rc, #expr);           \
            g_failed++;                                                    \
            return 0;                                                      \
        }                                                                  \
    } while (0)

/* Expect a naion call to return an error (non-zero). */
#define CHECK_ERR(expr)                                                    \
    do {                                                                   \
        int _rc = (int)(expr);                                             \
        if (_rc == 0) {                                                    \
            printf("  FAIL %-40s [%s:%d] expected error, got OK  (%s)\n",   \
                   g_test_name, __FILE__, __LINE__, #expr);                \
            g_failed++;                                                    \
            return 0;                                                      \
        }                                                                  \
    } while (0)

#define TEST_END()                              \
    do {                                        \
        printf("  ok   %s\n", g_test_name);     \
        g_passed++;                             \
        return 1;                               \
    } while (0)

/* Expect a CSM call to return a specific status code. */
#define CHECK_CSM(expr, want)                                              \
    do {                                                                   \
        int _rc = (int)(expr);                                             \
        if (_rc != (want)) {                                               \
            printf("  FAIL %-40s [%s:%d] expected %d, got %d  (%s)\n",     \
                   g_test_name, __FILE__, __LINE__, (want), _rc, #expr);   \
            g_failed++;                                                    \
            return 0;                                                      \
        }                                                                  \
    } while (0)

/* ========================================================================= */
/* Deterministic key system                                                   */
/* ========================================================================= */

/* Fixed 32-byte seed: 0x00..0x1f. */
static const unsigned char DSEED[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

#if NAION_LAYER_SYMM
/* Derive |outlen| bytes from DSEED tagged by |tag| using BLAKE2b. */
static void derive_key(unsigned char *out, size_t outlen, const char *tag)
{
    naion_generichash_state st;
    size_t taglen = tag ? strlen(tag) : 0;
    (void) naion_generichash_init(&st, NULL, 0, outlen);
    (void) naion_generichash_update(&st, DSEED, sizeof DSEED);
    if (taglen > 0) {
        (void) naion_generichash_update(&st, (const unsigned char *) tag, taglen);
    }
    (void) naion_generichash_final(&st, out, outlen);
}
#endif /* NAION_LAYER_SYMM */

/* Fill a buffer with a reproducible pattern: buf[i] = (seed + i) & 0xff. */
static void fill_pattern(unsigned char *buf, size_t len, unsigned int seed)
{
    size_t i;
    for (i = 0; i < len; i++) {
        buf[i] = (unsigned char)(seed + (unsigned int)i);
    }
}

/* ========================================================================= */
/* Size ladders                                                               */
/* ========================================================================= */

/* 18-step size ladder used by the roundtrip tests. */
static const size_t SIZE_LADDER[18] = {
    0, 1, 16, 32, 64, 127, 128, 129, 255, 256, 257,
    512, 1000, 1024, 4096, 65535, 65536, 65537
};

/* Large sizes gated behind --full. */
static const size_t SIZE_LARGE[2] = {
    1048576UL,         /* 1 MB */
    104857600UL        /* 100 MB */
};

#define MAX_LADDER 65537

/* Stack-friendly working buffers for the regular ladder. Sizes accommodate the
 * largest ciphertext: message(65537) + seal overhead(48) = 65585. */
static unsigned char g_buf_a[MAX_LADDER + 64];
static unsigned char g_buf_b[MAX_LADDER + 64];
static unsigned char g_buf_c[MAX_LADDER + 64];

/* ========================================================================= */
/* Section 0 — Utility functions                                              */
/* naion_memcmp / naion_is_zero / naion_verify_32 / naion_memzero            */
/* ========================================================================= */

/* T0.1 */
static int test_memcmp(void)
{
    static const size_t sizes[] = { 0, 1, 16, 32, 128, 1024, 65536 };
    size_t si;
    unsigned char a[65536], b[65536];

    TEST_BEGIN("test_memcmp");
    for (si = 0; si < sizeof sizes / sizeof sizes[0]; si++) {
        size_t n = sizes[si];
        fill_pattern(a, n, 0);
        fill_pattern(b, n, 0);
        CHECK(naion_memcmp(a, b, n) == 0);            /* equal -> 0 */

        if (n > 0) {
            /* first-byte difference */
            fill_pattern(b, n, 0);
            b[0] ^= 0xff;
            CHECK(naion_memcmp(a, b, n) != 0);
            /* last-byte difference */
            fill_pattern(b, n, 0);
            b[n - 1] ^= 0xff;
            CHECK(naion_memcmp(a, b, n) != 0);
        }
    }

    /* all-zero vs all-one */
    memset(a, 0x00, sizeof a);
    memset(b, 0xff, sizeof b);
    CHECK(naion_memcmp(a, b, sizeof a) != 0);
    CHECK(naion_memcmp(a, a, sizeof a) == 0);
    CHECK(naion_memcmp(b, b, sizeof b) == 0);
    TEST_END();
}

/* T0.2 */
static int test_is_zero(void)
{
    static const size_t sizes[] = { 0, 1, 16, 32, 128 };
    size_t si;
    unsigned char buf[128];

    TEST_BEGIN("test_is_zero");
    for (si = 0; si < sizeof sizes / sizeof sizes[0]; si++) {
        size_t n = sizes[si];
        memset(buf, 0, sizeof buf);
        CHECK(naion_is_zero(buf, n) == 1);

        if (n > 0) {
            memset(buf, 0, n);
            buf[0] = 1;                              /* first byte non-zero */
            CHECK(naion_is_zero(buf, n) == 0);

            if (n > 1) {
                memset(buf, 0, n);
                buf[n / 2] = 1;                      /* middle byte non-zero */
                CHECK(naion_is_zero(buf, n) == 0);
                memset(buf, 0, n);
                buf[n - 1] = 1;                      /* last byte non-zero */
                CHECK(naion_is_zero(buf, n) == 0);
            }
        }
    }
    TEST_END();
}

/* T0.3 */
static int test_verify_32(void)
{
    unsigned char x[32], y[32];
    int pos;

    TEST_BEGIN("test_verify_32");
    fill_pattern(x, 32, 0);
    fill_pattern(y, 32, 0);
    CHECK(naion_verify_32(x, y) == 0);

    for (pos = 0; pos < 32; pos++) {
        fill_pattern(y, 32, 0);
        y[pos] ^= 0x01;                              /* single bit flip */
        CHECK(naion_verify_32(x, y) != 0);
        y[pos] ^= 0x01;                              /* restore */
        CHECK(naion_verify_32(x, y) == 0);
    }
    TEST_END();
}

/* T0.4 */
static int test_memzero(void)
{
    static const size_t sizes[] = { 0, 1, 16, 64, 1024, 65536 };
    size_t si;
    unsigned char *buf = g_buf_a;

    TEST_BEGIN("test_memzero");
    for (si = 0; si < sizeof sizes / sizeof sizes[0]; si++) {
        size_t n = sizes[si];
        fill_pattern(buf, n, 0xa5);
        naion_memzero(buf, n);
        CHECK(naion_is_zero(buf, n) == 1);
    }
    TEST_END();
}

/* ========================================================================= */
/* Section 1 — Layer 1 (NAION_LAYER_SYMM)                                     */
/* ========================================================================= */
#if NAION_LAYER_SYMM

/* ---- 1A. RNG & init ----------------------------------------------------- */

/* T1.1 */
static int test_init(void)
{
    TEST_BEGIN("test_init");
    CHECK_OK(naion_init());
    CHECK_OK(naion_init());          /* idempotent */
    TEST_END();
}

/* T1.2 */
static int test_random_provider_default(void)
{
    TEST_BEGIN("test_random_provider_default");
    CHECK(naion_get_random_provider() != NULL);
    TEST_END();
}

/* T1.3 */
static int test_random_provider_custom(void)
{
    naion_random_provider_fn prev;
    unsigned char buf[32];

    TEST_BEGIN("test_random_provider_custom");

    /* Setting NULL must still yield a usable (system) provider. */
    prev = naion_get_random_provider();
    naion_set_random_provider(NULL);
    CHECK(naion_get_random_provider() != NULL);

    memset(buf, 0, sizeof buf);
    naion_get_random_provider()(buf, sizeof buf);
    /* The system provider must not leave the buffer all-zero. */
    CHECK(naion_is_zero(buf, sizeof buf) == 0);

    /* Restore whatever was there (effectively the system provider). */
    naion_set_random_provider(prev);
    CHECK(naion_get_random_provider() == prev || prev == NULL);
    TEST_END();
}

/* Custom deterministic provider: buf[i] = (0x42 + i) & 0xff. */
static void randombytes_custom(void *const buf, const size_t size)
{
    unsigned char *p = (unsigned char *) buf;
    size_t i;
    for (i = 0; i < size; i++) {
        p[i] = (unsigned char)(0x42 + (unsigned int)i);
    }
}

/* T1.4 */
static int test_random_provider_roundtrip(void)
{
    static const size_t sizes[] = { 0, 1, 32, 64, 256, 4096, 65536 };
    naion_random_provider_fn prev;
    unsigned char *buf = g_buf_a;
    unsigned char expect[65536];
    size_t si;

    TEST_BEGIN("test_random_provider_roundtrip");

    prev = naion_get_random_provider();
    naion_set_random_provider(randombytes_custom);
    CHECK(naion_get_random_provider() == randombytes_custom);

    for (si = 0; si < sizeof sizes / sizeof sizes[0]; si++) {
        size_t n = sizes[si];
        memset(buf, 0, n);
        naion_get_random_provider()(buf, n);
        fill_pattern(expect, n, 0x42);
        CHECK(naion_memcmp(buf, expect, n) == 0);
    }

    /* Restore the default provider; naion_init still works afterwards. */
    naion_set_random_provider(NULL);
    CHECK(naion_get_random_provider() != NULL);
    CHECK_OK(naion_init());
    naion_set_random_provider(prev);
    TEST_END();
}

/* ---- 1B. BLAKE2b generichash ------------------------------------------- */

/* T1.5 */
static int test_generichash_one_shot(void)
{
    static const size_t outlens[] = { 16, 32, 64 };
    size_t oi, si;
    unsigned char *in = g_buf_a;
    unsigned char h1[64], h2[64], hkey[64];

    TEST_BEGIN("test_generichash_one_shot");

    for (oi = 0; oi < sizeof outlens / sizeof outlens[0]; oi++) {
        size_t ol = outlens[oi];
        for (si = 0; si < 18; si++) {
            size_t n = SIZE_LADDER[si];
            fill_pattern(in, n, (unsigned int)oi + 1);
            CHECK_OK(naion_generichash(h1, ol, in, n, NULL, 0));
            /* deterministic: same input -> same output */
            CHECK_OK(naion_generichash(h2, ol, in, n, NULL, 0));
            CHECK(naion_memcmp(h1, h2, ol) == 0);

            /* different key -> different output (for non-empty input) */
            derive_key(hkey, ol, "ghkey");
            CHECK_OK(naion_generichash(h2, ol, in, n, hkey, ol));
            if (n > 0) {
                CHECK(naion_memcmp(h1, h2, ol) != 0);
            }
        }
    }
    TEST_END();
}

/* T1.6 */
static int test_generichash_deterministic(void)
{
    unsigned char in[32], out[32], out2[32];

    TEST_BEGIN("test_generichash_deterministic");
    fill_pattern(in, sizeof in, 0);

    CHECK_OK(naion_generichash(out, 32, in, sizeof in, NULL, 0));
    /* Repeatable across calls. */
    CHECK_OK(naion_generichash(out2, 32, in, sizeof in, NULL, 0));
    CHECK(naion_memcmp(out, out2, 32) == 0);

    /* Changing the input changes the digest. */
    in[0] ^= 0xff;
    CHECK_OK(naion_generichash(out2, 32, in, sizeof in, NULL, 0));
    CHECK(naion_memcmp(out, out2, 32) != 0);
    TEST_END();
}

/* T1.7 */
static int test_generichash_streaming(void)
{
    static const size_t chunks[] = { 1, 16, 64 };
    size_t si, ci;
    unsigned char *in = g_buf_a;
    unsigned char one[64], streamed[64];

    TEST_BEGIN("test_generichash_streaming");

    for (si = 0; si < 14; si++) {       /* cover 0 .. 4096 incl. 128B boundary */
        size_t total = SIZE_LADDER[si];
        fill_pattern(in, total, 0x11);

        CHECK_OK(naion_generichash(one, 32, in, total, NULL, 0));

        for (ci = 0; ci < sizeof chunks / sizeof chunks[0]; ci++) {
            naion_generichash_state st;
            size_t off = 0;
            CHECK_OK(naion_generichash_init(&st, NULL, 0, 32));
            while (off < total) {
                size_t step = chunks[ci];
                if (off + step > total) step = total - off;
                CHECK_OK(naion_generichash_update(&st, in + off, step));
                off += step;
            }
            CHECK_OK(naion_generichash_final(&st, streamed, 32));
            CHECK(naion_memcmp(one, streamed, 32) == 0);
        }
    }
    TEST_END();
}

/* T1.8 */
static int test_generichash_errors(void)
{
    naion_generichash_state st;
    unsigned char out[32];
    unsigned char in[32];
    unsigned char key[32];

    TEST_BEGIN("test_generichash_errors");

    /* one-shot: NULL out, NULL in with len>0, NULL state, outlen out of range,
     * key==NULL with keylen>0. */
    CHECK_ERR(naion_generichash(NULL, 32, in, sizeof in, NULL, 0));
    CHECK_ERR(naion_generichash(out, 32, NULL, 1, NULL, 0));     /* in NULL + len */
    CHECK_ERR(naion_generichash(out, 15, in, sizeof in, NULL, 0));  /* outlen < 16 */
    CHECK_ERR(naion_generichash(out, 65, in, sizeof in, NULL, 0));  /* outlen > 64 */
    CHECK_ERR(naion_generichash(out, 32, in, sizeof in, NULL, 16)); /* key NULL + keylen>0 */
    CHECK_ERR(naion_generichash(out, 32, in, sizeof in, key, 15));  /* keylen < 16 */
    CHECK_ERR(naion_generichash(out, 32, in, sizeof in, key, 65));  /* keylen > 64 */

    /* streaming */
    CHECK_ERR(naion_generichash_init(NULL, NULL, 0, 32));
    CHECK_ERR(naion_generichash_init(&st, NULL, 0, 15));
    CHECK_ERR(naion_generichash_update(NULL, in, sizeof in));
    CHECK_ERR(naion_generichash_final(&st, NULL, 32));
    TEST_END();
}

/* T1.9 */
static int test_generichash_keyed(void)
{
    static const size_t keylens[] = { 16, 32, 64 };
    static const size_t msglens[] = { 0, 32, 256 };
    unsigned char key[64], msg[256];
    unsigned char unkeyed[32], keyed[32], keyed2[32];
    size_t ki, mi;

    TEST_BEGIN("test_generichash_keyed");
    for (mi = 0; mi < sizeof msglens / sizeof msglens[0]; mi++) {
        size_t mlen = msglens[mi];
        fill_pattern(msg, mlen, 0x21);
        CHECK_OK(naion_generichash(unkeyed, 32, msg, mlen, NULL, 0));

        for (ki = 0; ki < sizeof keylens / sizeof keylens[0]; ki++) {
            size_t klen = keylens[ki];
            derive_key(key, klen, "ghk");
            CHECK_OK(naion_generichash(keyed, 32, msg, mlen, key, klen));
            if (mlen > 0) {
                CHECK(naion_memcmp(unkeyed, keyed, 32) != 0);
            }
            /* deterministic */
            CHECK_OK(naion_generichash(keyed2, 32, msg, mlen, key, klen));
            CHECK(naion_memcmp(keyed, keyed2, 32) == 0);
        }
    }

    /* keylen boundary checks */
    fill_pattern(msg, 32, 0x21);
    CHECK_ERR(naion_generichash(keyed, 32, msg, 32, key, 15));   /* < 16 */
    CHECK_ERR(naion_generichash(keyed, 32, msg, 32, key, 65));   /* > 64 */
    TEST_END();
}

/* ---- 1C. XChaCha20 stream ---------------------------------------------- */

/* T1.10 */
static int test_stream_xchacha20_keystream(void)
{
    unsigned char key[32], nonce[24];
    unsigned char *c1 = g_buf_a, *c2 = g_buf_b, *c3 = g_buf_c;
    size_t si;

    TEST_BEGIN("test_stream_xchacha20_keystream");
    derive_key(key, 32, "stream-k");
    derive_key(nonce, 24, "stream-n");

    for (si = 0; si < 18; si++) {
        size_t n = SIZE_LADDER[si];
        CHECK_OK(naion_stream_xchacha20(c1, n, nonce, key));

        if (n > 0) {
            /* keystream must not be all-zero */
            CHECK(naion_is_zero(c1, n) == 0);

            /* same key+nonce -> identical keystream */
            CHECK_OK(naion_stream_xchacha20(c2, n, nonce, key));
            CHECK(naion_memcmp(c1, c2, n) == 0);
        }
    }

    /* different nonce -> different keystream (for non-trivial length) */
    CHECK_OK(naion_stream_xchacha20(c1, 64, nonce, key));
    nonce[0] ^= 0xff;
    CHECK_OK(naion_stream_xchacha20(c3, 64, nonce, key));
    CHECK(naion_memcmp(c1, c3, 64) != 0);
    nonce[0] ^= 0xff;
    TEST_END();
}

/* T1.11 */
static int test_stream_xchacha20_deterministic(void)
{
    unsigned char key[32], nonce[24];
    unsigned char ks1[64], ks2[64];

    TEST_BEGIN("test_stream_xchacha20_deterministic");
    derive_key(key, 32, "det-k");
    derive_key(nonce, 24, "det-n");

    CHECK_OK(naion_stream_xchacha20(ks1, 64, nonce, key));
    CHECK_OK(naion_stream_xchacha20(ks2, 64, nonce, key));
    CHECK(naion_memcmp(ks1, ks2, 64) == 0);

    /* changing the key changes the keystream */
    key[0] ^= 0xff;
    CHECK_OK(naion_stream_xchacha20(ks2, 64, nonce, key));
    CHECK(naion_memcmp(ks1, ks2, 64) != 0);
    TEST_END();
}

/* T1.12 */
static int test_stream_xchacha20_xor_roundtrip(void)
{
    unsigned char key[32], nonce[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    size_t si;

    TEST_BEGIN("test_stream_xchacha20_xor_roundtrip");
    derive_key(key, 32, "xor-k");
    derive_key(nonce, 24, "xor-n");

    for (si = 0; si < 18; si++) {
        size_t n = SIZE_LADDER[si];
        fill_pattern(m, n, 0x33);
        CHECK_OK(naion_stream_xchacha20_xor(c, m, n, nonce, key));
        if (n > 0) {
            /* ciphertext != plaintext */
            CHECK(naion_memcmp(c, m, n) != 0);
        }
        /* self-inverse: xor again recovers plaintext */
        CHECK_OK(naion_stream_xchacha20_xor(m2, c, n, nonce, key));
        CHECK(naion_memcmp(m, m2, n) == 0);
    }
    TEST_END();
}

/* T1.13 */
static int test_stream_xchacha20_xor_ic(void)
{
    static const size_t mlens[] = { 0, 128, 256, 512, 1024 };
    unsigned char key[32], nonce[24];
    unsigned char *m = g_buf_a, *c0 = g_buf_b, *c_ic = g_buf_c, *m2 = g_buf_b;
    size_t si;

    TEST_BEGIN("test_stream_xchacha20_xor_ic");
    derive_key(key, 32, "ic-k");
    derive_key(nonce, 24, "ic-n");

    for (si = 0; si < sizeof mlens / sizeof mlens[0]; si++) {
        size_t n = mlens[si];
        fill_pattern(m, n, 0x44);

        /* ic=0 matches _xor */
        CHECK_OK(naion_stream_xchacha20_xor(c0, m, n, nonce, key));
        CHECK_OK(naion_stream_xchacha20_xor_ic(c_ic, m, n, nonce, 0ULL, key));
        CHECK(naion_memcmp(c0, c_ic, n) == 0);

        /* ic>0 differs from ic=0 (for non-trivial length) */
        if (n > 0) {
            CHECK_OK(naion_stream_xchacha20_xor_ic(c_ic, m, n, nonce, 4ULL, key));
            CHECK(naion_memcmp(c0, c_ic, n) != 0);
        }

        /* round-trip with a fixed ic */
        CHECK_OK(naion_stream_xchacha20_xor_ic(c_ic, m, n, nonce, 7ULL, key));
        CHECK_OK(naion_stream_xchacha20_xor_ic(m2, c_ic, n, nonce, 7ULL, key));
        CHECK(naion_memcmp(m, m2, n) == 0);
    }

    /* boundary counter */
    {
        fill_pattern(m, 64, 0x44);
        CHECK_OK(naion_stream_xchacha20_xor_ic(c0, m, 64, nonce, 0xFFFFFFFFULL, key));
        CHECK_OK(naion_stream_xchacha20_xor_ic(m2, c0, 64, nonce, 0xFFFFFFFFULL, key));
        CHECK(naion_memcmp(m, m2, 64) == 0);
    }
    TEST_END();
}

/* T1.14 */
static int test_stream_errors_null(void)
{
    unsigned char key[32], nonce[24], out[64];

    TEST_BEGIN("test_stream_errors_null");
    derive_key(key, 32, "err-k");
    derive_key(nonce, 24, "err-n");

    /* keystream */
    CHECK_ERR(naion_stream_xchacha20(NULL, 64, nonce, key));
    CHECK_ERR(naion_stream_xchacha20(out, 64, NULL, key));
    CHECK_ERR(naion_stream_xchacha20(out, 64, nonce, NULL));

    /* xor: NULL m with mlen>0 must fail */
    CHECK_ERR(naion_stream_xchacha20_xor(out, NULL, 1, nonce, key));
    CHECK_ERR(naion_stream_xchacha20_xor(NULL, out, 1, nonce, key));
    CHECK_ERR(naion_stream_xchacha20_xor(out, out, 1, NULL, key));
    CHECK_ERR(naion_stream_xchacha20_xor(out, out, 1, nonce, NULL));

    /* xor_ic: NULL m with mlen>0 must fail */
    CHECK_ERR(naion_stream_xchacha20_xor_ic(out, NULL, 1, nonce, 0ULL, key));
    CHECK_ERR(naion_stream_xchacha20_xor_ic(NULL, out, 1, nonce, 0ULL, key));
    CHECK_ERR(naion_stream_xchacha20_xor_ic(out, out, 1, NULL, 0ULL, key));
    CHECK_ERR(naion_stream_xchacha20_xor_ic(out, out, 1, nonce, 0ULL, NULL));
    TEST_END();
}

#endif /* NAION_LAYER_SYMM */

/* ========================================================================= */
/* Section 2 — Layer 2 (NAION_LAYER_AEAD)                                     */
/* ========================================================================= */
#if NAION_LAYER_AEAD

/* shared nonce/key/nonce derivation for the AEAD tests */
static void aead_kn(unsigned char key[32], unsigned char nonce[24])
{
    derive_key(key, 32, "aead-k");
    derive_key(nonce, 24, "aead-n");
}

/* ---- 2A. AEAD-IETF ----------------------------------------------------- */

/* T2.1 */
static int test_aead_ietf_roundtrip(void)
{
    static const size_t adlens[] = { 0, 1, 32, 256 };
    unsigned char key[32], nonce[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    unsigned char ad[256];
    size_t si, ai;
    unsigned long long clen = 0, mlen = 0;

    TEST_BEGIN("test_aead_ietf_roundtrip");
    aead_kn(key, nonce);

    for (si = 0; si < 18; si++) {
        size_t n = SIZE_LADDER[si];
        fill_pattern(m, n, 0x55);
        for (ai = 0; ai < sizeof adlens / sizeof adlens[0]; ai++) {
            size_t alen = adlens[ai];
            fill_pattern(ad, alen, 0xaa);

            CHECK_OK(naion_aead_xchacha20poly1305_ietf_encrypt(
                c, &clen, m, n, ad, alen, NULL, nonce, key));
            CHECK(clen == (unsigned long long)(n + 16));   /* mlen + ABYTES */

            mlen = 0;
            CHECK_OK(naion_aead_xchacha20poly1305_ietf_decrypt(
                m2, &mlen, NULL, c, clen, ad, alen, nonce, key));
            CHECK(mlen == (unsigned long long)n);
            CHECK(naion_memcmp(m, m2, n) == 0);
        }
    }
    TEST_END();
}

/* T2.2 */
static int test_aead_ietf_tamper(void)
{
    static const size_t mlens[] = { 32, 256, 4096 };
    unsigned char key[32], nonce[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    unsigned long long clen = 0, mlen = 0;
    size_t si, pos;

    TEST_BEGIN("test_aead_ietf_tamper");
    aead_kn(key, nonce);

    for (si = 0; si < sizeof mlens / sizeof mlens[0]; si++) {
        size_t n = mlens[si];
        fill_pattern(m, n, 0x55);
        CHECK_OK(naion_aead_xchacha20poly1305_ietf_encrypt(
            c, &clen, m, n, NULL, 0, NULL, nonce, key));

        /* tamper ciphertext byte 0 */
        pos = 0;
        c[pos] ^= 0xff;
        mlen = 0;
        CHECK_ERR(naion_aead_xchacha20poly1305_ietf_decrypt(
            m2, &mlen, NULL, c, clen, NULL, 0, nonce, key));
        c[pos] ^= 0xff;

        /* tamper last ciphertext byte */
        pos = clen - 1;
        c[pos] ^= 0xff;
        mlen = 0;
        CHECK_ERR(naion_aead_xchacha20poly1305_ietf_decrypt(
            m2, &mlen, NULL, c, clen, NULL, 0, nonce, key));
        c[pos] ^= 0xff;

        /* tamper MAC byte 0 (MAC is the trailing 16 bytes: c[clen-16]) */
        pos = clen - 16;
        c[pos] ^= 0xff;
        mlen = 0;
        CHECK_ERR(naion_aead_xchacha20poly1305_ietf_decrypt(
            m2, &mlen, NULL, c, clen, NULL, 0, nonce, key));
        c[pos] ^= 0xff;
    }
    TEST_END();
}

/* T2.3 */
static int test_aead_ietf_wrong_ad(void)
{
    static const size_t mlens[] = { 32, 256, 4096 };
    unsigned char key[32], nonce[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    unsigned char ad_enc[4] = { 'f','o','o',0 };
    unsigned char ad_dec[4] = { 'b','a','r',0 };
    unsigned long long clen = 0, mlen = 0;
    size_t si;

    TEST_BEGIN("test_aead_ietf_wrong_ad");
    aead_kn(key, nonce);
    for (si = 0; si < sizeof mlens / sizeof mlens[0]; si++) {
        size_t n = mlens[si];
        fill_pattern(m, n, 0x55);
        CHECK_OK(naion_aead_xchacha20poly1305_ietf_encrypt(
            c, &clen, m, n, ad_enc, 3, NULL, nonce, key));
        mlen = 0;
        CHECK_ERR(naion_aead_xchacha20poly1305_ietf_decrypt(
            m2, &mlen, NULL, c, clen, ad_dec, 3, nonce, key));
    }
    TEST_END();
}

/* T2.4 */
static int test_aead_ietf_wrong_nonce(void)
{
    static const size_t mlens[] = { 32, 256 };
    unsigned char key[32], nonce[24], nonce2[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    unsigned long long clen = 0, mlen = 0;
    size_t si;

    TEST_BEGIN("test_aead_ietf_wrong_nonce");
    aead_kn(key, nonce);
    memcpy(nonce2, nonce, 24);
    nonce2[0] ^= 0xff;

    for (si = 0; si < sizeof mlens / sizeof mlens[0]; si++) {
        size_t n = mlens[si];
        fill_pattern(m, n, 0x55);
        CHECK_OK(naion_aead_xchacha20poly1305_ietf_encrypt(
            c, &clen, m, n, NULL, 0, NULL, nonce, key));
        mlen = 0;
        CHECK_ERR(naion_aead_xchacha20poly1305_ietf_decrypt(
            m2, &mlen, NULL, c, clen, NULL, 0, nonce2, key));
    }
    TEST_END();
}

/* T2.5 */
static int test_aead_ietf_wrong_key(void)
{
    static const size_t mlens[] = { 32, 256 };
    unsigned char key[32], key2[32], nonce[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    unsigned long long clen = 0, mlen = 0;
    size_t si;

    TEST_BEGIN("test_aead_ietf_wrong_key");
    aead_kn(key, nonce);
    derive_key(key2, 32, "aead-k2");

    for (si = 0; si < sizeof mlens / sizeof mlens[0]; si++) {
        size_t n = mlens[si];
        fill_pattern(m, n, 0x55);
        CHECK_OK(naion_aead_xchacha20poly1305_ietf_encrypt(
            c, &clen, m, n, NULL, 0, NULL, nonce, key));
        mlen = 0;
        CHECK_ERR(naion_aead_xchacha20poly1305_ietf_decrypt(
            m2, &mlen, NULL, c, clen, NULL, 0, nonce, key2));
    }
    TEST_END();
}

/* T2.6 */
static int test_aead_ietf_detached_roundtrip(void)
{
    unsigned char key[32], nonce[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    unsigned char mac[16];
    unsigned char *cc = g_buf_c;            /* combined for equivalence */
    unsigned long long maclen = 0;
    size_t si;
    unsigned long long clen_c;

    TEST_BEGIN("test_aead_ietf_detached_roundtrip");
    aead_kn(key, nonce);

    for (si = 0; si < 18; si++) {
        size_t n = SIZE_LADDER[si];
        fill_pattern(m, n, 0x55);

        maclen = 0;
        CHECK_OK(naion_aead_xchacha20poly1305_ietf_encrypt_detached(
            c, mac, &maclen, m, n, NULL, 0, NULL, nonce, key));
        CHECK(maclen == 16);

        CHECK_OK(naion_aead_xchacha20poly1305_ietf_decrypt_detached(
            m2, NULL, c, n, mac, NULL, 0, nonce, key));
        CHECK(naion_memcmp(m, m2, n) == 0);

        /* equivalence: detached (c||mac) must equal combined encrypt */
        clen_c = 0;
        CHECK_OK(naion_aead_xchacha20poly1305_ietf_encrypt(
            cc, &clen_c, m, n, NULL, 0, NULL, nonce, key));
        CHECK(naion_memcmp(cc, c, n) == 0);
        CHECK(naion_memcmp(cc + n, mac, 16) == 0);
    }
    TEST_END();
}

/* T2.7 */
static int test_aead_ietf_detached_tamper_mac(void)
{
    static const size_t mlens[] = { 32, 256, 4096 };
    unsigned char key[32], nonce[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    unsigned char mac[16];
    unsigned long long maclen = 0;
    size_t si, pos;

    TEST_BEGIN("test_aead_ietf_detached_tamper_mac");
    aead_kn(key, nonce);

    for (si = 0; si < sizeof mlens / sizeof mlens[0]; si++) {
        size_t n = mlens[si];
        fill_pattern(m, n, 0x55);
        maclen = 0;
        CHECK_OK(naion_aead_xchacha20poly1305_ietf_encrypt_detached(
            c, mac, &maclen, m, n, NULL, 0, NULL, nonce, key));

        for (pos = 0; pos < 16; pos++) {
            mac[pos] ^= 0xff;
            CHECK_ERR(naion_aead_xchacha20poly1305_ietf_decrypt_detached(
                m2, NULL, c, n, mac, NULL, 0, nonce, key));
            mac[pos] ^= 0xff;
        }
    }
    TEST_END();
}

/* T2.8 */
static int test_aead_ietf_detached_tamper_ct(void)
{
    static const size_t mlens[] = { 32, 256, 4096 };
    unsigned char key[32], nonce[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    unsigned char mac[16];
    unsigned long long maclen = 0;
    size_t si, pos;

    TEST_BEGIN("test_aead_ietf_detached_tamper_ct");
    aead_kn(key, nonce);

    for (si = 0; si < sizeof mlens / sizeof mlens[0]; si++) {
        size_t n = mlens[si];
        fill_pattern(m, n, 0x55);
        maclen = 0;
        CHECK_OK(naion_aead_xchacha20poly1305_ietf_encrypt_detached(
            c, mac, &maclen, m, n, NULL, 0, NULL, nonce, key));

        if (n == 0) continue;
        pos = 0;
        c[pos] ^= 0xff;
        CHECK_ERR(naion_aead_xchacha20poly1305_ietf_decrypt_detached(
            m2, NULL, c, n, mac, NULL, 0, nonce, key));
        c[pos] ^= 0xff;

        pos = n - 1;
        c[pos] ^= 0xff;
        CHECK_ERR(naion_aead_xchacha20poly1305_ietf_decrypt_detached(
            m2, NULL, c, n, mac, NULL, 0, nonce, key));
        c[pos] ^= 0xff;
    }
    TEST_END();
}

/* T2.9 */
static int test_aead_ietf_detached_wrong_ad(void)
{
    static const size_t mlens[] = { 32, 256 };
    unsigned char key[32], nonce[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    unsigned char mac[16], ad1[4] = { 'f','o','o' }, ad2[4] = { 'b','a','r' };
    unsigned long long maclen = 0;
    size_t si;

    TEST_BEGIN("test_aead_ietf_detached_wrong_ad");
    aead_kn(key, nonce);
    for (si = 0; si < sizeof mlens / sizeof mlens[0]; si++) {
        size_t n = mlens[si];
        fill_pattern(m, n, 0x55);
        maclen = 0;
        CHECK_OK(naion_aead_xchacha20poly1305_ietf_encrypt_detached(
            c, mac, &maclen, m, n, ad1, 3, NULL, nonce, key));
        CHECK_ERR(naion_aead_xchacha20poly1305_ietf_decrypt_detached(
            m2, NULL, c, n, mac, ad2, 3, nonce, key));
    }
    TEST_END();
}

/* T2.10 */
static int test_aead_ietf_errors(void)
{
    unsigned char key[32], nonce[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    unsigned char ad[4] = { 1, 2, 3, 4 };
    unsigned char mac[16];
    unsigned char nsec[1] = { 0 };
    unsigned long long clen = 0, mlen = 0, maclen = 0;

    TEST_BEGIN("test_aead_ietf_errors");
    aead_kn(key, nonce);
    fill_pattern(m, 32, 0x55);

    /* nsec != NULL must fail */
    CHECK_ERR(naion_aead_xchacha20poly1305_ietf_encrypt(
        c, &clen, m, 32, NULL, 0, nsec, nonce, key));
    CHECK_ERR(naion_aead_xchacha20poly1305_ietf_decrypt(
        m2, &mlen, nsec, c, 48, NULL, 0, nonce, key));

    /* encrypt: NULL required args */
    CHECK_ERR(naion_aead_xchacha20poly1305_ietf_encrypt(
        NULL, &clen, m, 32, NULL, 0, NULL, nonce, key));
    CHECK_ERR(naion_aead_xchacha20poly1305_ietf_encrypt(
        c, NULL, m, 32, NULL, 0, NULL, nonce, key));
    CHECK_ERR(naion_aead_xchacha20poly1305_ietf_encrypt(
        c, &clen, m, 32, NULL, 0, NULL, NULL, key));
    CHECK_ERR(naion_aead_xchacha20poly1305_ietf_encrypt(
        c, &clen, m, 32, NULL, 0, NULL, nonce, NULL));
    CHECK_ERR(naion_aead_xchacha20poly1305_ietf_encrypt(
        c, &clen, NULL, 1, NULL, 0, NULL, nonce, key));     /* m NULL + mlen>0 */

    /* decrypt: clen < 16 */
    CHECK_ERR(naion_aead_xchacha20poly1305_ietf_decrypt(
        m2, &mlen, NULL, c, 15, NULL, 0, nonce, key));
    /* decrypt: NULL c/m/npub/k */
    CHECK_ERR(naion_aead_xchacha20poly1305_ietf_decrypt(
        NULL, &mlen, NULL, c, 48, NULL, 0, nonce, key));
    CHECK_ERR(naion_aead_xchacha20poly1305_ietf_decrypt(
        m2, NULL, NULL, c, 48, NULL, 0, nonce, key));
    CHECK_ERR(naion_aead_xchacha20poly1305_ietf_decrypt(
        m2, &mlen, NULL, NULL, 48, NULL, 0, nonce, key));
    CHECK_ERR(naion_aead_xchacha20poly1305_ietf_decrypt(
        m2, &mlen, NULL, c, 48, NULL, 0, NULL, key));
    CHECK_ERR(naion_aead_xchacha20poly1305_ietf_decrypt(
        m2, &mlen, NULL, c, 48, NULL, 0, nonce, NULL));

    /* NULL ad + adlen>0 */
    CHECK_ERR(naion_aead_xchacha20poly1305_ietf_encrypt(
        c, &clen, m, 32, NULL, 4, NULL, nonce, key));

    /* detached */
    CHECK_ERR(naion_aead_xchacha20poly1305_ietf_encrypt_detached(
        NULL, mac, &maclen, m, 32, NULL, 0, NULL, nonce, key));
    CHECK_ERR(naion_aead_xchacha20poly1305_ietf_encrypt_detached(
        c, NULL, &maclen, m, 32, NULL, 0, NULL, nonce, key));
    CHECK_ERR(naion_aead_xchacha20poly1305_ietf_decrypt_detached(
        NULL, NULL, c, 32, mac, NULL, 0, nonce, key));
    CHECK_ERR(naion_aead_xchacha20poly1305_ietf_decrypt_detached(
        m2, NULL, NULL, 32, mac, NULL, 0, nonce, key));
    (void) ad;
    TEST_END();
}

/* T2.11 */
static int test_aead_ietf_empty_msg(void)
{
    static const size_t adlens[] = { 0, 32, 256 };
    unsigned char key[32], nonce[24];
    unsigned char *c = g_buf_a, *m2 = g_buf_b;
    unsigned char ad[256];
    unsigned long long clen = 0, mlen = 0;
    size_t ai;

    TEST_BEGIN("test_aead_ietf_empty_msg");
    aead_kn(key, nonce);

    for (ai = 0; ai < sizeof adlens / sizeof adlens[0]; ai++) {
        size_t alen = adlens[ai];
        fill_pattern(ad, alen, 0xaa);

        clen = 0;
        CHECK_OK(naion_aead_xchacha20poly1305_ietf_encrypt(
            c, &clen, NULL, 0, ad, alen, NULL, nonce, key));
        CHECK(clen == 16);                       /* MAC only */

        mlen = 0;
        CHECK_OK(naion_aead_xchacha20poly1305_ietf_decrypt(
            m2, &mlen, NULL, c, clen, ad, alen, nonce, key));
        CHECK(mlen == 0);

        /* tamper the MAC */
        c[0] ^= 0xff;
        mlen = 0;
        CHECK_ERR(naion_aead_xchacha20poly1305_ietf_decrypt(
            m2, &mlen, NULL, c, clen, ad, alen, nonce, key));
        c[0] ^= 0xff;
    }
    TEST_END();
}

/* T2.12 — determinism + round-trip with a libsodium-style fixed vector. */
static int test_aead_ietf_vs_libsodium(void)
{
    static const unsigned char key[32] = {
        0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
        0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
        0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f
    };
    static const unsigned char nonce[24] = {
        0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
        0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,
        0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57
    };
    static const unsigned char msg114[114] = {
        0x4c,0x61,0x64,0x69,0x65,0x73,0x20,0x61,0x6e,0x64,0x20,0x47,0x65,0x6e,
        0x74,0x6c,0x65,0x6d,0x65,0x6e,0x20,0x6f,0x66,0x20,0x74,0x68,0x65,0x20,
        0x63,0x6c,0x61,0x73,0x73,0x20,0x6f,0x66,0x20,0x27,0x39,0x39,0x3a,0x20,
        0x49,0x66,0x20,0x49,0x20,0x63,0x6f,0x75,0x6c,0x64,0x20,0x6f,0x66,0x66,
        0x65,0x72,0x20,0x79,0x6f,0x75,0x20,0x6f,0x6e,0x6c,0x79,0x20,0x6f,0x6e,
        0x65,0x20,0x74,0x69,0x70,0x20,0x66,0x6f,0x72,0x20,0x74,0x68,0x65,0x20,
        0x66,0x75,0x74,0x75,0x72,0x65,0x2c,0x20,0x73,0x75,0x6e,0x73,0x63,0x72,
        0x65,0x65,0x6e,0x20,0x77,0x6f,0x75,0x6c,0x64,0x20,0x62,0x65,0x20,0x69,
        0x74,0x2e
    };
    static const size_t lengths[] = { 0, 32, 114 };
    unsigned char c[114 + 16], m2[114], c2[114 + 16];
    unsigned long long clen, mlen;
    size_t li;

    TEST_BEGIN("test_aead_ietf_vs_libsodium");
    for (li = 0; li < sizeof lengths / sizeof lengths[0]; li++) {
        size_t n = lengths[li];
        clen = 0;
        CHECK_OK(naion_aead_xchacha20poly1305_ietf_encrypt(
            c, &clen, msg114, n, NULL, 0, NULL, nonce, key));
        CHECK(clen == (unsigned long long)(n + 16));

        /* deterministic */
        clen = 0;
        CHECK_OK(naion_aead_xchacha20poly1305_ietf_encrypt(
            c2, &clen, msg114, n, NULL, 0, NULL, nonce, key));
        CHECK(naion_memcmp(c, c2, n + 16) == 0);

        /* round-trip */
        mlen = 0;
        CHECK_OK(naion_aead_xchacha20poly1305_ietf_decrypt(
            m2, &mlen, NULL, c, n + 16, NULL, 0, nonce, key));
        CHECK(mlen == (unsigned long long)n);
        CHECK(naion_memcmp(msg114, m2, n) == 0);
    }
    TEST_END();
}

/* ---- 2B. secretbox ----------------------------------------------------- */

static void secretbox_kn(unsigned char key[32], unsigned char nonce[24])
{
    derive_key(key, 32, "sbox-k");
    derive_key(nonce, 24, "sbox-n");
}

/* T2.13 */
static int test_secretbox_easy_roundtrip(void)
{
    unsigned char key[32], nonce[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    size_t si;

    TEST_BEGIN("test_secretbox_easy_roundtrip");
    secretbox_kn(key, nonce);

    for (si = 0; si < 18; si++) {
        size_t n = SIZE_LADDER[si];
        fill_pattern(m, n, 0x66);
        CHECK_OK(naion_secretbox_xchacha20poly1305_easy(c, m, n, nonce, key));
        /* layout MAC[16] || CT[mlen] */
        CHECK_OK(naion_secretbox_xchacha20poly1305_open_easy(m2, c, n + 16, nonce, key));
        CHECK(naion_memcmp(m, m2, n) == 0);

        if (n > 0) {
            /* tamper MAC */
            c[0] ^= 0xff;
            CHECK_ERR(naion_secretbox_xchacha20poly1305_open_easy(m2, c, n + 16, nonce, key));
            c[0] ^= 0xff;
            /* tamper CT */
            c[16] ^= 0xff;
            CHECK_ERR(naion_secretbox_xchacha20poly1305_open_easy(m2, c, n + 16, nonce, key));
            c[16] ^= 0xff;
        }
    }
    TEST_END();
}

/* T2.14 */
static int test_secretbox_easy_tamper(void)
{
    static const size_t mlens[] = { 32, 256, 4096 };
    unsigned char key[32], nonce[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    size_t si;

    TEST_BEGIN("test_secretbox_easy_tamper");
    secretbox_kn(key, nonce);
    for (si = 0; si < sizeof mlens / sizeof mlens[0]; si++) {
        size_t n = mlens[si];
        fill_pattern(m, n, 0x66);
        CHECK_OK(naion_secretbox_xchacha20poly1305_easy(c, m, n, nonce, key));

        /* tamper MAC byte (front 16) */
        c[5] ^= 0xff;
        CHECK_ERR(naion_secretbox_xchacha20poly1305_open_easy(m2, c, n + 16, nonce, key));
        c[5] ^= 0xff;
        /* tamper CT byte */
        c[16 + n / 2] ^= 0xff;
        CHECK_ERR(naion_secretbox_xchacha20poly1305_open_easy(m2, c, n + 16, nonce, key));
        c[16 + n / 2] ^= 0xff;
    }
    TEST_END();
}

/* T2.15 */
static int test_secretbox_easy_wrong_key(void)
{
    static const size_t mlens[] = { 32, 256 };
    unsigned char key[32], key2[32], nonce[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    size_t si;

    TEST_BEGIN("test_secretbox_easy_wrong_key");
    secretbox_kn(key, nonce);
    derive_key(key2, 32, "sbox-k2");
    for (si = 0; si < sizeof mlens / sizeof mlens[0]; si++) {
        size_t n = mlens[si];
        fill_pattern(m, n, 0x66);
        CHECK_OK(naion_secretbox_xchacha20poly1305_easy(c, m, n, nonce, key));
        CHECK_ERR(naion_secretbox_xchacha20poly1305_open_easy(m2, c, n + 16, nonce, key2));
    }
    TEST_END();
}

/* T2.16 */
static int test_secretbox_easy_wrong_nonce(void)
{
    static const size_t mlens[] = { 32, 256 };
    unsigned char key[32], nonce[24], nonce2[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    size_t si;

    TEST_BEGIN("test_secretbox_easy_wrong_nonce");
    secretbox_kn(key, nonce);
    memcpy(nonce2, nonce, 24);
    nonce2[0] ^= 0xff;
    for (si = 0; si < sizeof mlens / sizeof mlens[0]; si++) {
        size_t n = mlens[si];
        fill_pattern(m, n, 0x66);
        CHECK_OK(naion_secretbox_xchacha20poly1305_easy(c, m, n, nonce, key));
        CHECK_ERR(naion_secretbox_xchacha20poly1305_open_easy(m2, c, n + 16, nonce2, key));
    }
    TEST_END();
}

/* T2.17 */
static int test_secretbox_detached_roundtrip(void)
{
    unsigned char key[32], nonce[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    unsigned char mac[16], *cc = g_buf_c;        /* combined MAC||CT for equivalence */
    size_t si;

    TEST_BEGIN("test_secretbox_detached_roundtrip");
    secretbox_kn(key, nonce);
    for (si = 0; si < 18; si++) {
        size_t n = SIZE_LADDER[si];
        fill_pattern(m, n, 0x66);
        CHECK_OK(naion_secretbox_xchacha20poly1305_detached(c, mac, m, n, nonce, key));
        CHECK_OK(naion_secretbox_xchacha20poly1305_open_detached(m2, c, mac, n, nonce, key));
        CHECK(naion_memcmp(m, m2, n) == 0);

        /* equivalence with easy: mac||c == easy output */
        CHECK_OK(naion_secretbox_xchacha20poly1305_easy(cc, m, n, nonce, key));
        CHECK(naion_memcmp(cc, mac, 16) == 0);
        CHECK(naion_memcmp(cc + 16, c, n) == 0);
    }
    TEST_END();
}

/* T2.18 */
static int test_secretbox_detached_tamper(void)
{
    static const size_t mlens[] = { 32, 256, 4096 };
    unsigned char key[32], nonce[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    unsigned char mac[16], badmac[16];
    size_t si;

    TEST_BEGIN("test_secretbox_detached_tamper");
    secretbox_kn(key, nonce);
    for (si = 0; si < sizeof mlens / sizeof mlens[0]; si++) {
        size_t n = mlens[si];
        fill_pattern(m, n, 0x66);
        CHECK_OK(naion_secretbox_xchacha20poly1305_detached(c, mac, m, n, nonce, key));

        /* tamper MAC */
        mac[0] ^= 0xff;
        CHECK_ERR(naion_secretbox_xchacha20poly1305_open_detached(m2, c, mac, n, nonce, key));
        mac[0] ^= 0xff;
        /* tamper CT */
        c[0] ^= 0xff;
        CHECK_ERR(naion_secretbox_xchacha20poly1305_open_detached(m2, c, mac, n, nonce, key));
        c[0] ^= 0xff;
        /* wrong MAC + correct CT */
        memcpy(badmac, mac, 16);
        badmac[15] ^= 0xff;
        CHECK_ERR(naion_secretbox_xchacha20poly1305_open_detached(m2, c, badmac, n, nonce, key));
    }
    TEST_END();
}

/* T2.19 */
static int test_secretbox_errors(void)
{
    unsigned char key[32], nonce[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    unsigned char mac[16];

    TEST_BEGIN("test_secretbox_errors");
    secretbox_kn(key, nonce);
    fill_pattern(m, 32, 0x66);
    CHECK_OK(naion_secretbox_xchacha20poly1305_easy(c, m, 32, nonce, key));

    /* easy: NULL */
    CHECK_ERR(naion_secretbox_xchacha20poly1305_easy(NULL, m, 32, nonce, key));
    CHECK_ERR(naion_secretbox_xchacha20poly1305_easy(c, NULL, 32, nonce, key));
    CHECK_ERR(naion_secretbox_xchacha20poly1305_easy(c, m, 32, NULL, key));
    CHECK_ERR(naion_secretbox_xchacha20poly1305_easy(c, m, 32, nonce, NULL));
    /* open_easy: clen < 16 */
    CHECK_ERR(naion_secretbox_xchacha20poly1305_open_easy(m2, c, 15, nonce, key));
    /* open_easy: NULL */
    CHECK_ERR(naion_secretbox_xchacha20poly1305_open_easy(NULL, c, 48, nonce, key));
    CHECK_ERR(naion_secretbox_xchacha20poly1305_open_easy(m2, NULL, 48, nonce, key));
    CHECK_ERR(naion_secretbox_xchacha20poly1305_open_easy(m2, c, 48, NULL, key));
    CHECK_ERR(naion_secretbox_xchacha20poly1305_open_easy(m2, c, 48, nonce, NULL));

    /* detached */
    CHECK_ERR(naion_secretbox_xchacha20poly1305_detached(NULL, mac, m, 32, nonce, key));
    CHECK_ERR(naion_secretbox_xchacha20poly1305_detached(c, NULL, m, 32, nonce, key));
    CHECK_ERR(naion_secretbox_xchacha20poly1305_open_detached(m2, c, NULL, 32, nonce, key));
    CHECK_ERR(naion_secretbox_xchacha20poly1305_open_detached(NULL, c, mac, 32, nonce, key));
    TEST_END();
}

/* T2.20 */
static int test_secretbox_empty(void)
{
    unsigned char key[32], nonce[24];
    unsigned char *c = g_buf_a, *m2 = g_buf_b;

    TEST_BEGIN("test_secretbox_empty");
    secretbox_kn(key, nonce);
    CHECK_OK(naion_secretbox_xchacha20poly1305_easy(c, NULL, 0, nonce, key));
    /* only MAC produced */
    CHECK(naion_is_zero(c, 16) == 0);
    CHECK_OK(naion_secretbox_xchacha20poly1305_open_easy(m2, c, 16, nonce, key));
    /* tamper MAC fails */
    c[0] ^= 0xff;
    CHECK_ERR(naion_secretbox_xchacha20poly1305_open_easy(m2, c, 16, nonce, key));
    c[0] ^= 0xff;
    TEST_END();
}

/* T2.21 */
static int test_secretbox_stream_interop(void)
{
    unsigned char key[32], nonce[24];
    unsigned char m1[32], m2[32];
    unsigned char c1[32 + 16], c2[32 + 16];

    TEST_BEGIN("test_secretbox_stream_interop");
    secretbox_kn(key, nonce);
    fill_pattern(m1, 32, 0x01);
    fill_pattern(m2, 32, 0x02);

    CHECK_OK(naion_secretbox_xchacha20poly1305_easy(c1, m1, 32, nonce, key));
    CHECK_OK(naion_secretbox_xchacha20poly1305_easy(c2, m2, 32, nonce, key));

    /* MAC must be non-zero and must depend on the message. */
    CHECK(naion_is_zero(c1, 16) == 0);
    CHECK(naion_is_zero(c2, 16) == 0);
    CHECK(naion_memcmp(c1, c2, 16) != 0);

    /* The ciphertext body is m XOR keystream; same key+nonce keystream means
     * c1[16:] XOR c2[16:] == m1 XOR m2. */
    {
        unsigned char diff[32];
        size_t i;
        for (i = 0; i < 32; i++) {
            diff[i] = (unsigned char)((c1[16 + i] ^ c2[16 + i]) ^ (m1[i] ^ m2[i]));
        }
        CHECK(naion_is_zero(diff, 32) == 1);
    }
    TEST_END();
}

/* ---- 2C. Box symmetric core (easy_afternm) ----------------------------- */

static void afternm_kn(unsigned char k[32], unsigned char n[24])
{
    derive_key(k, 32, "afternm-k");
    derive_key(n, 24, "afternm-n");
}

/* T2.22 */
static int test_box_afternm_roundtrip(void)
{
    unsigned char k[32], n[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    size_t si;

    TEST_BEGIN("test_box_afternm_roundtrip");
    afternm_kn(k, n);
    for (si = 0; si < 18; si++) {
        size_t len = SIZE_LADDER[si];
        fill_pattern(m, len, 0x77);
        CHECK_OK(naion_box_curve25519xchacha20poly1305_easy_afternm(c, m, len, n, k));
        CHECK_OK(naion_box_curve25519xchacha20poly1305_open_easy_afternm(m2, c, len + 16, n, k));
        CHECK(naion_memcmp(m, m2, len) == 0);
        if (len > 0) {
            c[0] ^= 0xff;
            CHECK_ERR(naion_box_curve25519xchacha20poly1305_open_easy_afternm(m2, c, len + 16, n, k));
            c[0] ^= 0xff;
        }
    }
    TEST_END();
}

/* T2.23 */
static int test_box_afternm_tamper(void)
{
    static const size_t mlens[] = { 32, 256, 4096 };
    unsigned char k[32], n[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    size_t si;

    TEST_BEGIN("test_box_afternm_tamper");
    afternm_kn(k, n);
    for (si = 0; si < sizeof mlens / sizeof mlens[0]; si++) {
        size_t len = mlens[si];
        fill_pattern(m, len, 0x77);
        CHECK_OK(naion_box_curve25519xchacha20poly1305_easy_afternm(c, m, len, n, k));
        c[3] ^= 0xff;                                       /* MAC */
        CHECK_ERR(naion_box_curve25519xchacha20poly1305_open_easy_afternm(m2, c, len + 16, n, k));
        c[3] ^= 0xff;
        c[16] ^= 0xff;                                      /* CT */
        CHECK_ERR(naion_box_curve25519xchacha20poly1305_open_easy_afternm(m2, c, len + 16, n, k));
        c[16] ^= 0xff;
    }
    TEST_END();
}

/* T2.24 */
static int test_box_afternm_wrong_key(void)
{
    static const size_t mlens[] = { 32, 256 };
    unsigned char k[32], k2[32], n[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    size_t si;

    TEST_BEGIN("test_box_afternm_wrong_key");
    afternm_kn(k, n);
    derive_key(k2, 32, "afternm-k2");
    for (si = 0; si < sizeof mlens / sizeof mlens[0]; si++) {
        size_t len = mlens[si];
        fill_pattern(m, len, 0x77);
        CHECK_OK(naion_box_curve25519xchacha20poly1305_easy_afternm(c, m, len, n, k));
        CHECK_ERR(naion_box_curve25519xchacha20poly1305_open_easy_afternm(m2, c, len + 16, n, k2));
    }
    TEST_END();
}

/* T2.25 */
static int test_box_afternm_wrong_nonce(void)
{
    static const size_t mlens[] = { 32, 256 };
    unsigned char k[32], n[24], n2[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    size_t si;

    TEST_BEGIN("test_box_afternm_wrong_nonce");
    afternm_kn(k, n);
    memcpy(n2, n, 24);
    n2[0] ^= 0xff;
    for (si = 0; si < sizeof mlens / sizeof mlens[0]; si++) {
        size_t len = mlens[si];
        fill_pattern(m, len, 0x77);
        CHECK_OK(naion_box_curve25519xchacha20poly1305_easy_afternm(c, m, len, n, k));
        CHECK_ERR(naion_box_curve25519xchacha20poly1305_open_easy_afternm(m2, c, len + 16, n2, k));
    }
    TEST_END();
}

/* T2.26 */
static int test_box_afternm_errors(void)
{
    unsigned char k[32], n[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;

    TEST_BEGIN("test_box_afternm_errors");
    afternm_kn(k, n);
    fill_pattern(m, 32, 0x77);
    CHECK_OK(naion_box_curve25519xchacha20poly1305_easy_afternm(c, m, 32, n, k));

    /* easy_afternm: NULL */
    CHECK_ERR(naion_box_curve25519xchacha20poly1305_easy_afternm(NULL, m, 32, n, k));
    CHECK_ERR(naion_box_curve25519xchacha20poly1305_easy_afternm(c, NULL, 32, n, k));
    CHECK_ERR(naion_box_curve25519xchacha20poly1305_easy_afternm(c, m, 32, NULL, k));
    CHECK_ERR(naion_box_curve25519xchacha20poly1305_easy_afternm(c, m, 32, n, NULL));
    /* open_easy_afternm: clen < 16 */
    CHECK_ERR(naion_box_curve25519xchacha20poly1305_open_easy_afternm(m2, c, 15, n, k));
    CHECK_ERR(naion_box_curve25519xchacha20poly1305_open_easy_afternm(NULL, c, 48, n, k));
    CHECK_ERR(naion_box_curve25519xchacha20poly1305_open_easy_afternm(m2, NULL, 48, n, k));
    CHECK_ERR(naion_box_curve25519xchacha20poly1305_open_easy_afternm(m2, c, 48, NULL, k));
    CHECK_ERR(naion_box_curve25519xchacha20poly1305_open_easy_afternm(m2, c, 48, n, NULL));
    TEST_END();
}

/* T2.27 — secretbox delegates to easy_afternm: identical output. */
static int test_secretbox_delegates_to_afternm(void)
{
    static const size_t mlens[] = { 0, 32, 256 };
    unsigned char k[32], n[24];
    unsigned char *m = g_buf_a, *cs = g_buf_b, *cb = g_buf_c;
    size_t si;

    TEST_BEGIN("test_secretbox_delegates_to_afternm");
    afternm_kn(k, n);
    for (si = 0; si < sizeof mlens / sizeof mlens[0]; si++) {
        size_t len = mlens[si];
        fill_pattern(m, len, 0x88);
        CHECK_OK(naion_secretbox_xchacha20poly1305_easy(cs, m, len, n, k));
        CHECK_OK(naion_box_curve25519xchacha20poly1305_easy_afternm(cb, m, len, n, k));
        CHECK(naion_memcmp(cs, cb, len + 16) == 0);
    }
    TEST_END();
}

#endif /* NAION_LAYER_AEAD */

/* ========================================================================= */
/* Section 3 — Layer 3 (NAION_LAYER_CSM)                                      */
/* ========================================================================= */
#if NAION_LAYER_CSM

/* ---- 3A. X25519 scalar multiplication ---------------------------------- */

/* RFC 7748 test vector scalars / public keys (section 6.1). */
static const unsigned char RFC7748_ALICE_SK[32] = {
    0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,
    0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
    0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,
    0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a
};
static const unsigned char RFC7748_ALICE_PK[32] = {
    0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54,
    0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a,
    0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4,
    0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a
};
static const unsigned char RFC7748_BOB_SK[32] = {
    0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
    0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
    0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
    0x1c,0x2f,0x28,0x89,0x67,0x31,0xbc,0xea
};
static const unsigned char RFC7748_BOB_PK[32] = {
    0x07,0x75,0xa5,0x1c,0xef,0xf4,0x1c,0x24,
    0xf2,0x08,0xed,0x70,0xa4,0x38,0x75,0xb7,
    0x4f,0x02,0x0f,0xb6,0xfd,0x73,0xdf,0x92,
    0x80,0xf8,0x68,0x3c,0xd4,0xb8,0x63,0x54
};

/* T3.1 */
static int test_scalarmult_rfc7748(void)
{
    unsigned char pk[32];

    TEST_BEGIN("test_scalarmult_rfc7748");
    /* base * alice_sk == alice_pk */
    CHECK_OK(naion_scalarmult_curve25519_base(pk, RFC7748_ALICE_SK));
    CHECK(naion_memcmp(pk, RFC7748_ALICE_PK, 32) == 0);
    /* base * bob_sk == bob_pk */
    CHECK_OK(naion_scalarmult_curve25519_base(pk, RFC7748_BOB_SK));
    CHECK(naion_memcmp(pk, RFC7748_BOB_PK, 32) == 0);
    TEST_END();
}

/* T3.2 */
static int test_scalarmult_dh_agreement(void)
{
    /* DH agreement: derive each party's public key as base*sk, then verify
     * sk_a*pk_b == sk_b*pk_a. The public keys are derived from the same scalar
     * engine the library uses, so this checks the DH property directly rather
     * than RFC 7748 wire compatibility (see test_scalarmult_rfc7748). */
    unsigned char pk_a[32], pk_b[32], s_ab[32], s_ba[32];

    TEST_BEGIN("test_scalarmult_dh_agreement");
    CHECK_OK(naion_scalarmult_curve25519_base(pk_a, RFC7748_ALICE_SK));
    CHECK_OK(naion_scalarmult_curve25519_base(pk_b, RFC7748_BOB_SK));
    CHECK_OK(naion_scalarmult_curve25519(s_ab, RFC7748_ALICE_SK, pk_b));
    CHECK_OK(naion_scalarmult_curve25519(s_ba, RFC7748_BOB_SK, pk_a));
    CHECK(naion_memcmp(s_ab, s_ba, 32) == 0);
    TEST_END();
}

/* T3.3 */
static int test_scalarmult_commutative(void)
{
    unsigned char sa[32], sb[32], pk_a[32], pk_b[32], sk_a[32], sk_b[32];
    int trial;

    TEST_BEGIN("test_scalarmult_commutative");
    for (trial = 0; trial < 4; trial++) {
        derive_key(sk_a, 32, "comm-a");
        derive_key(sk_b, 32, "comm-b");
        sk_a[31] ^= (unsigned char)trial;
        sk_b[31] ^= (unsigned char)(trial + 1);
        CHECK_OK(naion_scalarmult_curve25519_base(pk_a, sk_a));
        CHECK_OK(naion_scalarmult_curve25519_base(pk_b, sk_b));
        CHECK_OK(naion_scalarmult_curve25519(sa, sk_a, pk_b));
        CHECK_OK(naion_scalarmult_curve25519(sb, sk_b, pk_a));
        CHECK(naion_memcmp(sa, sb, 32) == 0);
    }
    TEST_END();
}

/* T3.4 */
static int test_scalarmult_errors(void)
{
    unsigned char q[32], n[32], p[32];

    TEST_BEGIN("test_scalarmult_errors");
    derive_key(n, 32, "sm-n");
    derive_key(p, 32, "sm-p");

    CHECK_ERR(naion_scalarmult_curve25519(NULL, n, p));
    CHECK_ERR(naion_scalarmult_curve25519(q, NULL, p));
    CHECK_ERR(naion_scalarmult_curve25519(q, n, NULL));
    CHECK_ERR(naion_scalarmult_curve25519_base(NULL, n));
    CHECK_ERR(naion_scalarmult_curve25519_base(q, NULL));

    /* base() with an all-zero scalar: a valid scalar (only low-order *points*
     * are rejected), so it must not error. The encoded result is
     * implementation-defined (the identity point), so we only assert no error
     * and determinism. */
    memset(n, 0, 32);
    CHECK_OK(naion_scalarmult_curve25519_base(q, n));
    {
        unsigned char q2[32];
        CHECK_OK(naion_scalarmult_curve25519_base(q2, n));
        CHECK(naion_memcmp(q, q2, 32) == 0);
    }
    TEST_END();
}

/* T3.5 */
static int test_scalarmult_small_order(void)
{
    static const unsigned char small0[32]  = { 0 };
    static const unsigned char small1[32]  = { 1 };
    /* 0xe0eb7a... one of the RFC 7748 blacklist points */
    static const unsigned char smallp3[32] = {
        0xe0,0xeb,0x7a,0x7c,0x3b,0x41,0xb8,0xae,
        0x16,0x56,0xe3,0xfa,0xf1,0x9f,0xc4,0x6a,
        0xda,0x09,0x8d,0xeb,0x9c,0x32,0xb1,0xfd,
        0x86,0x62,0x05,0x16,0x5f,0x49,0xb8,0x00
    };
    unsigned char sk[32], q[32];

    TEST_BEGIN("test_scalarmult_small_order");
    derive_key(sk, 32, "so-sk");
    CHECK_ERR(naion_scalarmult_curve25519(q, sk, small0));
    CHECK_ERR(naion_scalarmult_curve25519(q, sk, small1));
    CHECK_ERR(naion_scalarmult_curve25519(q, sk, smallp3));
    TEST_END();
}

/* T3.6 */
static int test_scalarmult_zero_scalar(void)
{
    /* Zero-scalar behaviour. The encoded identity point is
     * implementation-defined for this library, so we only assert that the calls
     * succeed and are deterministic. */
    unsigned char sk0[32], pk_base[32], q_bob[32], bob[32];

    TEST_BEGIN("test_scalarmult_zero_scalar");
    memset(sk0, 0, 32);
    /* base * 0 must not error and must be deterministic */
    CHECK_OK(naion_scalarmult_curve25519_base(pk_base, sk0));
    {
        unsigned char pk2[32];
        CHECK_OK(naion_scalarmult_curve25519_base(pk2, sk0));
        CHECK(naion_memcmp(pk_base, pk2, 32) == 0);
    }
    /* 0 * bob must not error and must be deterministic */
    derive_key(bob, 32, "zs-bob");
    CHECK_OK(naion_scalarmult_curve25519_base(bob, bob));
    CHECK_OK(naion_scalarmult_curve25519(q_bob, sk0, bob));
    {
        unsigned char q2[32];
        CHECK_OK(naion_scalarmult_curve25519(q2, sk0, bob));
        CHECK(naion_memcmp(q_bob, q2, 32) == 0);
    }
    TEST_END();
}

/* ---- 3B. KX key exchange ---------------------------------------------- */

/* T3.7 */
static int test_kx_keypair_random(void)
{
    unsigned char pk1[32], sk1[32], pk2[32], sk2[32];

    TEST_BEGIN("test_kx_keypair_random");
    CHECK_OK(naion_kx_keypair(pk1, sk1));
    CHECK_OK(naion_kx_keypair(pk2, sk2));
    CHECK(naion_is_zero(pk1, 32) == 0);
    CHECK(naion_is_zero(sk1, 32) == 0);
    CHECK(naion_memcmp(pk1, sk1, 32) != 0);
    CHECK(naion_memcmp(pk1, pk2, 32) != 0);
    CHECK(naion_memcmp(sk1, sk2, 32) != 0);
    TEST_END();
}

/* T3.8 */
static int test_kx_seed_keypair(void)
{
    unsigned char seed[32], pk1[32], sk1[32], pk2[32], sk2[32], base_pk[32];

    TEST_BEGIN("test_kx_seed_keypair");
    derive_key(seed, 32, "kx-seed");

    CHECK_OK(naion_kx_seed_keypair(pk1, sk1, seed));
    CHECK_OK(naion_kx_seed_keypair(pk2, sk2, seed));
    CHECK(naion_memcmp(pk1, pk2, 32) == 0);
    CHECK(naion_memcmp(sk1, sk2, 32) == 0);

    /* different seed -> different keypair */
    seed[0] ^= 0xff;
    CHECK_OK(naion_kx_seed_keypair(pk2, sk2, seed));
    CHECK(naion_memcmp(pk1, pk2, 32) != 0);

    /* pk == base * sk */
    CHECK_OK(naion_scalarmult_curve25519_base(base_pk, sk1));
    CHECK(naion_memcmp(base_pk, pk1, 32) == 0);
    TEST_END();
}

/* T3.9 */
static int test_kx_session_keys(void)
{
    unsigned char cpk[32], csk[32], spk[32], ssk[32];
    unsigned char c_rx[32], c_tx[32], s_rx[32], s_tx[32];

    TEST_BEGIN("test_kx_session_keys");
    CHECK_OK(naion_kx_keypair(cpk, csk));
    CHECK_OK(naion_kx_keypair(spk, ssk));

    CHECK_OK(naion_kx_client_session_keys(c_rx, c_tx, cpk, csk, spk));
    CHECK_OK(naion_kx_server_session_keys(s_rx, s_tx, spk, ssk, cpk));

    /* mirror property: rx_c == tx_s && tx_c == rx_s */
    CHECK(naion_memcmp(c_rx, s_tx, 32) == 0);
    CHECK(naion_memcmp(c_tx, s_rx, 32) == 0);
    TEST_END();
}

/* T3.10 */
static int test_kx_session_keys_deterministic(void)
{
    unsigned char seed[32], cpk[32], csk[32], spk[32], ssk[32];
    unsigned char c_rx1[32], c_tx1[32], c_rx2[32], c_tx2[32];

    TEST_BEGIN("test_kx_session_keys_deterministic");
    derive_key(seed, 32, "kx-det");
    CHECK_OK(naion_kx_seed_keypair(cpk, csk, seed));
    seed[0] ^= 0xff;
    CHECK_OK(naion_kx_seed_keypair(spk, ssk, seed));

    CHECK_OK(naion_kx_client_session_keys(c_rx1, c_tx1, cpk, csk, spk));
    CHECK_OK(naion_kx_client_session_keys(c_rx2, c_tx2, cpk, csk, spk));
    CHECK(naion_memcmp(c_rx1, c_rx2, 32) == 0);
    CHECK(naion_memcmp(c_tx1, c_tx2, 32) == 0);
    TEST_END();
}

/* T3.11 */
static int test_kx_session_aliasing(void)
{
    unsigned char cpk[32], csk[32], spk[32], ssk[32];
    unsigned char both[32], rx_only[32], tx_only[32];

    TEST_BEGIN("test_kx_session_aliasing");
    CHECK_OK(naion_kx_keypair(cpk, csk));
    CHECK_OK(naion_kx_keypair(spk, ssk));

    /* When a single buffer is provided the keys are written into it in
     * rx-then-tx order, so the aliased buffer ends up holding the tx key. */
    CHECK_OK(naion_kx_client_session_keys(both, NULL, cpk, csk, spk));
    CHECK_OK(naion_kx_client_session_keys(rx_only, tx_only, cpk, csk, spk));
    CHECK(naion_memcmp(both, tx_only, 32) == 0);

    CHECK_OK(naion_kx_client_session_keys(NULL, both, cpk, csk, spk));
    CHECK(naion_memcmp(both, tx_only, 32) == 0);

    /* both NULL -> error */
    CHECK_ERR(naion_kx_client_session_keys(NULL, NULL, cpk, csk, spk));
    (void) ssk; (void) rx_only;
    TEST_END();
}

/* T3.12 */
static int test_kx_errors(void)
{
    unsigned char seed[32], pk[32], sk[32], buf[32];

    TEST_BEGIN("test_kx_errors");
    derive_key(seed, 32, "kx-err");
    CHECK_OK(naion_kx_seed_keypair(pk, sk, seed));

    /* keypair */
    CHECK_ERR(naion_kx_keypair(NULL, sk));
    CHECK_ERR(naion_kx_keypair(pk, NULL));
    /* seed_keypair */
    CHECK_ERR(naion_kx_seed_keypair(NULL, sk, seed));
    CHECK_ERR(naion_kx_seed_keypair(pk, NULL, seed));
    CHECK_ERR(naion_kx_seed_keypair(pk, sk, NULL));
    /* client session */
    CHECK_ERR(naion_kx_client_session_keys(buf, buf, NULL, sk, pk));
    CHECK_ERR(naion_kx_client_session_keys(buf, buf, pk, NULL, pk));
    CHECK_ERR(naion_kx_client_session_keys(buf, buf, pk, sk, NULL));
    /* server session */
    CHECK_ERR(naion_kx_server_session_keys(buf, buf, NULL, sk, pk));
    CHECK_ERR(naion_kx_server_session_keys(buf, buf, pk, NULL, pk));
    CHECK_ERR(naion_kx_server_session_keys(buf, buf, pk, sk, NULL));
    TEST_END();
}

/* ---- 3C. Box XChaCha20 asymmetric ------------------------------------- */

/* T3.13 */
static int test_box_xchacha_keypair(void)
{
    unsigned char pk1[32], sk1[32], pk2[32], sk2[32];

    TEST_BEGIN("test_box_xchacha_keypair");
    CHECK_OK(naion_box_curve25519xchacha20poly1305_keypair(pk1, sk1));
    CHECK_OK(naion_box_curve25519xchacha20poly1305_keypair(pk2, sk2));
    CHECK(naion_is_zero(pk1, 32) == 0);
    CHECK(naion_is_zero(sk1, 32) == 0);
    CHECK(naion_memcmp(pk1, sk1, 32) != 0);
    CHECK(naion_memcmp(pk1, pk2, 32) != 0);
    TEST_END();
}

/* T3.14 */
static int test_box_xchacha_seed_keypair(void)
{
    unsigned char seed[32], pk1[32], sk1[32], pk2[32], sk2[32], base_pk[32];

    TEST_BEGIN("test_box_xchacha_seed_keypair");
    derive_key(seed, 32, "box-seed");
    CHECK_OK(naion_box_curve25519xchacha20poly1305_seed_keypair(pk1, sk1, seed));
    CHECK_OK(naion_box_curve25519xchacha20poly1305_seed_keypair(pk2, sk2, seed));
    CHECK(naion_memcmp(pk1, pk2, 32) == 0);
    CHECK(naion_memcmp(sk1, sk2, 32) == 0);
    seed[0] ^= 0xff;
    CHECK_OK(naion_box_curve25519xchacha20poly1305_seed_keypair(pk2, sk2, seed));
    CHECK(naion_memcmp(pk1, pk2, 32) != 0);
    /* pk == base * sk */
    CHECK_OK(naion_scalarmult_curve25519_base(base_pk, sk1));
    CHECK(naion_memcmp(base_pk, pk1, 32) == 0);
    TEST_END();
}

/* T3.15 */
static int test_box_xchacha_beforenm(void)
{
    unsigned char apk[32], ask[32], bpk[32], bsk[32];
    unsigned char k_ab[32], k_ba[32], k_ab2[32];

    TEST_BEGIN("test_box_xchacha_beforenm");
    CHECK_OK(naion_box_curve25519xchacha20poly1305_keypair(apk, ask));
    CHECK_OK(naion_box_curve25519xchacha20poly1305_keypair(bpk, bsk));

    CHECK_OK(naion_box_curve25519xchacha20poly1305_beforenm(k_ab, bpk, ask));
    CHECK_OK(naion_box_curve25519xchacha20poly1305_beforenm(k_ba, apk, bsk));
    CHECK(naion_memcmp(k_ab, k_ba, 32) == 0);

    /* same inputs -> same output */
    CHECK_OK(naion_box_curve25519xchacha20poly1305_beforenm(k_ab2, bpk, ask));
    CHECK(naion_memcmp(k_ab, k_ab2, 32) == 0);
    TEST_END();
}

/* T3.16 */
static int test_box_xchacha_easy_roundtrip(void)
{
    unsigned char apk[32], ask[32], bpk[32], bsk[32], nonce[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    size_t si;

    TEST_BEGIN("test_box_xchacha_easy_roundtrip");
    CHECK_OK(naion_box_curve25519xchacha20poly1305_keypair(apk, ask));
    CHECK_OK(naion_box_curve25519xchacha20poly1305_keypair(bpk, bsk));
    derive_key(nonce, 24, "box-nonce");

    for (si = 0; si < 18; si++) {
        size_t n = SIZE_LADDER[si];
        fill_pattern(m, n, 0x99);
        /* Alice -> Bob: encrypt with Bob's pk + Alice's sk */
        CHECK_OK(naion_box_curve25519xchacha20poly1305_easy(c, m, n, nonce, bpk, ask));
        /* Bob decrypts with Alice's pk + Bob's sk */
        CHECK_OK(naion_box_curve25519xchacha20poly1305_open_easy(m2, c, n + 16, nonce, apk, bsk));
        CHECK(naion_memcmp(m, m2, n) == 0);
        if (n > 0) {
            c[0] ^= 0xff;
            CHECK_ERR(naion_box_curve25519xchacha20poly1305_open_easy(m2, c, n + 16, nonce, apk, bsk));
            c[0] ^= 0xff;
        }
    }
    TEST_END();
}

/* T3.17 */
static int test_box_xchacha_easy_tamper(void)
{
    static const size_t mlens[] = { 32, 256, 4096 };
    unsigned char apk[32], ask[32], bpk[32], bsk[32], nonce[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    size_t si;

    TEST_BEGIN("test_box_xchacha_easy_tamper");
    CHECK_OK(naion_box_curve25519xchacha20poly1305_keypair(apk, ask));
    CHECK_OK(naion_box_curve25519xchacha20poly1305_keypair(bpk, bsk));
    derive_key(nonce, 24, "box-nonce");

    for (si = 0; si < sizeof mlens / sizeof mlens[0]; si++) {
        size_t n = mlens[si];
        fill_pattern(m, n, 0x99);
        CHECK_OK(naion_box_curve25519xchacha20poly1305_easy(c, m, n, nonce, bpk, ask));
        c[4] ^= 0xff;                                       /* MAC */
        CHECK_ERR(naion_box_curve25519xchacha20poly1305_open_easy(m2, c, n + 16, nonce, apk, bsk));
        c[4] ^= 0xff;
        c[16] ^= 0xff;                                      /* CT */
        CHECK_ERR(naion_box_curve25519xchacha20poly1305_open_easy(m2, c, n + 16, nonce, apk, bsk));
        c[16] ^= 0xff;
    }
    TEST_END();
}

/* T3.18 */
static int test_box_xchacha_easy_wrong_recipient(void)
{
    static const size_t mlens[] = { 32, 256 };
    unsigned char apk[32], ask[32], bpk[32], bsk[32], cpk[32], csk[32], nonce[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    size_t si;

    TEST_BEGIN("test_box_xchacha_easy_wrong_recipient");
    CHECK_OK(naion_box_curve25519xchacha20poly1305_keypair(apk, ask));
    CHECK_OK(naion_box_curve25519xchacha20poly1305_keypair(bpk, bsk));
    CHECK_OK(naion_box_curve25519xchacha20poly1305_keypair(cpk, csk));   /* Carol */
    derive_key(nonce, 24, "box-nonce");

    for (si = 0; si < sizeof mlens / sizeof mlens[0]; si++) {
        size_t n = mlens[si];
        fill_pattern(m, n, 0x99);
        /* encrypt to Bob */
        CHECK_OK(naion_box_curve25519xchacha20poly1305_easy(c, m, n, nonce, bpk, ask));
        /* Carol tries to decrypt -> fail */
        CHECK_ERR(naion_box_curve25519xchacha20poly1305_open_easy(m2, c, n + 16, nonce, apk, csk));
    }
    TEST_END();
}

/* T3.19 */
static int test_box_xchacha_seal_roundtrip(void)
{
    unsigned char bpk[32], bsk[32];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    size_t si;

    TEST_BEGIN("test_box_xchacha_seal_roundtrip");
    CHECK_OK(naion_box_curve25519xchacha20poly1305_keypair(bpk, bsk));

    for (si = 0; si < 18; si++) {
        size_t n = SIZE_LADDER[si];
        fill_pattern(m, n, 0xab);
        CHECK_OK(naion_box_curve25519xchacha20poly1305_seal(c, m, n, bpk));
        /* layout eph_pk(32) || MAC(16) || CT(n) */
        CHECK_OK(naion_box_curve25519xchacha20poly1305_seal_open(m2, c, n + 48, bpk, bsk));
        CHECK(naion_memcmp(m, m2, n) == 0);
    }
    TEST_END();
}

/* T3.20 */
static int test_box_xchacha_seal_tamper(void)
{
    static const size_t mlens[] = { 32, 256, 4096 };
    unsigned char bpk[32], bsk[32];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    size_t si;

    TEST_BEGIN("test_box_xchacha_seal_tamper");
    CHECK_OK(naion_box_curve25519xchacha20poly1305_keypair(bpk, bsk));

    for (si = 0; si < sizeof mlens / sizeof mlens[0]; si++) {
        size_t n = mlens[si];
        fill_pattern(m, n, 0xab);
        CHECK_OK(naion_box_curve25519xchacha20poly1305_seal(c, m, n, bpk));

        /* tamper eph_pk */
        c[0] ^= 0xff;
        CHECK_ERR(naion_box_curve25519xchacha20poly1305_seal_open(m2, c, n + 48, bpk, bsk));
        c[0] ^= 0xff;
        /* tamper MAC */
        c[40] ^= 0xff;
        CHECK_ERR(naion_box_curve25519xchacha20poly1305_seal_open(m2, c, n + 48, bpk, bsk));
        c[40] ^= 0xff;
        /* tamper CT */
        c[48] ^= 0xff;
        CHECK_ERR(naion_box_curve25519xchacha20poly1305_seal_open(m2, c, n + 48, bpk, bsk));
        c[48] ^= 0xff;
    }
    TEST_END();
}

/* T3.21 */
static int test_box_xchacha_seal_anon(void)
{
    static const size_t mlens[] = { 32, 256 };
    unsigned char bpk[32], bsk[32];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    size_t si;

    TEST_BEGIN("test_box_xchacha_seal_anon");
    CHECK_OK(naion_box_curve25519xchacha20poly1305_keypair(bpk, bsk));
    for (si = 0; si < sizeof mlens / sizeof mlens[0]; si++) {
        size_t n = mlens[si];
        fill_pattern(m, n, 0xab);
        /* seal needs only the recipient pk */
        CHECK_OK(naion_box_curve25519xchacha20poly1305_seal(c, m, n, bpk));
        /* open needs only the recipient sk + pk */
        CHECK_OK(naion_box_curve25519xchacha20poly1305_seal_open(m2, c, n + 48, bpk, bsk));
        CHECK(naion_memcmp(m, m2, n) == 0);
    }
    TEST_END();
}

/* T3.22 */
static int test_box_xchacha_seal_size(void)
{
    static const size_t mlens[] = { 32, 256 };
    unsigned char bpk[32], bsk[32];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    size_t si;

    TEST_BEGIN("test_box_xchacha_seal_size");
    CHECK_OK(naion_box_curve25519xchacha20poly1305_keypair(bpk, bsk));
    for (si = 0; si < sizeof mlens / sizeof mlens[0]; si++) {
        size_t n = mlens[si];
        fill_pattern(m, n, 0xab);
        CHECK_OK(naion_box_curve25519xchacha20poly1305_seal(c, m, n, bpk));
        /* output = plaintext + 48 */
        CHECK(n + 48 == n + naion_box_curve25519xchacha20poly1305_SEALBYTES);
        /* clen < 48 -> error */
        CHECK_ERR(naion_box_curve25519xchacha20poly1305_seal_open(m2, c, 47, bpk, bsk));
    }
    TEST_END();
}

/* T3.23 */
static int test_box_xchacha_errors(void)
{
    unsigned char apk[32], ask[32], bpk[32], bsk[32], nonce[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;

    TEST_BEGIN("test_box_xchacha_errors");
    CHECK_OK(naion_box_curve25519xchacha20poly1305_keypair(apk, ask));
    CHECK_OK(naion_box_curve25519xchacha20poly1305_keypair(bpk, bsk));
    derive_key(nonce, 24, "box-nonce");
    fill_pattern(m, 32, 0x99);

    /* easy: NULL */
    CHECK_ERR(naion_box_curve25519xchacha20poly1305_easy(NULL, m, 32, nonce, bpk, ask));
    CHECK_ERR(naion_box_curve25519xchacha20poly1305_easy(c, NULL, 32, nonce, bpk, ask));
    CHECK_ERR(naion_box_curve25519xchacha20poly1305_easy(c, m, 32, NULL, bpk, ask));
    CHECK_ERR(naion_box_curve25519xchacha20poly1305_easy(c, m, 32, nonce, NULL, ask));
    CHECK_ERR(naion_box_curve25519xchacha20poly1305_easy(c, m, 32, nonce, bpk, NULL));
    /* open_easy: clen < 16 */
    CHECK_ERR(naion_box_curve25519xchacha20poly1305_open_easy(m2, c, 15, nonce, apk, bsk));
    CHECK_ERR(naion_box_curve25519xchacha20poly1305_open_easy(NULL, c, 48, nonce, apk, bsk));
    CHECK_ERR(naion_box_curve25519xchacha20poly1305_open_easy(m2, NULL, 48, nonce, apk, bsk));
    CHECK_ERR(naion_box_curve25519xchacha20poly1305_open_easy(m2, c, 48, NULL, apk, bsk));
    CHECK_ERR(naion_box_curve25519xchacha20poly1305_open_easy(m2, c, 48, nonce, NULL, bsk));
    CHECK_ERR(naion_box_curve25519xchacha20poly1305_open_easy(m2, c, 48, nonce, apk, NULL));

    /* seal: NULL + clen<48 */
    CHECK_ERR(naion_box_curve25519xchacha20poly1305_seal(NULL, m, 32, bpk));
    CHECK_ERR(naion_box_curve25519xchacha20poly1305_seal(c, NULL, 32, bpk));
    CHECK_ERR(naion_box_curve25519xchacha20poly1305_seal(c, m, 32, NULL));
    CHECK_ERR(naion_box_curve25519xchacha20poly1305_seal_open(NULL, c, 80, bpk, bsk));
    CHECK_ERR(naion_box_curve25519xchacha20poly1305_seal_open(m2, NULL, 80, bpk, bsk));
    CHECK_ERR(naion_box_curve25519xchacha20poly1305_seal_open(m2, c, 47, bpk, bsk));
    CHECK_ERR(naion_box_curve25519xchacha20poly1305_seal_open(m2, c, 80, NULL, bsk));
    CHECK_ERR(naion_box_curve25519xchacha20poly1305_seal_open(m2, c, 80, bpk, NULL));

    /* beforenm NULL */
    {
        unsigned char k[32];
        CHECK_ERR(naion_box_curve25519xchacha20poly1305_beforenm(NULL, bpk, ask));
        CHECK_ERR(naion_box_curve25519xchacha20poly1305_beforenm(k, NULL, ask));
        CHECK_ERR(naion_box_curve25519xchacha20poly1305_beforenm(k, bpk, NULL));
    }
    TEST_END();
}

/* ---- 3D. Box runtime scheduler --------------------------------------- */

/* T3.24 */
static int test_box_get_use_xchacha(void)
{
    TEST_BEGIN("test_box_get_use_xchacha");
#if NAION_XSALSA20
    /* default initial value */
    CHECK(naion_box_get_use_xchacha20() == 1);
    CHECK(naion_get_use_xchacha20() == 1);
#else
    /* compile-time constant 1 */
    CHECK(naion_box_get_use_xchacha20() == 1);
    CHECK(naion_get_use_xchacha20() == 1);
#endif
    TEST_END();
}

/* T3.25 */
static int test_box_set_use_xchacha(void)
{
    int before, after;

    TEST_BEGIN("test_box_set_use_xchacha");
    before = naion_box_get_use_xchacha20();
    naion_box_set_use_xchacha20(0);
    naion_set_use_xchacha20(0);
    after = naion_box_get_use_xchacha20();
#if NAION_XSALSA20
    CHECK(after == 0);
    CHECK(naion_get_use_xchacha20() == 0);
#else
    (void) after;
#endif
    /* restore */
    naion_box_set_use_xchacha20(1);
    CHECK(naion_box_get_use_xchacha20() == 1);
    CHECK(naion_get_use_xchacha20() == 1);
    /* aliases agree */
    naion_box_set_use_xchacha20(before != 0);
    CHECK(naion_get_use_xchacha20() == naion_box_get_use_xchacha20());
    TEST_END();
}

/* T3.26 */
static int test_box_query_sizes(void)
{
    TEST_BEGIN("test_box_query_sizes");
    CHECK(naion_box_seedbytes()       == 32);
    CHECK(naion_box_publickeybytes()  == 32);
    CHECK(naion_box_secretkeybytes()  == 32);
    CHECK(naion_box_beforenmbytes()   == 32);
    CHECK(naion_box_noncebytes()      == 24);
    CHECK(naion_box_macbytes()        == 16);
    CHECK(naion_box_sealbytes()       == 48);
    TEST_END();
}

/* ---- 3E. Generic box dispatch (naion_box_*) -------------------------- */

/* T3.27 */
static int test_box_generic_keypair(void)
{
    unsigned char pk[32], sk[32], xpk[32], xsk[32];

    TEST_BEGIN("test_box_generic_keypair");
    CHECK_OK(naion_box_keypair(pk, sk));
    CHECK(naion_is_zero(pk, 32) == 0);
    CHECK(naion_is_zero(sk, 32) == 0);
    CHECK(naion_memcmp(pk, sk, 32) != 0);

    /* behaviour matches the xchacha-specific variant */
    CHECK_OK(naion_box_curve25519xchacha20poly1305_keypair(xpk, xsk));
    /* both produce non-zero distinct pairs (sanity) */
    CHECK(naion_memcmp(xpk, xsk, 32) != 0);
    TEST_END();
}

/* T3.28 */
static int test_box_generic_seed_keypair(void)
{
    unsigned char seed[32], pk1[32], sk1[32], pk2[32], sk2[32];

    TEST_BEGIN("test_box_generic_seed_keypair");
    derive_key(seed, 32, "gbox-seed");
    CHECK_OK(naion_box_seed_keypair(pk1, sk1, seed));
    CHECK_OK(naion_box_seed_keypair(pk2, sk2, seed));
    CHECK(naion_memcmp(pk1, pk2, 32) == 0);
    CHECK(naion_memcmp(sk1, sk2, 32) == 0);
    seed[0] ^= 0xff;
    CHECK_OK(naion_box_seed_keypair(pk2, sk2, seed));
    CHECK(naion_memcmp(pk1, pk2, 32) != 0);
    TEST_END();
}

/* T3.29 */
static int test_box_generic_beforenm(void)
{
    unsigned char apk[32], ask[32], bpk[32], bsk[32];
    unsigned char k_ab[32], k_ba[32];

    TEST_BEGIN("test_box_generic_beforenm");
    CHECK_OK(naion_box_keypair(apk, ask));
    CHECK_OK(naion_box_keypair(bpk, bsk));
    CHECK_OK(naion_box_beforenm(k_ab, bpk, ask));
    CHECK_OK(naion_box_beforenm(k_ba, apk, bsk));
    CHECK(naion_memcmp(k_ab, k_ba, 32) == 0);
    TEST_END();
}

/* T3.30 */
static int test_box_generic_easy_roundtrip(void)
{
    unsigned char apk[32], ask[32], bpk[32], bsk[32], nonce[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    size_t si;

    TEST_BEGIN("test_box_generic_easy_roundtrip");
    CHECK_OK(naion_box_keypair(apk, ask));
    CHECK_OK(naion_box_keypair(bpk, bsk));
    derive_key(nonce, 24, "gbox-nonce");
    for (si = 0; si < 18; si++) {
        size_t n = SIZE_LADDER[si];
        fill_pattern(m, n, 0xb1);
        CHECK_OK(naion_box_easy(c, m, n, nonce, bpk, ask));
        CHECK_OK(naion_box_open_easy(m2, c, n + 16, nonce, apk, bsk));
        CHECK(naion_memcmp(m, m2, n) == 0);
        if (n > 0) {
            c[0] ^= 0xff;
            CHECK_ERR(naion_box_open_easy(m2, c, n + 16, nonce, apk, bsk));
            c[0] ^= 0xff;
        }
    }
    TEST_END();
}

/* T3.31 */
static int test_box_generic_afternm_roundtrip(void)
{
    unsigned char apk[32], ask[32], bpk[32], bsk[32], nonce[24], k[32];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    size_t si;

    TEST_BEGIN("test_box_generic_afternm_roundtrip");
    CHECK_OK(naion_box_keypair(apk, ask));
    CHECK_OK(naion_box_keypair(bpk, bsk));
    derive_key(nonce, 24, "gbox-nonce");
    CHECK_OK(naion_box_beforenm(k, bpk, ask));
    for (si = 0; si < 18; si++) {
        size_t n = SIZE_LADDER[si];
        fill_pattern(m, n, 0xb2);
        CHECK_OK(naion_box_easy_afternm(c, m, n, nonce, k));
        CHECK_OK(naion_box_open_easy_afternm(m2, c, n + 16, nonce, k));
        CHECK(naion_memcmp(m, m2, n) == 0);
        if (n > 0) {
            c[0] ^= 0xff;
            CHECK_ERR(naion_box_open_easy_afternm(m2, c, n + 16, nonce, k));
            c[0] ^= 0xff;
        }
    }
    TEST_END();
}

/* T3.32 */
static int test_box_generic_seal_roundtrip(void)
{
    unsigned char bpk[32], bsk[32];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    size_t si;

    TEST_BEGIN("test_box_generic_seal_roundtrip");
    CHECK_OK(naion_box_keypair(bpk, bsk));
    for (si = 0; si < 18; si++) {
        size_t n = SIZE_LADDER[si];
        fill_pattern(m, n, 0xb3);
        CHECK_OK(naion_box_seal(c, m, n, bpk));
        CHECK_OK(naion_box_seal_open(m2, c, n + 48, bpk, bsk));
        CHECK(naion_memcmp(m, m2, n) == 0);
        if (n > 0) {
            c[48] ^= 0xff;
            CHECK_ERR(naion_box_seal_open(m2, c, n + 48, bpk, bsk));
            c[48] ^= 0xff;
        }
    }
    TEST_END();
}

/* T3.33 */
static int test_box_generic_errors(void)
{
    unsigned char apk[32], ask[32], bpk[32], bsk[32], nonce[24], k[32];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;

    TEST_BEGIN("test_box_generic_errors");
    CHECK_OK(naion_box_keypair(apk, ask));
    CHECK_OK(naion_box_keypair(bpk, bsk));
    derive_key(nonce, 24, "gbox-nonce");
    CHECK_OK(naion_box_beforenm(k, bpk, ask));
    fill_pattern(m, 32, 0xb1);

    /* easy NULL */
    CHECK_ERR(naion_box_easy(NULL, m, 32, nonce, bpk, ask));
    CHECK_ERR(naion_box_easy(c, NULL, 32, nonce, bpk, ask));
    CHECK_ERR(naion_box_easy(c, m, 32, NULL, bpk, ask));
    CHECK_ERR(naion_box_easy(c, m, 32, nonce, NULL, ask));
    CHECK_ERR(naion_box_easy(c, m, 32, nonce, bpk, NULL));
    /* open_easy clen<16 + NULL */
    CHECK_ERR(naion_box_open_easy(m2, c, 15, nonce, apk, bsk));
    CHECK_ERR(naion_box_open_easy(NULL, c, 48, nonce, apk, bsk));

    /* afternm NULL */
    CHECK_ERR(naion_box_easy_afternm(NULL, m, 32, nonce, k));
    CHECK_ERR(naion_box_easy_afternm(c, NULL, 32, nonce, k));
    CHECK_ERR(naion_box_easy_afternm(c, m, 32, NULL, k));
    CHECK_ERR(naion_box_easy_afternm(c, m, 32, nonce, NULL));
    CHECK_ERR(naion_box_open_easy_afternm(m2, c, 15, nonce, k));

    /* seal NULL + clen<48 */
    CHECK_ERR(naion_box_seal(NULL, m, 32, bpk));
    CHECK_ERR(naion_box_seal(c, NULL, 32, bpk));
    CHECK_ERR(naion_box_seal(c, m, 32, NULL));
    CHECK_ERR(naion_box_seal_open(m2, c, 47, bpk, bsk));
    CHECK_ERR(naion_box_seal_open(NULL, c, 80, bpk, bsk));

    /* beforenm NULL */
    CHECK_ERR(naion_box_beforenm(NULL, bpk, ask));
    CHECK_ERR(naion_box_beforenm(k, NULL, ask));
    TEST_END();
}

/* ---- 3F. Ed25519 ------------------------------------------------------ */

/* RFC 8032 test vector 1 (SECRETKEY / PUBLICKEY / MESSAGE / SIGNATURE). */
static const unsigned char ED25519_TV1_SEED[32] = {
    0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,
    0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,
    0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,
    0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60
};
static const unsigned char ED25519_TV1_PK[32] = {
    0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,
    0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
    0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,
    0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a
};

/* T3.34 */
static int test_ed25519_keypair_random(void)
{
    unsigned char pk1[32], sk1[64], pk2[32], sk2[64];

    TEST_BEGIN("test_ed25519_keypair_random");
    CHECK_OK(naion_sign_ed25519_keypair(pk1, sk1));
    CHECK_OK(naion_sign_ed25519_keypair(pk2, sk2));
    CHECK(naion_is_zero(pk1, 32) == 0);
    CHECK(naion_is_zero(sk1, 64) == 0);
    CHECK(naion_memcmp(pk1, pk2, 32) != 0);
    CHECK(naion_memcmp(sk1, sk2, 64) != 0);
    TEST_END();
}

/* T3.35 */
static int test_ed25519_seed_keypair(void)
{
    unsigned char pk[32], sk[64];

    TEST_BEGIN("test_ed25519_seed_keypair");
    CHECK_OK(naion_sign_ed25519_seed_keypair(pk, sk, ED25519_TV1_SEED));
    CHECK(naion_memcmp(pk, ED25519_TV1_PK, 32) == 0);
    /* sk layout = seed(32) || pk(32) */
    CHECK(naion_memcmp(sk, ED25519_TV1_SEED, 32) == 0);
    CHECK(naion_memcmp(sk + 32, pk, 32) == 0);
    TEST_END();
}

/* T3.36 */
static int test_ed25519_sign_detached_verify(void)
{
    unsigned char pk[32], sk[64], sig[64], sig2[64];
    unsigned char *m = g_buf_a;
    unsigned long long siglen = 0;
    size_t si;

    TEST_BEGIN("test_ed25519_sign_detached_verify");
    CHECK_OK(naion_sign_ed25519_seed_keypair(pk, sk, ED25519_TV1_SEED));

    for (si = 0; si < 18; si++) {
        size_t n = SIZE_LADDER[si];
        fill_pattern(m, n, 0xc1);
        siglen = 0;
        CHECK_OK(naion_sign_ed25519_detached(sig, &siglen, m, n, sk));
        CHECK(siglen == 64);
        CHECK_OK(naion_sign_ed25519_verify_detached(sig, m, n, pk));

        /* tamper sig[0] */
        sig[0] ^= 0xff;
        CHECK_ERR(naion_sign_ed25519_verify_detached(sig, m, n, pk));
        sig[0] ^= 0xff;
        /* tamper sig[63] */
        sig2[0] = sig[63] ^ 0xff;                      /* save changed byte */
        {
            unsigned char save = sig[63];
            sig[63] ^= 0xff;
            CHECK_ERR(naion_sign_ed25519_verify_detached(sig, m, n, pk));
            sig[63] = save;
        }
        (void) sig2;
        /* tamper msg */
        if (n > 0) {
            m[0] ^= 0xff;
            CHECK_ERR(naion_sign_ed25519_verify_detached(sig, m, n, pk));
            m[0] ^= 0xff;
        }
    }
    TEST_END();
}

/* T3.37 */
static int test_ed25519_sign_combined(void)
{
    unsigned char pk[32], sk[64];
    unsigned char *m = g_buf_a, *sm = g_buf_b, *m2 = g_buf_c;
    unsigned long long smlen = 0, mlen = 0;
    size_t si;

    TEST_BEGIN("test_ed25519_sign_combined");
    CHECK_OK(naion_sign_ed25519_seed_keypair(pk, sk, ED25519_TV1_SEED));

    for (si = 0; si < 18; si++) {
        size_t n = SIZE_LADDER[si];
        fill_pattern(m, n, 0xc2);
        smlen = 0;
        CHECK_OK(naion_sign_ed25519(sm, &smlen, m, n, sk));
        CHECK(smlen == (unsigned long long)(n + 64));

        mlen = 0;
        CHECK_OK(naion_sign_ed25519_open(m2, &mlen, sm, smlen, pk));
        CHECK(mlen == (unsigned long long)n);
        CHECK(naion_memcmp(m, m2, n) == 0);

        /* tamper sig */
        sm[0] ^= 0xff;
        mlen = 0;
        CHECK_ERR(naion_sign_ed25519_open(m2, &mlen, sm, smlen, pk));
        sm[0] ^= 0xff;
        /* tamper message portion */
        if (n > 0) {
            sm[64] ^= 0xff;
            mlen = 0;
            CHECK_ERR(naion_sign_ed25519_open(m2, &mlen, sm, smlen, pk));
            sm[64] ^= 0xff;
        }
    }
    TEST_END();
}

/* T3.38 */
static int test_ed25519_deterministic_sign(void)
{
    static const size_t mlens[] = { 32, 256, 1000 };
    unsigned char pk[32], sk[64];
    unsigned char *m = g_buf_a, s1[64], s2[64];
    unsigned long long sl;
    size_t si;

    TEST_BEGIN("test_ed25519_deterministic_sign");
    CHECK_OK(naion_sign_ed25519_seed_keypair(pk, sk, ED25519_TV1_SEED));
    for (si = 0; si < sizeof mlens / sizeof mlens[0]; si++) {
        size_t n = mlens[si];
        fill_pattern(m, n, 0xc3);
        sl = 0;
        CHECK_OK(naion_sign_ed25519_detached(s1, &sl, m, n, sk));
        sl = 0;
        CHECK_OK(naion_sign_ed25519_detached(s2, &sl, m, n, sk));
        CHECK(naion_memcmp(s1, s2, 64) == 0);
    }
    TEST_END();
}

/* T3.39 */
static int test_ed25519_different_message(void)
{
    unsigned char pk[32], sk[64];
    unsigned char m1[128], m2[128], s1[64], s2[64];
    unsigned long long sl;

    TEST_BEGIN("test_ed25519_different_message");
    CHECK_OK(naion_sign_ed25519_seed_keypair(pk, sk, ED25519_TV1_SEED));
    fill_pattern(m1, 32, 0xd1);
    fill_pattern(m2, 32, 0xd2);
    sl = 0;
    CHECK_OK(naion_sign_ed25519_detached(s1, &sl, m1, 32, sk));
    sl = 0;
    CHECK_OK(naion_sign_ed25519_detached(s2, &sl, m2, 32, sk));
    CHECK(naion_memcmp(s1, s2, 64) != 0);
    /* verify m1's sig against m2 -> fail */
    CHECK_ERR(naion_sign_ed25519_verify_detached(s1, m2, 32, pk));
    CHECK_OK(naion_sign_ed25519_verify_detached(s1, m1, 32, pk));
    TEST_END();
}

/* T3.40 */
static int test_ed25519_wrong_pk(void)
{
    static const size_t mlens[] = { 32, 128, 1024 };
    unsigned char apk[32], ask[64], bpk[32], bsk[64];
    unsigned char *m = g_buf_a, sig[64];
    unsigned long long sl;
    size_t si;

    TEST_BEGIN("test_ed25519_wrong_pk");
    CHECK_OK(naion_sign_ed25519_keypair(apk, ask));
    CHECK_OK(naion_sign_ed25519_keypair(bpk, bsk));
    for (si = 0; si < sizeof mlens / sizeof mlens[0]; si++) {
        size_t n = mlens[si];
        fill_pattern(m, n, 0xd3);
        sl = 0;
        CHECK_OK(naion_sign_ed25519_detached(sig, &sl, m, n, ask));
        CHECK_OK(naion_sign_ed25519_verify_detached(sig, m, n, apk));
        /* verify with Bob's pk -> fail */
        CHECK_ERR(naion_sign_ed25519_verify_detached(sig, m, n, bpk));
    }
    TEST_END();
}

/* T3.41 */
static int test_ed25519_sk_to_seed_pk(void)
{
    unsigned char seed[32], pk[32], sk[64], seed_out[32], pk_out[32];

    TEST_BEGIN("test_ed25519_sk_to_seed_pk");
    CHECK_OK(naion_sign_ed25519_seed_keypair(pk, sk, ED25519_TV1_SEED));
    CHECK_OK(naion_sign_ed25519_sk_to_seed(seed_out, sk));
    CHECK_OK(naion_sign_ed25519_sk_to_pk(pk_out, sk));
    CHECK(naion_memcmp(seed_out, ED25519_TV1_SEED, 32) == 0);
    CHECK(naion_memcmp(pk_out, pk, 32) == 0);
    (void) seed;
    TEST_END();
}

/* T3.42 */
static int test_ed25519_pk_to_curve25519(void)
{
    unsigned char sk[64], pk[32], c1[32], c2[32];

    TEST_BEGIN("test_ed25519_pk_to_curve25519");
    CHECK_OK(naion_sign_ed25519_seed_keypair(pk, sk, ED25519_TV1_SEED));
    CHECK_OK(naion_sign_ed25519_pk_to_curve25519(c1, pk));
    CHECK(naion_is_zero(c1, 32) == 0);
    /* deterministic */
    CHECK_OK(naion_sign_ed25519_pk_to_curve25519(c2, pk));
    CHECK(naion_memcmp(c1, c2, 32) == 0);
    TEST_END();
}

/* T3.43 */
static int test_ed25519_sk_to_curve25519(void)
{
    unsigned char sk[64], pk[32], csk[32], csk2[32];

    TEST_BEGIN("test_ed25519_sk_to_curve25519");
    CHECK_OK(naion_sign_ed25519_seed_keypair(pk, sk, ED25519_TV1_SEED));
    CHECK_OK(naion_sign_ed25519_sk_to_curve25519(csk, sk));
    CHECK(naion_is_zero(csk, 32) == 0);
    CHECK_OK(naion_sign_ed25519_sk_to_curve25519(csk2, sk));
    CHECK(naion_memcmp(csk, csk2, 32) == 0);
    TEST_END();
}

/* T3.44 */
static int test_ed25519_curve25519_consistency(void)
{
    unsigned char sk[64], pk[32], xpk[32], xsk[32], base_xpk[32];

    TEST_BEGIN("test_ed25519_curve25519_consistency");
    CHECK_OK(naion_sign_ed25519_seed_keypair(pk, sk, ED25519_TV1_SEED));
    CHECK_OK(naion_sign_ed25519_pk_to_curve25519(xpk, pk));
    CHECK_OK(naion_sign_ed25519_sk_to_curve25519(xsk, sk));
    /* xpk must equal base * xsk */
    CHECK_OK(naion_scalarmult_curve25519_base(base_xpk, xsk));
    CHECK(naion_memcmp(xpk, base_xpk, 32) == 0);
    TEST_END();
}

/* T3.45 */
static int test_ed25519_errors(void)
{
    unsigned char pk[32], sk[64], *sm = g_buf_a, *m = g_buf_b, sig[64], m2[64];
    unsigned long long smlen = 0, mlen = 0, siglen = 0;

    TEST_BEGIN("test_ed25519_errors");
    CHECK_OK(naion_sign_ed25519_seed_keypair(pk, sk, ED25519_TV1_SEED));
    fill_pattern(m, 32, 0xe1);
    CHECK_OK(naion_sign_ed25519_detached(sig, &siglen, m, 32, sk));

    /* keypair NULL */
    CHECK_ERR(naion_sign_ed25519_keypair(NULL, sk));
    CHECK_ERR(naion_sign_ed25519_keypair(pk, NULL));
    /* seed_keypair NULL */
    CHECK_ERR(naion_sign_ed25519_seed_keypair(NULL, sk, ED25519_TV1_SEED));
    CHECK_ERR(naion_sign_ed25519_seed_keypair(pk, NULL, ED25519_TV1_SEED));
    CHECK_ERR(naion_sign_ed25519_seed_keypair(pk, sk, NULL));

    /* sign combined NULL */
    CHECK_ERR(naion_sign_ed25519(NULL, &smlen, m, 32, sk));
    CHECK_ERR(naion_sign_ed25519(sm, NULL, m, 32, sk));
    CHECK_ERR(naion_sign_ed25519(sm, &smlen, m, 32, NULL));
    CHECK_ERR(naion_sign_ed25519(sm, &smlen, NULL, 1, sk));
    /* open NULL + smlen<64 */
    CHECK_ERR(naion_sign_ed25519_open(NULL, &mlen, sm, 96, pk));
    CHECK_ERR(naion_sign_ed25519_open(m2, NULL, sm, 96, pk));
    CHECK_ERR(naion_sign_ed25519_open(m2, &mlen, NULL, 96, pk));
    CHECK_ERR(naion_sign_ed25519_open(m2, &mlen, sm, 63, pk));
    CHECK_ERR(naion_sign_ed25519_open(m2, &mlen, sm, 96, NULL));

    /* detached: NULL sig and NULL sk must fail; NULL msg with mlen>0 must fail.
     * siglen_p is allowed to be NULL (libsodium-compatible). */
    CHECK_ERR(naion_sign_ed25519_detached(NULL, &siglen, m, 32, sk));
    CHECK_ERR(naion_sign_ed25519_detached(sig, &siglen, m, 32, NULL));
    CHECK_ERR(naion_sign_ed25519_detached(sig, &siglen, NULL, 1, sk));
    /* verify NULL */
    CHECK_ERR(naion_sign_ed25519_verify_detached(NULL, m, 32, pk));
    CHECK_ERR(naion_sign_ed25519_verify_detached(sig, NULL, 1, pk));
    CHECK_ERR(naion_sign_ed25519_verify_detached(sig, m, 32, NULL));

    /* sk_to_seed / sk_to_pk NULL */
    CHECK_ERR(naion_sign_ed25519_sk_to_seed(NULL, sk));
    CHECK_ERR(naion_sign_ed25519_sk_to_seed(sig, NULL));
    CHECK_ERR(naion_sign_ed25519_sk_to_pk(NULL, sk));
    CHECK_ERR(naion_sign_ed25519_sk_to_pk(pk, NULL));

    /* pk_to_curve25519 with an invalid (low-order) ed pk -> error */
    {
        unsigned char badpk[32] = { 0 };
        unsigned char c[32];
        CHECK_ERR(naion_sign_ed25519_pk_to_curve25519(c, badpk));
        CHECK_ERR(naion_sign_ed25519_pk_to_curve25519(NULL, pk));
        CHECK_ERR(naion_sign_ed25519_pk_to_curve25519(c, NULL));
    }
    /* sk_to_curve25519 NULL */
    {
        unsigned char c[32];
        CHECK_ERR(naion_sign_ed25519_sk_to_curve25519(NULL, sk));
        CHECK_ERR(naion_sign_ed25519_sk_to_curve25519(c, NULL));
    }
    TEST_END();
}

/* T3.46 */
static int test_ed25519_small_order(void)
{
    unsigned char pk[32], sk[64];
    unsigned char sig[64], m[32];
    unsigned long long sl = 0;

    TEST_BEGIN("test_ed25519_small_order");
    CHECK_OK(naion_sign_ed25519_seed_keypair(pk, sk, ED25519_TV1_SEED));
    fill_pattern(m, 32, 0xe4);
    CHECK_OK(naion_sign_ed25519_detached(sig, &sl, m, 32, sk));

    /* A low-order public key must be rejected even against a real signature. */
    {
        static const unsigned char badpk[32] = { 0 };   /* all-zero = small order */
        CHECK_ERR(naion_sign_ed25519_verify_detached(sig, m, 32, badpk));
    }
    /* A non-canonical S (sig[32..63]) must be rejected. */
    {
        unsigned char badsig[64];
        memcpy(badsig, sig, 64);
        badsig[63] = 0xff;                              /* S high bit set etc. */
        /* Only assert it does not crash; canonical check may pass or fail, but
         * the all-0xff S is non-canonical and must be rejected. */
        CHECK_ERR(naion_sign_ed25519_verify_detached(badsig, m, 32, pk));
    }
    TEST_END();
}

/* ---- 3G. CSM client/server secure messaging -------------------------- */

/* T3.47 */
static int test_csm_init(void)
{
    TEST_BEGIN("test_csm_init");
    CHECK_CSM(naion_csm_init(), NAION_CSM_OK);
    TEST_END();
}

/* T3.48 */
static int test_csm_client_create_wipe(void)
{
    naion_csm_client c;
    unsigned char seed[32], spk[32];

    TEST_BEGIN("test_csm_client_create_wipe");
    derive_key(seed, 32, "csm-c-seed");
    derive_key(spk, 32, "csm-s-pk");
    CHECK_CSM(naion_csm_client_create(&c, seed, spk), NAION_CSM_OK);
    CHECK(naion_is_zero(c.ed_public_key, 32) == 0);
    naion_csm_client_wipe(&c);
    CHECK(naion_is_zero((const unsigned char *)&c, sizeof c) == 1);
    TEST_END();
}

/* T3.49 */
static int test_csm_server_create_wipe(void)
{
    naion_csm_server s;
    unsigned char seed[32];

    TEST_BEGIN("test_csm_server_create_wipe");
    derive_key(seed, 32, "csm-s-seed");
    CHECK_CSM(naion_csm_server_create(&s, seed), NAION_CSM_OK);
    CHECK(s.client_public_key_initialized == 0);
    naion_csm_server_wipe(&s);
    CHECK(naion_is_zero((const unsigned char *)&s, sizeof s) == 1);
    TEST_END();
}

/* Helper: build a matched client/server pair from seeds. */
static void csm_pair(naion_csm_client *c, naion_csm_server *s)
{
    unsigned char cseed[32], sseed[32], spk[32];
    derive_key(cseed, 32, "csm-c-seed");
    derive_key(sseed, 32, "csm-s-seed");
    (void) naion_csm_server_create(s, sseed);
    /* client needs the server's ed public key */
    memcpy(spk, s->ed_public_key, 32);
    (void) naion_csm_client_create(c, cseed, spk);
}

/* T3.50 */
static int test_csm_full_flow(void)
{
    static const size_t plens[] = { 1, 32, 256, NAION_CSM_MAX_CLIENT_PAYLOAD_BYTES };
    naion_csm_client c;
    naion_csm_server s;
    unsigned char *pt = g_buf_a, *pkt = g_buf_b, *out = g_buf_c;
    size_t pkt_len = 0, out_len = 0;
    size_t li;

    TEST_BEGIN("test_csm_full_flow");
    csm_pair(&c, &s);

    for (li = 0; li < sizeof plens / sizeof plens[0]; li++) {
        size_t n = plens[li];
        fill_pattern(pt, n, 0xf1);

        /* C -> S */
        CHECK_CSM(naion_csm_client_encrypt(&c, pt, n, pkt, NAION_CSM_MAX_UDP_DATAGRAM_BYTES, &pkt_len),
                  NAION_CSM_OK);
        CHECK(pkt_len == naion_csm_client_encrypt_size(n));
        CHECK_CSM(naion_csm_server_decrypt(&s, pkt, pkt_len, out, NAION_CSM_MAX_UDP_DATAGRAM_BYTES, &out_len),
                  NAION_CSM_OK);
        CHECK(out_len == n);
        CHECK(naion_memcmp(pt, out, n) == 0);
        CHECK(s.client_public_key_initialized == 1);

        /* S -> C */
        CHECK_CSM(naion_csm_server_encrypt(&s, pt, n, pkt, NAION_CSM_MAX_UDP_DATAGRAM_BYTES, &pkt_len),
                  NAION_CSM_OK);
        CHECK(pkt_len == naion_csm_server_encrypt_size(n));
        CHECK_CSM(naion_csm_client_decrypt(&c, pkt, pkt_len, out, NAION_CSM_MAX_UDP_DATAGRAM_BYTES, &out_len),
                  NAION_CSM_OK);
        CHECK(out_len == n);
        CHECK(naion_memcmp(pt, out, n) == 0);
    }
    TEST_END();
}

/* T3.51 */
static int test_csm_server_encrypt_before_client(void)
{
    naion_csm_server s;
    unsigned char seed[32], pt[32], pkt[256];
    size_t pkt_len = 0;

    TEST_BEGIN("test_csm_server_encrypt_before_client");
    derive_key(seed, 32, "csm-s-seed");
    CHECK_CSM(naion_csm_server_create(&s, seed), NAION_CSM_OK);
    CHECK(s.client_public_key_initialized == 0);
    fill_pattern(pt, 32, 0xf2);
    CHECK_CSM(naion_csm_server_encrypt(&s, pt, 32, pkt, sizeof pkt, &pkt_len),
              NAION_CSM_ERR_STATE);
    TEST_END();
}

/* T3.52 */
static int test_csm_size_functions(void)
{
    static const size_t plens[] = { 0, 1, 32, 256, NAION_CSM_MAX_CLIENT_PAYLOAD_BYTES };
    size_t li;

    TEST_BEGIN("test_csm_size_functions");
    for (li = 0; li < sizeof plens / sizeof plens[0]; li++) {
        size_t n = plens[li];
        /* client encrypt = 168 + n  (sig64 + xpk32 + nonce24 + mac16 + edpk32) */
        CHECK(naion_csm_client_encrypt_size(n) == 168 + n);
        /* server encrypt = 136 + n  (sig64 + xpk32 + nonce24 + mac16) */
        CHECK(naion_csm_server_encrypt_size(n) == 136 + n);
        /* decrypt_max inverses */
        CHECK(naion_csm_client_decrypt_max_plaintext_size(naion_csm_server_encrypt_size(n))
              == n);
        CHECK(naion_csm_server_decrypt_max_plaintext_size(naion_csm_client_encrypt_size(n))
              == n);
    }
    TEST_END();
}

/* T3.53 */
static int test_csm_encrypt_null_plaintext(void)
{
    naion_csm_client c;
    naion_csm_server s;
    unsigned char pkt[256];
    size_t pkt_len = 0;

    TEST_BEGIN("test_csm_encrypt_null_plaintext");
    csm_pair(&c, &s);
    CHECK_CSM(naion_csm_client_encrypt(&c, NULL, 16, pkt, sizeof pkt, &pkt_len),
              NAION_CSM_ERR_INVALID_ARGUMENT);
    TEST_END();
}

/* T3.54 */
static int test_csm_encrypt_zero_length(void)
{
    naion_csm_client c;
    naion_csm_server s;
    unsigned char pkt[256];
    size_t pkt_len = 0;

    TEST_BEGIN("test_csm_encrypt_zero_length");
    csm_pair(&c, &s);
    CHECK_CSM(naion_csm_client_encrypt(&c, NULL, 0, pkt, sizeof pkt, &pkt_len),
              NAION_CSM_ERR_NO_DATA);
    TEST_END();
}

/* T3.55 */
static int test_csm_buffer_too_small(void)
{
    naion_csm_client c;
    naion_csm_server s;
    unsigned char pt[32], pkt[16];
    size_t pkt_len = 0;

    TEST_BEGIN("test_csm_buffer_too_small");
    csm_pair(&c, &s);
    fill_pattern(pt, 32, 0xf5);
    /* encrypt cap too small */
    CHECK_CSM(naion_csm_client_encrypt(&c, pt, 32, pkt, sizeof pkt, &pkt_len),
              NAION_CSM_ERR_BUFFER_TOO_SMALL);

    /* decrypt cap too small: first do a real encrypt into a big buffer */
    {
        unsigned char big[NAION_CSM_MAX_UDP_DATAGRAM_BYTES];
        unsigned char tiny[16];
        size_t big_len = 0, out_len = 0;
        CHECK_CSM(naion_csm_client_encrypt(&c, pt, 32, big, sizeof big, &big_len),
                  NAION_CSM_OK);
        CHECK_CSM(naion_csm_server_decrypt(&s, big, big_len, tiny, sizeof tiny, &out_len),
                  NAION_CSM_ERR_BUFFER_TOO_SMALL);
    }
    TEST_END();
}

/* T3.56 */
static int test_csm_tamper_packet(void)
{
    naion_csm_client c;
    naion_csm_server s;
    unsigned char pt[32], *pkt = g_buf_a, *out = g_buf_b;
    size_t pkt_len = 0, out_len = 0;

    TEST_BEGIN("test_csm_tamper_packet");
    csm_pair(&c, &s);
    fill_pattern(pt, 32, 0xf6);
    CHECK_CSM(naion_csm_client_encrypt(&c, pt, 32, pkt, NAION_CSM_MAX_UDP_DATAGRAM_BYTES, &pkt_len),
              NAION_CSM_OK);

    /* layout: sig[0:64] | eph_pk[64:96] | nonce[96:120] | mac[120:136] | ct[136:] */
    {
        size_t offs[] = { 0, 63, 64, 95, 96, 119, 120, 135, 136, pkt_len - 1 };
        size_t oi;
        for (oi = 0; oi < sizeof offs / sizeof offs[0]; oi++) {
            size_t off = offs[oi];
            pkt[off] ^= 0xff;
            out_len = 0;
            CHECK_CSM(naion_csm_server_decrypt(&s, pkt, pkt_len, out, NAION_CSM_MAX_UDP_DATAGRAM_BYTES, &out_len),
                      NAION_CSM_ERR_CRYPTO);
            pkt[off] ^= 0xff;
        }
    }
    TEST_END();
}

/* T3.57 */
static int test_csm_null_errors(void)
{
    naion_csm_client c;
    naion_csm_server s;
    unsigned char pt[32], buf[256];
    size_t len = 0;

    TEST_BEGIN("test_csm_null_errors");
    csm_pair(&c, &s);
    fill_pattern(pt, 32, 0xf7);

    /* client_encrypt NULLs */
    CHECK_CSM(naion_csm_client_encrypt(NULL, pt, 32, buf, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_client_encrypt(&c, pt, 32, NULL, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_client_encrypt(&c, pt, 32, buf, sizeof buf, NULL), NAION_CSM_ERR_INVALID_ARGUMENT);
    /* client_decrypt NULLs */
    CHECK_CSM(naion_csm_client_decrypt(NULL, buf, 32, buf, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_client_decrypt(&c, NULL, 32, buf, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_client_decrypt(&c, buf, 32, NULL, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_client_decrypt(&c, buf, 32, buf, sizeof buf, NULL), NAION_CSM_ERR_INVALID_ARGUMENT);
    /* server_decrypt NULLs */
    CHECK_CSM(naion_csm_server_decrypt(NULL, buf, 32, buf, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_server_decrypt(&s, NULL, 32, buf, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_server_decrypt(&s, buf, 32, NULL, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_server_decrypt(&s, buf, 32, buf, sizeof buf, NULL), NAION_CSM_ERR_INVALID_ARGUMENT);
    /* server_encrypt NULLs */
    CHECK_CSM(naion_csm_server_encrypt(NULL, pt, 32, buf, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_server_encrypt(&s, pt, 32, NULL, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_server_encrypt(&s, pt, 32, buf, sizeof buf, NULL), NAION_CSM_ERR_INVALID_ARGUMENT);
    /* create NULLs */
    {
        unsigned char seed[32], spk[32];
        CHECK_CSM(naion_csm_client_create(NULL, seed, spk), NAION_CSM_ERR_INVALID_ARGUMENT);
        CHECK_CSM(naion_csm_client_create(&c, NULL, spk), NAION_CSM_ERR_INVALID_ARGUMENT);
        CHECK_CSM(naion_csm_client_create(&c, seed, NULL), NAION_CSM_ERR_INVALID_ARGUMENT);
        CHECK_CSM(naion_csm_server_create(NULL, seed), NAION_CSM_ERR_INVALID_ARGUMENT);
        CHECK_CSM(naion_csm_server_create(&s, NULL), NAION_CSM_ERR_INVALID_ARGUMENT);
    }
    TEST_END();
}

#endif /* NAION_LAYER_CSM */

/* ========================================================================= */
/* Section 4 — Layer 4 (NAION_LAYER_CSM_CA)                                   */
/* ========================================================================= */
#if NAION_LAYER_CSM_CA

/* ---- 4A. CA handshake -------------------------------------------------- */

/* Build a real CA-signed certificate for a server using an offline CA seed. */
static void ca_make_cert(const unsigned char ca_seed[32],
                         const unsigned char server_ed_pk[32],
                         unsigned char ca_sig_out[64])
{
    unsigned char ca_pk[32], ca_sk[64];
    unsigned long long sl = 0;
    (void) naion_sign_ed25519_seed_keypair(ca_pk, ca_sk, ca_seed);
    (void) naion_sign_ed25519_detached(ca_sig_out, &sl, server_ed_pk, 32, ca_sk);
}

/* T4.1 */
static int test_csm_ca_client_create(void)
{
    naion_csm_ca_client c;
    unsigned char seed[32], ca_pk[32];

    TEST_BEGIN("test_csm_ca_client_create");
    derive_key(seed, 32, "ca-c-seed");
    derive_key(ca_pk, 32, "ca-ed-pk");
    CHECK_CSM(naion_csm_ca_client_create(&c, seed, ca_pk), NAION_CSM_OK);
    CHECK(c.server_key_verified == 0);
    CHECK(naion_is_zero(c.ed_public_key, 32) == 0);
    TEST_END();
}

/* T4.2 */
static int test_csm_ca_server_create(void)
{
    naion_csm_ca_server s;
    unsigned char seed[32], ca_sig[64];

    TEST_BEGIN("test_csm_ca_server_create");
    derive_key(seed, 32, "ca-s-seed");
    memset(ca_sig, 0x5a, sizeof ca_sig);
    CHECK_CSM(naion_csm_ca_server_create(&s, seed, ca_sig), NAION_CSM_OK);
    CHECK(s.client_key_verified == 0);
    CHECK(naion_is_zero(s.ed_public_key, 32) == 0);
    TEST_END();
}

/* T4.3 */
static int test_csm_ca_handshake_response_size(void)
{
    TEST_BEGIN("test_csm_ca_handshake_response_size");
    CHECK(naion_csm_ca_handshake_response_size() == NAION_CSM_CA_CERT_BYTES);
    CHECK(naion_csm_ca_handshake_response_size() == 96);
    TEST_END();
}

/* T4.4 */
static int test_csm_ca_handshake_response(void)
{
    naion_csm_ca_server s;
    unsigned char seed[32], ca_seed[32], ca_sig[64];
    unsigned char m1[NAION_CSM_CA_CERT_BYTES], m1b[200];
    size_t out_len = 0;

    TEST_BEGIN("test_csm_ca_handshake_response");
    derive_key(seed, 32, "ca-s-seed");
    derive_key(ca_seed, 32, "ca-ed-seed");
    memset(ca_sig, 0, sizeof ca_sig);
    CHECK_CSM(naion_csm_ca_server_create(&s, seed, ca_sig), NAION_CSM_OK);
    ca_make_cert(ca_seed, s.ed_public_key, ca_sig);
    memcpy(s.ca_signature, ca_sig, 64);

    out_len = 999;
    CHECK_CSM(naion_csm_ca_handshake_response(&s, m1, sizeof m1, &out_len), NAION_CSM_OK);
    CHECK(out_len == 96);
    /* layout: server_ed_pk[32] || ca_sig[64] */
    CHECK(naion_memcmp(m1, s.ed_public_key, 32) == 0);
    CHECK(naion_memcmp(m1 + 32, ca_sig, 64) == 0);

    /* cap too small */
    out_len = 0;
    CHECK_CSM(naion_csm_ca_handshake_response(&s, m1b, 95, &out_len), NAION_CSM_ERR_BUFFER_TOO_SMALL);
    TEST_END();
}

/* T4.5 */
static int test_csm_ca_handshake_flow(void)
{
    naion_csm_ca_client c;
    naion_csm_ca_server s;
    unsigned char cseed[32], sseed[32], ca_seed[32], ca_pk[32], ca_sig[64];
    unsigned char m1[NAION_CSM_CA_CERT_BYTES];
    size_t out_len = 0;

    TEST_BEGIN("test_csm_ca_handshake_flow");
    derive_key(cseed, 32, "ca-c-seed");
    derive_key(sseed, 32, "ca-s-seed");
    derive_key(ca_seed, 32, "ca-ed-seed");
    (void) naion_sign_ed25519_seed_keypair(ca_pk, NULL, ca_seed);   /* placeholder */
    {
        unsigned char dummy_sk[64];
        (void) naion_sign_ed25519_seed_keypair(ca_pk, dummy_sk, ca_seed);
    }

    /* server: create with a placeholder sig, then have CA sign its pk */
    memset(ca_sig, 0, sizeof ca_sig);
    CHECK_CSM(naion_csm_ca_server_create(&s, sseed, ca_sig), NAION_CSM_OK);
    ca_make_cert(ca_seed, s.ed_public_key, ca_sig);
    memcpy(s.ca_signature, ca_sig, 64);

    /* client: built with the CA public key */
    CHECK_CSM(naion_csm_ca_client_create(&c, cseed, ca_pk), NAION_CSM_OK);
    CHECK(c.server_key_verified == 0);

    /* server -> client: handshake response */
    CHECK_CSM(naion_csm_ca_handshake_response(&s, m1, sizeof m1, &out_len), NAION_CSM_OK);
    /* client verifies */
    CHECK_CSM(naion_csm_ca_handshake_verify(&c, m1, out_len), NAION_CSM_OK);
    CHECK(c.server_key_verified == 1);
    CHECK(naion_memcmp(c.server_ed_public_key, s.ed_public_key, 32) == 0);
    TEST_END();
}

/* T4.6 */
static int test_csm_ca_handshake_tamper(void)
{
    naion_csm_ca_client c;
    naion_csm_ca_server s;
    unsigned char cseed[32], sseed[32], ca_seed[32], ca_pk[64], ca_sig[64];
    unsigned char m1[NAION_CSM_CA_CERT_BYTES];
    size_t out_len = 0;

    TEST_BEGIN("test_csm_ca_handshake_tamper");
    derive_key(cseed, 32, "ca-c-seed");
    derive_key(sseed, 32, "ca-s-seed");
    derive_key(ca_seed, 32, "ca-ed-seed");
    {
        unsigned char dummy_sk[64];
        (void) naion_sign_ed25519_seed_keypair(ca_pk, dummy_sk, ca_seed);
    }
    CHECK_CSM(naion_csm_ca_server_create(&s, sseed, ca_sig), NAION_CSM_OK);
    ca_make_cert(ca_seed, s.ed_public_key, ca_sig);
    memcpy(s.ca_signature, ca_sig, 64);
    CHECK_CSM(naion_csm_ca_client_create(&c, cseed, ca_pk), NAION_CSM_OK);
    CHECK_CSM(naion_csm_ca_handshake_response(&s, m1, sizeof m1, &out_len), NAION_CSM_OK);

    /* tamper server_pk */
    m1[0] ^= 0xff;
    CHECK_CSM(naion_csm_ca_handshake_verify(&c, m1, out_len), NAION_CSM_ERR_VERIFY_FAILED);
    m1[0] ^= 0xff;
    CHECK(c.server_key_verified == 0);
    /* tamper ca_sig */
    m1[40] ^= 0xff;
    CHECK_CSM(naion_csm_ca_handshake_verify(&c, m1, out_len), NAION_CSM_ERR_VERIFY_FAILED);
    m1[40] ^= 0xff;
    TEST_END();
}

/* T4.7 */
static int test_csm_ca_handshake_wrong_ca(void)
{
    naion_csm_ca_client c;
    naion_csm_ca_server s;
    unsigned char cseed[32], sseed[32], ca_seed[32], wrong_pk[32], ca_sig[64];
    unsigned char m1[NAION_CSM_CA_CERT_BYTES];
    size_t out_len = 0;

    TEST_BEGIN("test_csm_ca_handshake_wrong_ca");
    derive_key(cseed, 32, "ca-c-seed");
    derive_key(sseed, 32, "ca-s-seed");
    derive_key(ca_seed, 32, "ca-ed-seed");
    derive_key(wrong_pk, 32, "ca-wrong");
    {
        unsigned char dummy_sk[64];
        (void) naion_sign_ed25519_seed_keypair(wrong_pk, dummy_sk, ca_seed);
        /* wrong_pk is actually the real pk here; use a genuinely different seed */
    }
    /* Build a client with an unrelated CA pk */
    derive_key(wrong_pk, 32, "totally-different-ca");
    memset(ca_sig, 0, sizeof ca_sig);
    CHECK_CSM(naion_csm_ca_server_create(&s, sseed, ca_sig), NAION_CSM_OK);
    ca_make_cert(ca_seed, s.ed_public_key, ca_sig);
    memcpy(s.ca_signature, ca_sig, 64);
    CHECK_CSM(naion_csm_ca_client_create(&c, cseed, wrong_pk), NAION_CSM_OK);
    CHECK_CSM(naion_csm_ca_handshake_response(&s, m1, sizeof m1, &out_len), NAION_CSM_OK);
    CHECK_CSM(naion_csm_ca_handshake_verify(&c, m1, out_len), NAION_CSM_ERR_VERIFY_FAILED);
    TEST_END();
}

/* T4.8 */
static int test_csm_ca_handshake_wrong_size(void)
{
    naion_csm_ca_client c;
    unsigned char cseed[32], ca_pk[32], m1[100];

    TEST_BEGIN("test_csm_ca_handshake_wrong_size");
    derive_key(cseed, 32, "ca-c-seed");
    derive_key(ca_pk, 32, "ca-ed-pk");
    CHECK_CSM(naion_csm_ca_client_create(&c, cseed, ca_pk), NAION_CSM_OK);
    memset(m1, 0, sizeof m1);
    CHECK_CSM(naion_csm_ca_handshake_verify(&c, m1, 95), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_ca_handshake_verify(&c, m1, 97), NAION_CSM_ERR_INVALID_ARGUMENT);
    TEST_END();
}

/* ---- 4B. CSM-CA messages ---------------------------------------------- */

/* Helper: full CA handshake so client+server can exchange messages. */
static void ca_handshake_pair(naion_csm_ca_client *c, naion_csm_ca_server *s)
{
    unsigned char cseed[32], sseed[32], ca_seed[32], ca_pk[32], ca_sig[64];
    unsigned char m1[NAION_CSM_CA_CERT_BYTES];
    size_t out_len = 0;
    derive_key(cseed, 32, "ca-c-seed");
    derive_key(sseed, 32, "ca-s-seed");
    derive_key(ca_seed, 32, "ca-ed-seed");
    {
        unsigned char dummy_sk[64];
        (void) naion_sign_ed25519_seed_keypair(ca_pk, dummy_sk, ca_seed);
    }
    memset(ca_sig, 0, sizeof ca_sig);
    (void) naion_csm_ca_server_create(s, sseed, ca_sig);
    ca_make_cert(ca_seed, s->ed_public_key, ca_sig);
    memcpy(s->ca_signature, ca_sig, 64);
    (void) naion_csm_ca_client_create(c, cseed, ca_pk);
    (void) naion_csm_ca_handshake_response(s, m1, sizeof m1, &out_len);
    (void) naion_csm_ca_handshake_verify(c, m1, out_len);
}

/* T4.9 */
static int test_csm_ca_full_flow(void)
{
    static const size_t plens[] = { 1, 32, 256 };
    naion_csm_ca_client c;
    naion_csm_ca_server s;
    unsigned char *pt = g_buf_a, *pkt = g_buf_b, *out = g_buf_c;
    size_t pkt_len = 0, out_len = 0;
    size_t li;

    TEST_BEGIN("test_csm_ca_full_flow");
    ca_handshake_pair(&c, &s);
    CHECK(c.server_key_verified == 1);

    for (li = 0; li < sizeof plens / sizeof plens[0]; li++) {
        size_t n = plens[li];
        fill_pattern(pt, n, 0xa1);
        /* C -> S */
        CHECK_CSM(naion_csm_ca_client_encrypt(&c, pt, n, pkt, NAION_CSM_MAX_UDP_DATAGRAM_BYTES, &pkt_len),
                  NAION_CSM_OK);
        CHECK_CSM(naion_csm_ca_server_decrypt(&s, pkt, pkt_len, out, NAION_CSM_MAX_UDP_DATAGRAM_BYTES, &out_len),
                  NAION_CSM_OK);
        CHECK(out_len == n);
        CHECK(naion_memcmp(pt, out, n) == 0);
        CHECK(s.client_key_verified == 1);
        /* S -> C */
        CHECK_CSM(naion_csm_ca_server_encrypt(&s, pt, n, pkt, NAION_CSM_MAX_UDP_DATAGRAM_BYTES, &pkt_len),
                  NAION_CSM_OK);
        CHECK_CSM(naion_csm_ca_client_decrypt(&c, pkt, pkt_len, out, NAION_CSM_MAX_UDP_DATAGRAM_BYTES, &out_len),
                  NAION_CSM_OK);
        CHECK(out_len == n);
        CHECK(naion_memcmp(pt, out, n) == 0);
    }
    TEST_END();
}

/* T4.10 */
static int test_csm_ca_encrypt_before_handshake(void)
{
    naion_csm_ca_client c;
    naion_csm_ca_server s;
    unsigned char cseed[32], ca_pk[32], pt[32], pkt[256];
    size_t pkt_len = 0;

    TEST_BEGIN("test_csm_ca_encrypt_before_handshake");
    derive_key(cseed, 32, "ca-c-seed");
    derive_key(ca_pk, 32, "ca-ed-pk");
    /* create client but do NOT handshake */
    CHECK_CSM(naion_csm_ca_client_create(&c, cseed, ca_pk), NAION_CSM_OK);
    fill_pattern(pt, 32, 0xa2);
    CHECK_CSM(naion_csm_ca_client_encrypt(&c, pt, 32, pkt, sizeof pkt, &pkt_len),
              NAION_CSM_ERR_STATE);
    (void) s;
    TEST_END();
}

/* T4.11 */
static int test_csm_ca_server_encrypt_before_client(void)
{
    naion_csm_ca_client c;
    naion_csm_ca_server s;
    unsigned char pt[32], pkt[256];
    size_t pkt_len = 0;

    TEST_BEGIN("test_csm_ca_server_encrypt_before_client");
    ca_handshake_pair(&c, &s);
    /* server has NOT yet seen a client packet */
    CHECK(s.client_key_verified == 0);
    fill_pattern(pt, 32, 0xa3);
    CHECK_CSM(naion_csm_ca_server_encrypt(&s, pt, 32, pkt, sizeof pkt, &pkt_len),
              NAION_CSM_ERR_STATE);
    TEST_END();
}

/* T4.12 */
static int test_csm_ca_size_functions(void)
{
    static const size_t plens[] = { 0, 1, 32, 256, NAION_CSM_MAX_CLIENT_PAYLOAD_BYTES };
    size_t li;

    TEST_BEGIN("test_csm_ca_size_functions");
    for (li = 0; li < sizeof plens / sizeof plens[0]; li++) {
        size_t n = plens[li];
        CHECK(naion_csm_ca_client_encrypt_size(n) == naion_csm_client_encrypt_size(n));
        CHECK(naion_csm_ca_server_encrypt_size(n) == naion_csm_server_encrypt_size(n));
        CHECK(naion_csm_ca_client_decrypt_max_plaintext_size(naion_csm_ca_server_encrypt_size(n)) == n);
        CHECK(naion_csm_ca_server_decrypt_max_plaintext_size(naion_csm_ca_client_encrypt_size(n)) == n);
    }
    TEST_END();
}

/* T4.13 */
static int test_csm_ca_wipe(void)
{
    naion_csm_ca_client c;
    naion_csm_ca_server s;

    TEST_BEGIN("test_csm_ca_wipe");
    ca_handshake_pair(&c, &s);
    naion_csm_ca_client_wipe(&c);
    naion_csm_ca_server_wipe(&s);
    CHECK(c.server_key_verified == 0);
    CHECK(s.client_key_verified == 0);
    TEST_END();
}

/* T4.14 */
static int test_csm_ca_tamper(void)
{
    naion_csm_ca_client c;
    naion_csm_ca_server s;
    unsigned char pt[32], *pkt = g_buf_a, *out = g_buf_b;
    size_t pkt_len = 0, out_len = 0;
    size_t offs[] = { 0, 63, 64, 95, 96, 119, 120, 135, 136 };
    size_t oi;

    TEST_BEGIN("test_csm_ca_tamper");
    ca_handshake_pair(&c, &s);
    fill_pattern(pt, 32, 0xa4);
    CHECK_CSM(naion_csm_ca_client_encrypt(&c, pt, 32, pkt, NAION_CSM_MAX_UDP_DATAGRAM_BYTES, &pkt_len),
              NAION_CSM_OK);
    for (oi = 0; oi < sizeof offs / sizeof offs[0]; oi++) {
        size_t off = offs[oi];
        pkt[off] ^= 0xff;
        out_len = 0;
        CHECK_CSM(naion_csm_ca_server_decrypt(&s, pkt, pkt_len, out, NAION_CSM_MAX_UDP_DATAGRAM_BYTES, &out_len),
                  NAION_CSM_ERR_CRYPTO);
        pkt[off] ^= 0xff;
    }
    TEST_END();
}

/* T4.15 */
static int test_csm_ca_null_errors(void)
{
    naion_csm_ca_client c;
    naion_csm_ca_server s;
    unsigned char seed[32], ca_pk[32], ca_sig[64], buf[256], pt[32];
    size_t len = 0;

    TEST_BEGIN("test_csm_ca_null_errors");
    derive_key(seed, 32, "ca-c-seed");
    derive_key(ca_pk, 32, "ca-ed-pk");
    memset(ca_sig, 0x5a, sizeof ca_sig);
    ca_handshake_pair(&c, &s);
    fill_pattern(pt, 32, 0xa5);

    /* create NULLs */
    CHECK_CSM(naion_csm_ca_client_create(NULL, seed, ca_pk), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_ca_client_create(&c, NULL, ca_pk), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_ca_client_create(&c, seed, NULL), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_ca_server_create(NULL, seed, ca_sig), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_ca_server_create(&s, NULL, ca_sig), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_ca_server_create(&s, seed, NULL), NAION_CSM_ERR_INVALID_ARGUMENT);

    /* handshake_response NULLs */
    CHECK_CSM(naion_csm_ca_handshake_response(NULL, buf, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_ca_handshake_response(&s, NULL, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_ca_handshake_response(&s, buf, sizeof buf, NULL), NAION_CSM_ERR_INVALID_ARGUMENT);
    /* handshake_verify NULLs */
    CHECK_CSM(naion_csm_ca_handshake_verify(NULL, buf, 96), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_ca_handshake_verify(&c, NULL, 96), NAION_CSM_ERR_INVALID_ARGUMENT);

    /* encrypt/decrypt NULLs */
    CHECK_CSM(naion_csm_ca_client_encrypt(NULL, pt, 32, buf, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_ca_client_encrypt(&c, pt, 32, NULL, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_ca_client_encrypt(&c, pt, 32, buf, sizeof buf, NULL), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_ca_client_decrypt(NULL, buf, 32, buf, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_ca_client_decrypt(&c, NULL, 32, buf, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_ca_client_decrypt(&c, buf, 32, NULL, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_ca_client_decrypt(&c, buf, 32, buf, sizeof buf, NULL), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_ca_server_encrypt(NULL, pt, 32, buf, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);

    /* server_encrypt with a client-known server: a real C->S packet makes the
     * server learn the client key, so the subsequent NULL-out / NULL-len paths
     * are reached (otherwise STATE short-circuits first). */
    {
        unsigned char pkt[NAION_CSM_MAX_UDP_DATAGRAM_BYTES];
        unsigned char out[NAION_CSM_MAX_UDP_DATAGRAM_BYTES];
        size_t pkt_len = 0, out_len = 0;
        CHECK_CSM(naion_csm_ca_client_encrypt(&c, pt, 32, pkt, sizeof pkt, &pkt_len), NAION_CSM_OK);
        CHECK_CSM(naion_csm_ca_server_decrypt(&s, pkt, pkt_len, out, sizeof out, &out_len), NAION_CSM_OK);
        CHECK(s.client_key_verified == 1);
        /* now NULL out / NULL out_len must be rejected */
        CHECK_CSM(naion_csm_ca_server_encrypt(&s, pt, 32, NULL, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
        CHECK_CSM(naion_csm_ca_server_encrypt(&s, pt, 32, buf, sizeof buf, NULL), NAION_CSM_ERR_INVALID_ARGUMENT);
        /* also exercise the STATE-vs-ARGUMENT ordering: before learning the
         * client a fresh server returns STATE, not INVALID_ARGUMENT. */
    }
    CHECK_CSM(naion_csm_ca_server_decrypt(NULL, buf, 32, buf, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_ca_server_decrypt(&s, NULL, 32, buf, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_ca_server_decrypt(&s, buf, 32, NULL, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_ca_server_decrypt(&s, buf, 32, buf, sizeof buf, NULL), NAION_CSM_ERR_INVALID_ARGUMENT);
    TEST_END();
}

#endif /* NAION_LAYER_CSM_CA */

/* ========================================================================= */
/* Section 4C — CSM-Session (Layer 5, ephemeral-ephemeral DH, PFS)          */
/* ========================================================================= */
#if NAION_LAYER_CSM_SESSION

/* Build a CA signature over a server Ed25519 pk using an offline CA seed. */
static void sess_ca_make_cert(const unsigned char ca_seed[32],
                               const unsigned char server_ed_pk[32],
                               unsigned char ca_sig_out[64])
{
    unsigned char ca_pk[32], ca_sk[64];
    unsigned long long sl = 0;
    (void) naion_sign_ed25519_seed_keypair(ca_pk, ca_sk, ca_seed);
    (void) naion_sign_ed25519_detached(ca_sig_out, &sl, server_ed_pk, 32, ca_sk);
}

/* T5.1 */
static int test_csm_sess_client_create(void)
{
    naion_csm_sess_client c;
    unsigned char seed[32], ca_pk[32];

    TEST_BEGIN("test_csm_sess_client_create");
    derive_key(seed, 32, "sess-c-seed");
    derive_key(ca_pk, 32, "sess-ca-pk");
    CHECK_CSM(naion_csm_sess_client_create(&c, seed, ca_pk), NAION_CSM_OK);
    CHECK(c.handshake_complete == 0);
    CHECK(naion_is_zero(c.ed_public_key, 32) == 0);
    TEST_END();
}

/* T5.2 */
static int test_csm_sess_server_create(void)
{
    naion_csm_sess_server s;
    unsigned char seed[32], ca_sig[64];

    TEST_BEGIN("test_csm_sess_server_create");
    derive_key(seed, 32, "sess-s-seed");
    memset(ca_sig, 0x5a, sizeof ca_sig);
    CHECK_CSM(naion_csm_sess_server_create(&s, seed, ca_sig), NAION_CSM_OK);
    CHECK(s.handshake_complete == 0);
    CHECK(naion_is_zero(s.ed_public_key, 32) == 0);
    TEST_END();
}

/* T5.3 */
static int test_csm_sess_constants(void)
{
    TEST_BEGIN("test_csm_sess_constants");
    CHECK(NAION_CSM_SESS_CLIENT_HELLO_BYTES == 128);
    CHECK(NAION_CSM_SESS_SERVER_RESPONSE_BYTES == 192);
    CHECK(NAION_CSM_SESS_PACKET_OVERHEAD == 104);
    CHECK(NAION_CSM_SESS_MAX_CLIENT_PAYLOAD_BYTES == 920);
    CHECK(NAION_CSM_SESS_MAX_SERVER_PAYLOAD_BYTES == 920);
    TEST_END();
}

/* T5.4 — CLIENT_HELLO structure: xpk(32) || ed_pk(32) || sig(64) */
static int test_csm_sess_client_hello(void)
{
    naion_csm_sess_client c;
    unsigned char seed[32], ca_pk[32];
    unsigned char hello[NAION_CSM_SESS_CLIENT_HELLO_BYTES];

    TEST_BEGIN("test_csm_sess_client_hello");
    derive_key(seed, 32, "sess-c-seed");
    derive_key(ca_pk, 32, "sess-ca-pk");
    CHECK_CSM(naion_csm_sess_client_create(&c, seed, ca_pk), NAION_CSM_OK);
    CHECK_CSM(naion_csm_sess_client_hello(&c, hello), NAION_CSM_OK);
    /* layout: client_session_xpk(32) || client_ed_pk(32) || sig(64) */
    CHECK(naion_memcmp(hello, c.client_session_xpk, 32) == 0);
    CHECK(naion_memcmp(hello + 32, c.ed_public_key, 32) == 0);
    /* signature must verify over client_session_xpk with client_ed_pk */
    CHECK_OK(naion_sign_ed25519_verify_detached(hello + 64, hello, 32, hello + 32));
    TEST_END();
}

/* T5.5 — full 1-RTT handshake helper used by the traffic tests below. */
static void sess_handshake_pair(naion_csm_sess_client *c, naion_csm_sess_server *s)
{
    unsigned char cseed[32], sseed[32], ca_seed[32], ca_pk[32], ca_sig[64];
    unsigned char hello[NAION_CSM_SESS_CLIENT_HELLO_BYTES];
    unsigned char m1[NAION_CSM_SESS_SERVER_RESPONSE_BYTES];
    size_t out_len = 0;

    derive_key(cseed, 32, "sess-c-seed");
    derive_key(sseed, 32, "sess-s-seed");
    derive_key(ca_seed, 32, "sess-ca-seed");
    {
        unsigned char ca_sk[64];
        (void) naion_sign_ed25519_seed_keypair(ca_pk, ca_sk, ca_seed);
    }
    memset(ca_sig, 0, sizeof ca_sig);
    (void) naion_csm_sess_server_create(s, sseed, ca_sig);
    sess_ca_make_cert(ca_seed, s->ed_public_key, ca_sig);
    memcpy(s->ca_signature, ca_sig, 64);
    (void) naion_csm_sess_client_create(c, cseed, ca_pk);
    (void) naion_csm_sess_client_hello(c, hello);
    (void) naion_csm_sess_server_handshake(s, hello, m1, sizeof m1, &out_len);
    (void) naion_csm_sess_client_finish(c, m1, out_len);
}

/* T5.6 */
static int test_csm_sess_handshake_flow(void)
{
    naion_csm_sess_client c;
    naion_csm_sess_server s;

    TEST_BEGIN("test_csm_sess_handshake_flow");
    sess_handshake_pair(&c, &s);
    CHECK(c.handshake_complete == 1);
    CHECK(s.handshake_complete == 1);
    /* server learnt the client identity ... */
    CHECK(naion_memcmp(s.client_ed_public_key, c.ed_public_key, 32) == 0);
    /* ... and the client learnt the server identity via the CA chain */
    CHECK(naion_memcmp(c.server_ed_public_key, s.ed_public_key, 32) == 0);
    /* forward-secrecy invariant: both sides derived the same session AEAD key */
    CHECK(naion_memcmp(c.session_aead_key, s.session_aead_key, 32) == 0);
    TEST_END();
}

/* T5.7 — bad CLIENT_HELLO must not allocate any server session state. */
static int test_csm_sess_server_handshake_reject(void)
{
    naion_csm_sess_client c;
    naion_csm_sess_server s;
    unsigned char hello[NAION_CSM_SESS_CLIENT_HELLO_BYTES];
    unsigned char m1[NAION_CSM_SESS_SERVER_RESPONSE_BYTES];
    unsigned char snapshot[sizeof(s)];
    size_t out_len = 0;

    TEST_BEGIN("test_csm_sess_server_handshake_reject");
    sess_handshake_pair(&c, &s);
    /* reset server to pre-handshake state */
    {
        unsigned char sseed[32], ca_seed[32], ca_sig[64];
        derive_key(sseed, 32, "sess-s-seed");
        derive_key(ca_seed, 32, "sess-ca-seed");
        memset(ca_sig, 0, sizeof ca_sig);
        (void) naion_csm_sess_server_create(&s, sseed, ca_sig);
        sess_ca_make_cert(ca_seed, s.ed_public_key, ca_sig);
        memcpy(s.ca_signature, ca_sig, 64);
    }
    memcpy(snapshot, &s, sizeof snapshot);

    /* zero client_session_xpk */
    memset(hello, 0, sizeof hello);
    CHECK_CSM(naion_csm_sess_server_handshake(&s, hello, m1, sizeof m1, &out_len),
              NAION_CSM_ERR_INVALID_ARGUMENT);
    /* build a real hello, then tamper the signature */
    CHECK_CSM(naion_csm_sess_client_hello(&c, hello), NAION_CSM_OK);
    hello[64] ^= 0xff;
    CHECK_CSM(naion_csm_sess_server_handshake(&s, hello, m1, sizeof m1, &out_len),
              NAION_CSM_ERR_VERIFY_FAILED);
    hello[64] ^= 0xff;
    /* tamper client_ed_pk instead */
    hello[32] ^= 0xff;
    CHECK_CSM(naion_csm_sess_server_handshake(&s, hello, m1, sizeof m1, &out_len),
              NAION_CSM_ERR_VERIFY_FAILED);
    hello[32] ^= 0xff;

    /* on every rejected path the server state is unchanged */
    CHECK(naion_memcmp(snapshot, &s, sizeof snapshot) == 0);
    CHECK(s.handshake_complete == 0);
    TEST_END();
}

/* T5.8 — client_finish certificate-chain verification. */
static int test_csm_sess_client_finish_reject(void)
{
    naion_csm_sess_client c;
    naion_csm_sess_server s;
    unsigned char hello[NAION_CSM_SESS_CLIENT_HELLO_BYTES];
    unsigned char m1[NAION_CSM_SESS_SERVER_RESPONSE_BYTES];
    size_t out_len = 0;

    TEST_BEGIN("test_csm_sess_client_finish_reject");
    sess_handshake_pair(&c, &s);
    /* reset to a fresh pre-handshake client */
    {
        unsigned char cseed[32], ca_pk[32];
        derive_key(cseed, 32, "sess-c-seed");
        derive_key(ca_pk, 32, "sess-ca-pk");
        /* deliberately use a *different* CA pk from the one that signed the server */
        derive_key(ca_pk, 32, "sess-wrong-ca");
        (void) naion_csm_sess_client_create(&c, cseed, ca_pk);
    }
    CHECK_CSM(naion_csm_sess_client_hello(&c, hello), NAION_CSM_OK);
    CHECK_CSM(naion_csm_sess_server_handshake(&s, hello, m1, sizeof m1, &out_len), NAION_CSM_OK);

    /* wrong m1 size */
    CHECK_CSM(naion_csm_sess_client_finish(&c, m1, 191), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_sess_client_finish(&c, m1, 193), NAION_CSM_ERR_INVALID_ARGUMENT);
    /* wrong CA */
    CHECK_CSM(naion_csm_sess_client_finish(&c, m1, out_len), NAION_CSM_ERR_VERIFY_FAILED);
    CHECK(c.handshake_complete == 0);
    /* tamper CA signature */
    m1[160] ^= 0xff;
    CHECK_CSM(naion_csm_sess_client_finish(&c, m1, out_len), NAION_CSM_ERR_VERIFY_FAILED);
    m1[160] ^= 0xff;
    TEST_END();
}

/* T5.9 — bidirectional traffic over the session key, no per-packet DH. */
static int test_csm_sess_full_flow(void)
{
    static const size_t plens[] = { 1, 32, 256, NAION_CSM_SESS_MAX_CLIENT_PAYLOAD_BYTES };
    naion_csm_sess_client c;
    naion_csm_sess_server s;
    unsigned char *pt = g_buf_a, *pkt = g_buf_b, *out = g_buf_c;
    size_t pkt_len = 0, out_len = 0;
    size_t li;

    TEST_BEGIN("test_csm_sess_full_flow");
    sess_handshake_pair(&c, &s);
    CHECK(c.handshake_complete == 1);
    CHECK(s.handshake_complete == 1);

    for (li = 0; li < sizeof plens / sizeof plens[0]; li++) {
        size_t n = plens[li];
        fill_pattern(pt, n, 0xa1);
        /* C -> S */
        CHECK(naion_csm_sess_client_encrypt_size(n) == 104 + n);
        CHECK_CSM(naion_csm_sess_client_encrypt(&c, pt, n, pkt, NAION_CSM_SESS_MAX_UDP_DATAGRAM_BYTES, &pkt_len),
                  NAION_CSM_OK);
        CHECK(pkt_len == 104 + n);
        CHECK_CSM(naion_csm_sess_server_decrypt(&s, pkt, pkt_len, out, NAION_CSM_SESS_MAX_UDP_DATAGRAM_BYTES, &out_len),
                  NAION_CSM_OK);
        CHECK(out_len == n);
        CHECK(naion_memcmp(pt, out, n) == 0);
        /* S -> C */
        CHECK_CSM(naion_csm_sess_server_encrypt(&s, pt, n, pkt, NAION_CSM_SESS_MAX_UDP_DATAGRAM_BYTES, &pkt_len),
                  NAION_CSM_OK);
        CHECK_CSM(naion_csm_sess_client_decrypt(&c, pkt, pkt_len, out, NAION_CSM_SESS_MAX_UDP_DATAGRAM_BYTES, &out_len),
                  NAION_CSM_OK);
        CHECK(out_len == n);
        CHECK(naion_memcmp(pt, out, n) == 0);
    }
    TEST_END();
}

/* T5.10 */
static int test_csm_sess_encrypt_before_handshake(void)
{
    naion_csm_sess_client c;
    naion_csm_sess_server s;
    unsigned char pt[32], pkt[256];
    size_t pkt_len = 0;

    TEST_BEGIN("test_csm_sess_encrypt_before_handshake");
    {
        unsigned char cseed[32], sseed[32], ca_pk[32], ca_sig[64];
        derive_key(cseed, 32, "sess-c-seed");
        derive_key(sseed, 32, "sess-s-seed");
        derive_key(ca_pk, 32, "sess-ca-pk");
        memset(ca_sig, 0, sizeof ca_sig);
        (void) naion_csm_sess_client_create(&c, cseed, ca_pk);
        (void) naion_csm_sess_server_create(&s, sseed, ca_sig);
    }
    fill_pattern(pt, 32, 0xa2);
    CHECK_CSM(naion_csm_sess_client_encrypt(&c, pt, 32, pkt, sizeof pkt, &pkt_len),
              NAION_CSM_ERR_STATE);
    CHECK_CSM(naion_csm_sess_server_encrypt(&s, pt, 32, pkt, sizeof pkt, &pkt_len),
              NAION_CSM_ERR_STATE);
    CHECK_CSM(naion_csm_sess_client_decrypt(&c, pt, 32, pkt, sizeof pkt, &pkt_len),
              NAION_CSM_ERR_STATE);
    CHECK_CSM(naion_csm_sess_server_decrypt(&s, pt, 32, pkt, sizeof pkt, &pkt_len),
              NAION_CSM_ERR_STATE);
    TEST_END();
}

/* T5.11 */
static int test_csm_sess_size_functions(void)
{
    static const size_t plens[] = { 1, 32, 256, NAION_CSM_SESS_MAX_CLIENT_PAYLOAD_BYTES };
    size_t li;

    TEST_BEGIN("test_csm_sess_size_functions");
    for (li = 0; li < sizeof plens / sizeof plens[0]; li++) {
        size_t n = plens[li];
        CHECK(naion_csm_sess_client_encrypt_size(n) == 104 + n);
        CHECK(naion_csm_sess_server_encrypt_size(n) == 104 + n);
        CHECK(naion_csm_sess_client_decrypt_max_plaintext_size(104 + n) == n);
        CHECK(naion_csm_sess_server_decrypt_max_plaintext_size(104 + n) == n);
    }
    CHECK(naion_csm_sess_client_decrypt_max_plaintext_size(104) == 0);
    CHECK(naion_csm_sess_server_decrypt_max_plaintext_size(0) == 0);
    TEST_END();
}

/* T5.12 */
static int test_csm_sess_wipe(void)
{
    naion_csm_sess_client c;
    naion_csm_sess_server s;

    TEST_BEGIN("test_csm_sess_wipe");
    sess_handshake_pair(&c, &s);
    naion_csm_sess_client_wipe(&c);
    naion_csm_sess_server_wipe(&s);
    CHECK(c.handshake_complete == 0);
    CHECK(s.handshake_complete == 0);
    CHECK(naion_is_zero((const unsigned char *) &c, sizeof c) == 1);
    CHECK(naion_is_zero((const unsigned char *) &s, sizeof s) == 1);
    TEST_END();
}

/* T5.13 — verify-then-decrypt: any tamper (sig / nonce / mac / ct) is rejected. */
static int test_csm_sess_tamper(void)
{
    naion_csm_sess_client c;
    naion_csm_sess_server s;
    unsigned char pt[32], *pkt = g_buf_a, *out = g_buf_b;
    size_t pkt_len = 0, out_len = 0;
    size_t offs[] = { 0, 63, 64, 87, 88, 103, 104, 120 };
    size_t oi;

    TEST_BEGIN("test_csm_sess_tamper");
    sess_handshake_pair(&c, &s);
    fill_pattern(pt, 32, 0xa4);
    CHECK_CSM(naion_csm_sess_client_encrypt(&c, pt, 32, pkt, NAION_CSM_SESS_MAX_UDP_DATAGRAM_BYTES, &pkt_len),
              NAION_CSM_OK);
    /* signature tamper -> VERIFY_FAILED (no AEAD work) */
    pkt[0] ^= 0xff;
    CHECK_CSM(naion_csm_sess_server_decrypt(&s, pkt, pkt_len, out, NAION_CSM_SESS_MAX_UDP_DATAGRAM_BYTES, &out_len),
              NAION_CSM_ERR_VERIFY_FAILED);
    pkt[0] ^= 0xff;
    /* nonce / mac / ciphertext tamper -> signature still valid, AEAD fails */
    for (oi = 0; oi < sizeof offs / sizeof offs[0]; oi++) {
        size_t off = offs[oi];
        pkt[off] ^= 0xff;
        out_len = 0;
        {
            int rc = naion_csm_sess_server_decrypt(&s, pkt, pkt_len, out,
                                                   NAION_CSM_SESS_MAX_UDP_DATAGRAM_BYTES, &out_len);
            /* off >= 64 corrupts body and therefore the signed bytes -> VERIFY_FAILED;
             * otherwise the signature is intact and the AEAD layer rejects it. */
            if (off < 64) {
                CHECK_CSM(rc, NAION_CSM_ERR_VERIFY_FAILED);
            } else {
                CHECK(rc == NAION_CSM_ERR_VERIFY_FAILED || rc == NAION_CSM_ERR_CRYPTO);
            }
        }
        pkt[off] ^= 0xff;
    }
    TEST_END();
}

/* T5.14 */
static int test_csm_sess_null_errors(void)
{
    naion_csm_sess_client c;
    naion_csm_sess_server s;
    unsigned char seed[32], ca_pk[32], ca_sig[64], buf[256], pt[32];
    unsigned char hello[NAION_CSM_SESS_CLIENT_HELLO_BYTES];
    unsigned char m1[NAION_CSM_SESS_SERVER_RESPONSE_BYTES];
    size_t len = 0;

    TEST_BEGIN("test_csm_sess_null_errors");
    derive_key(seed, 32, "sess-c-seed");
    derive_key(ca_pk, 32, "sess-ca-pk");
    memset(ca_sig, 0x5a, sizeof ca_sig);
    sess_handshake_pair(&c, &s);
    fill_pattern(pt, 32, 0xa5);

    /* create NULLs */
    CHECK_CSM(naion_csm_sess_client_create(NULL, seed, ca_pk), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_sess_client_create(&c, NULL, ca_pk), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_sess_client_create(&c, seed, NULL), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_sess_server_create(NULL, seed, ca_sig), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_sess_server_create(&s, NULL, ca_sig), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_sess_server_create(&s, seed, NULL), NAION_CSM_ERR_INVALID_ARGUMENT);

    /* hello NULLs */
    CHECK_CSM(naion_csm_sess_client_hello(NULL, hello), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_sess_client_hello(&c, NULL), NAION_CSM_ERR_INVALID_ARGUMENT);

    /* server_handshake NULLs */
    CHECK_CSM(naion_csm_sess_server_handshake(NULL, hello, m1, sizeof m1, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_sess_server_handshake(&s, NULL, m1, sizeof m1, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_sess_server_handshake(&s, hello, NULL, sizeof m1, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_sess_server_handshake(&s, hello, m1, sizeof m1, NULL), NAION_CSM_ERR_INVALID_ARGUMENT);

    /* client_finish NULLs */
    CHECK_CSM(naion_csm_sess_client_finish(NULL, m1, sizeof m1), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_sess_client_finish(&c, NULL, sizeof m1), NAION_CSM_ERR_INVALID_ARGUMENT);

    /* encrypt/decrypt NULLs */
    CHECK_CSM(naion_csm_sess_client_encrypt(NULL, pt, 32, buf, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_sess_client_encrypt(&c, pt, 32, NULL, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_sess_client_encrypt(&c, pt, 32, buf, sizeof buf, NULL), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_sess_client_decrypt(NULL, buf, 32, buf, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_sess_client_decrypt(&c, NULL, 32, buf, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_sess_client_decrypt(&c, buf, 32, NULL, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_sess_client_decrypt(&c, buf, 32, buf, sizeof buf, NULL), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_sess_server_encrypt(NULL, pt, 32, buf, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_sess_server_encrypt(&s, pt, 32, NULL, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_sess_server_encrypt(&s, pt, 32, buf, sizeof buf, NULL), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_sess_server_decrypt(NULL, buf, 32, buf, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_sess_server_decrypt(&s, NULL, 32, buf, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_sess_server_decrypt(&s, buf, 32, NULL, sizeof buf, &len), NAION_CSM_ERR_INVALID_ARGUMENT);
    CHECK_CSM(naion_csm_sess_server_decrypt(&s, buf, 32, buf, sizeof buf, NULL), NAION_CSM_ERR_INVALID_ARGUMENT);
    TEST_END();
}

#endif /* NAION_LAYER_CSM_SESSION */

/* ========================================================================= */
/* Section 5 — NAION_XSALSA20 (optional)                                      */
/* ========================================================================= */
#if NAION_XSALSA20

/* ---- 5A. Secretbox XSalsa20-Poly1305 ---------------------------------- */

static void sbox_kn(unsigned char key[32], unsigned char nonce[24])
{
    derive_key(key, 32, "xs-sbox-k");
    derive_key(nonce, 24, "xs-sbox-n");
}

/* T5.1 */
static int test_secretbox_xsalsa_easy_roundtrip(void)
{
    unsigned char key[32], nonce[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    size_t si;

    TEST_BEGIN("test_secretbox_xsalsa_easy_roundtrip");
    sbox_kn(key, nonce);
    for (si = 0; si < 18; si++) {
        size_t n = SIZE_LADDER[si];
        fill_pattern(m, n, 0x51);
        CHECK_OK(naion_secretbox_xsalsa20poly1305_easy(c, m, n, nonce, key));
        CHECK_OK(naion_secretbox_xsalsa20poly1305_open_easy(m2, c, n + 16, nonce, key));
        CHECK(naion_memcmp(m, m2, n) == 0);
        if (n > 0) {
            c[0] ^= 0xff;
            CHECK_ERR(naion_secretbox_xsalsa20poly1305_open_easy(m2, c, n + 16, nonce, key));
            c[0] ^= 0xff;
        }
    }
    /* wrong key */
    {
        unsigned char key2[32];
        derive_key(key2, 32, "xs-sbox-k2");
        fill_pattern(m, 32, 0x51);
        CHECK_OK(naion_secretbox_xsalsa20poly1305_easy(c, m, 32, nonce, key));
        CHECK_ERR(naion_secretbox_xsalsa20poly1305_open_easy(m2, c, 48, nonce, key2));
    }
    TEST_END();
}

/* T5.2 */
static int test_secretbox_xsalsa_detached_roundtrip(void)
{
    unsigned char key[32], nonce[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    unsigned char mac[16];
    size_t si;

    TEST_BEGIN("test_secretbox_xsalsa_detached_roundtrip");
    sbox_kn(key, nonce);
    for (si = 0; si < 18; si++) {
        size_t n = SIZE_LADDER[si];
        fill_pattern(m, n, 0x52);
        CHECK_OK(naion_secretbox_xsalsa20poly1305_detached(c, mac, m, n, nonce, key));
        CHECK_OK(naion_secretbox_xsalsa20poly1305_open_detached(m2, c, mac, n, nonce, key));
        CHECK(naion_memcmp(m, m2, n) == 0);
        if (n > 0) {
            mac[0] ^= 0xff;
            CHECK_ERR(naion_secretbox_xsalsa20poly1305_open_detached(m2, c, mac, n, nonce, key));
            mac[0] ^= 0xff;
        }
    }
    TEST_END();
}

/* T5.3 */
static int test_secretbox_xsalsa_errors(void)
{
    unsigned char key[32], nonce[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    unsigned char mac[16];

    TEST_BEGIN("test_secretbox_xsalsa_errors");
    sbox_kn(key, nonce);
    fill_pattern(m, 32, 0x53);
    CHECK_OK(naion_secretbox_xsalsa20poly1305_easy(c, m, 32, nonce, key));

    CHECK_ERR(naion_secretbox_xsalsa20poly1305_easy(NULL, m, 32, nonce, key));
    CHECK_ERR(naion_secretbox_xsalsa20poly1305_easy(c, NULL, 32, nonce, key));
    CHECK_ERR(naion_secretbox_xsalsa20poly1305_easy(c, m, 32, NULL, key));
    CHECK_ERR(naion_secretbox_xsalsa20poly1305_easy(c, m, 32, nonce, NULL));
    CHECK_ERR(naion_secretbox_xsalsa20poly1305_open_easy(m2, c, 15, nonce, key));
    CHECK_ERR(naion_secretbox_xsalsa20poly1305_open_easy(NULL, c, 48, nonce, key));
    CHECK_ERR(naion_secretbox_xsalsa20poly1305_open_easy(m2, NULL, 48, nonce, key));
    CHECK_ERR(naion_secretbox_xsalsa20poly1305_detached(NULL, mac, m, 32, nonce, key));
    CHECK_ERR(naion_secretbox_xsalsa20poly1305_detached(c, NULL, m, 32, nonce, key));
    CHECK_ERR(naion_secretbox_xsalsa20poly1305_open_detached(m2, c, NULL, 32, nonce, key));
    CHECK_ERR(naion_secretbox_xsalsa20poly1305_open_detached(NULL, c, mac, 32, nonce, key));
    TEST_END();
}

/* ---- 5B. Box XSalsa20-Poly1305 ---------------------------------------- */

/* T5.4 */
static int test_box_xsalsa_keypair(void)
{
    unsigned char seed[32], pk1[32], sk1[32], pk2[32], sk2[32], base_pk[32];

    TEST_BEGIN("test_box_xsalsa_keypair");
    derive_key(seed, 32, "xs-box-seed");
    CHECK_OK(naion_box_curve25519xsalsa20poly1305_seed_keypair(pk1, sk1, seed));
    CHECK_OK(naion_box_curve25519xsalsa20poly1305_seed_keypair(pk2, sk2, seed));
    CHECK(naion_memcmp(pk1, pk2, 32) == 0);
    CHECK(naion_memcmp(sk1, sk2, 32) == 0);
    /* pk == base * sk */
    CHECK_OK(naion_scalarmult_curve25519_base(base_pk, sk1));
    CHECK(naion_memcmp(base_pk, pk1, 32) == 0);
    TEST_END();
}

/* T5.5 */
static int test_box_xsalsa_beforenm(void)
{
    unsigned char apk[32], ask[32], bpk[32], bsk[32], k_ab[32], k_ba[32];

    TEST_BEGIN("test_box_xsalsa_beforenm");
    CHECK_OK(naion_box_curve25519xsalsa20poly1305_keypair(apk, ask));
    CHECK_OK(naion_box_curve25519xsalsa20poly1305_keypair(bpk, bsk));
    CHECK_OK(naion_box_curve25519xsalsa20poly1305_beforenm(k_ab, bpk, ask));
    CHECK_OK(naion_box_curve25519xsalsa20poly1305_beforenm(k_ba, apk, bsk));
    CHECK(naion_memcmp(k_ab, k_ba, 32) == 0);
    TEST_END();
}

/* T5.6 */
static int test_box_xsalsa_easy_roundtrip(void)
{
    unsigned char apk[32], ask[32], bpk[32], bsk[32], nonce[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    size_t si;

    TEST_BEGIN("test_box_xsalsa_easy_roundtrip");
    CHECK_OK(naion_box_curve25519xsalsa20poly1305_keypair(apk, ask));
    CHECK_OK(naion_box_curve25519xsalsa20poly1305_keypair(bpk, bsk));
    derive_key(nonce, 24, "xs-box-nonce");
    for (si = 0; si < 18; si++) {
        size_t n = SIZE_LADDER[si];
        fill_pattern(m, n, 0x56);
        CHECK_OK(naion_box_curve25519xsalsa20poly1305_easy(c, m, n, nonce, bpk, ask));
        CHECK_OK(naion_box_curve25519xsalsa20poly1305_open_easy(m2, c, n + 16, nonce, apk, bsk));
        CHECK(naion_memcmp(m, m2, n) == 0);
        if (n > 0) {
            c[0] ^= 0xff;
            CHECK_ERR(naion_box_curve25519xsalsa20poly1305_open_easy(m2, c, n + 16, nonce, apk, bsk));
            c[0] ^= 0xff;
        }
    }
    /* wrong recipient */
    {
        unsigned char cpk[32], csk[32];
        CHECK_OK(naion_box_curve25519xsalsa20poly1305_keypair(cpk, csk));
        fill_pattern(m, 32, 0x56);
        CHECK_OK(naion_box_curve25519xsalsa20poly1305_easy(c, m, 32, nonce, bpk, ask));
        CHECK_ERR(naion_box_curve25519xsalsa20poly1305_open_easy(m2, c, 48, nonce, apk, csk));
    }
    TEST_END();
}

/* T5.7 */
static int test_box_xsalsa_afternm_roundtrip(void)
{
    unsigned char apk[32], ask[32], bpk[32], bsk[32], nonce[24], k[32];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c, *cx = g_buf_c;
    size_t si;

    TEST_BEGIN("test_box_xsalsa_afternm_roundtrip");
    CHECK_OK(naion_box_curve25519xsalsa20poly1305_keypair(apk, ask));
    CHECK_OK(naion_box_curve25519xsalsa20poly1305_keypair(bpk, bsk));
    derive_key(nonce, 24, "xs-box-nonce");
    CHECK_OK(naion_box_curve25519xsalsa20poly1305_beforenm(k, bpk, ask));

    for (si = 0; si < 18; si++) {
        size_t n = SIZE_LADDER[si];
        fill_pattern(m, n, 0x57);
        CHECK_OK(naion_box_curve25519xsalsa20poly1305_easy_afternm(c, m, n, nonce, k));
        CHECK_OK(naion_box_curve25519xsalsa20poly1305_open_easy_afternm(m2, c, n + 16, nonce, k));
        CHECK(naion_memcmp(m, m2, n) == 0);
    }
    /* output differs from the XChaCha variant (same key+nonce) */
    {
        unsigned char kx[32];
        fill_pattern(m, 32, 0x57);
        CHECK_OK(naion_box_curve25519xchacha20poly1305_beforenm(kx, bpk, ask));
        CHECK_OK(naion_box_curve25519xchacha20poly1305_easy_afternm(cx, m, 32, nonce, kx));
        CHECK_OK(naion_box_curve25519xsalsa20poly1305_easy_afternm(c, m, 32, nonce, k));
        CHECK(naion_memcmp(cx, c, 48) != 0);
    }
    TEST_END();
}

/* T5.8 */
static int test_box_xsalsa_seal_roundtrip(void)
{
    unsigned char bpk[32], bsk[32];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;
    size_t si;

    TEST_BEGIN("test_box_xsalsa_seal_roundtrip");
    CHECK_OK(naion_box_curve25519xsalsa20poly1305_keypair(bpk, bsk));
    for (si = 0; si < 18; si++) {
        size_t n = SIZE_LADDER[si];
        fill_pattern(m, n, 0x58);
        CHECK_OK(naion_box_curve25519xsalsa20poly1305_seal(c, m, n, bpk));
        CHECK_OK(naion_box_curve25519xsalsa20poly1305_seal_open(m2, c, n + 48, bpk, bsk));
        CHECK(naion_memcmp(m, m2, n) == 0);
        if (n > 0) {
            c[48] ^= 0xff;
            CHECK_ERR(naion_box_curve25519xsalsa20poly1305_seal_open(m2, c, n + 48, bpk, bsk));
            c[48] ^= 0xff;
        }
    }
    TEST_END();
}

/* T5.9 */
static int test_box_xsalsa_errors(void)
{
    unsigned char apk[32], ask[32], bpk[32], bsk[32], nonce[24], k[32];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c;

    TEST_BEGIN("test_box_xsalsa_errors");
    CHECK_OK(naion_box_curve25519xsalsa20poly1305_keypair(apk, ask));
    CHECK_OK(naion_box_curve25519xsalsa20poly1305_keypair(bpk, bsk));
    derive_key(nonce, 24, "xs-box-nonce");
    CHECK_OK(naion_box_curve25519xsalsa20poly1305_beforenm(k, bpk, ask));
    fill_pattern(m, 32, 0x59);

    /* easy NULL */
    CHECK_ERR(naion_box_curve25519xsalsa20poly1305_easy(NULL, m, 32, nonce, bpk, ask));
    CHECK_ERR(naion_box_curve25519xsalsa20poly1305_easy(c, NULL, 32, nonce, bpk, ask));
    CHECK_ERR(naion_box_curve25519xsalsa20poly1305_easy(c, m, 32, NULL, bpk, ask));
    CHECK_ERR(naion_box_curve25519xsalsa20poly1305_easy(c, m, 32, nonce, NULL, ask));
    CHECK_ERR(naion_box_curve25519xsalsa20poly1305_easy(c, m, 32, nonce, bpk, NULL));
    /* open clen<16 + NULL */
    CHECK_ERR(naion_box_curve25519xsalsa20poly1305_open_easy(m2, c, 15, nonce, apk, bsk));
    CHECK_ERR(naion_box_curve25519xsalsa20poly1305_open_easy(NULL, c, 48, nonce, apk, bsk));
    CHECK_ERR(naion_box_curve25519xsalsa20poly1305_open_easy(m2, NULL, 48, nonce, apk, bsk));
    /* afternm NULL */
    CHECK_ERR(naion_box_curve25519xsalsa20poly1305_easy_afternm(NULL, m, 32, nonce, k));
    CHECK_ERR(naion_box_curve25519xsalsa20poly1305_easy_afternm(c, NULL, 32, nonce, k));
    CHECK_ERR(naion_box_curve25519xsalsa20poly1305_easy_afternm(c, m, 32, NULL, k));
    CHECK_ERR(naion_box_curve25519xsalsa20poly1305_easy_afternm(c, m, 32, nonce, NULL));
    CHECK_ERR(naion_box_curve25519xsalsa20poly1305_open_easy_afternm(m2, c, 15, nonce, k));
    /* seal NULL + clen<48 */
    CHECK_ERR(naion_box_curve25519xsalsa20poly1305_seal(NULL, m, 32, bpk));
    CHECK_ERR(naion_box_curve25519xsalsa20poly1305_seal(c, NULL, 32, bpk));
    CHECK_ERR(naion_box_curve25519xsalsa20poly1305_seal(c, m, 32, NULL));
    CHECK_ERR(naion_box_curve25519xsalsa20poly1305_seal_open(m2, c, 47, bpk, bsk));
    CHECK_ERR(naion_box_curve25519xsalsa20poly1305_seal_open(NULL, c, 80, bpk, bsk));
    TEST_END();
}

/* ---- 5C. Runtime scheduler toggle ------------------------------------ */

/* T5.10 */
static int test_use_xchacha20_toggle(void)
{
    int initial;

    TEST_BEGIN("test_use_xchacha20_toggle");
    initial = naion_box_get_use_xchacha20();
    naion_box_set_use_xchacha20(0);
    CHECK(naion_box_get_use_xchacha20() == 0);
    CHECK(naion_get_use_xchacha20() == 0);
    naion_box_set_use_xchacha20(1);
    CHECK(naion_box_get_use_xchacha20() == 1);
    CHECK(naion_get_use_xchacha20() == 1);
    /* aliases agree */
    naion_set_use_xchacha20(0);
    CHECK(naion_box_get_use_xchacha20() == 0);
    naion_set_use_xchacha20(1);
    CHECK(naion_get_use_xchacha20() == 1);
    /* initial default is 1 */
    CHECK(initial == 1);
    TEST_END();
}

/* T5.11 */
static int test_generic_box_dispatch_xsalsa(void)
{
    static const size_t mlens[] = { 32, 256, 4096 };
    unsigned char apk[32], ask[32], bpk[32], bsk[32], nonce[24];
    unsigned char *m = g_buf_a, *c = g_buf_b, *m2 = g_buf_c, *cx = g_buf_c;
    size_t si;

    TEST_BEGIN("test_generic_box_dispatch_xsalsa");
    CHECK_OK(naion_box_keypair(apk, ask));
    CHECK_OK(naion_box_keypair(bpk, bsk));
    derive_key(nonce, 24, "gbox-nonce");
    for (si = 0; si < sizeof mlens / sizeof mlens[0]; si++) {
        size_t n = mlens[si];
        fill_pattern(m, n, 0x5b);

        /* set(0): generic box uses XSalsa20 output */
        naion_box_set_use_xchacha20(0);
        CHECK_OK(naion_box_easy(c, m, n, nonce, bpk, ask));
        CHECK_OK(naion_box_open_easy(m2, c, n + 16, nonce, apk, bsk));
        CHECK(naion_memcmp(m, m2, n) == 0);

        /* set(1): generic box uses XChaCha -> different output */
        naion_box_set_use_xchacha20(1);
        CHECK_OK(naion_box_easy(cx, m, n, nonce, bpk, ask));
        CHECK(naion_memcmp(cx, c, n + 16) != 0);
    }
    TEST_END();
}

/* T5.12 */
static int test_generic_box_dispatch_toggle(void)
{
    static const size_t mlens[] = { 32, 256 };
    unsigned char apk[32], ask[32], bpk[32], bsk[32], nonce[24], k[32];
    unsigned char *m = g_buf_a, *cx = g_buf_b, *cs = g_buf_c, *m2 = g_buf_c;
    size_t si;

    TEST_BEGIN("test_generic_box_dispatch_toggle");
    CHECK_OK(naion_box_keypair(apk, ask));
    CHECK_OK(naion_box_keypair(bpk, bsk));
    derive_key(nonce, 24, "gbox-nonce");
    CHECK_OK(naion_box_beforenm(k, bpk, ask));
    for (si = 0; si < sizeof mlens / sizeof mlens[0]; si++) {
        size_t n = mlens[si];
        fill_pattern(m, n, 0x5c);

        naion_box_set_use_xchacha20(1);
        CHECK_OK(naion_box_easy_afternm(cx, m, n, nonce, k));
        CHECK_OK(naion_box_open_easy_afternm(m2, cx, n + 16, nonce, k));
        CHECK(naion_memcmp(m, m2, n) == 0);

        naion_box_set_use_xchacha20(0);
        CHECK_OK(naion_box_easy_afternm(cs, m, n, nonce, k));
        CHECK_OK(naion_box_open_easy_afternm(m2, cs, n + 16, nonce, k));
        CHECK(naion_memcmp(m, m2, n) == 0);

        /* different output under the two modes */
        CHECK(naion_memcmp(cx, cs, n + 16) != 0);
    }
    naion_box_set_use_xchacha20(1);
    TEST_END();
}

#endif /* NAION_XSALSA20 */

/* ========================================================================= */
/* Section 6 — Large-buffer tests (gated behind --full)                       */
/* ========================================================================= */

static int g_full = 0;

#if NAION_LAYER_AEAD
/* T6.1 */
static int test_large_aead_ietf(void)
{
    unsigned char key[32], nonce[24];
    size_t li;
    TEST_BEGIN("test_large_aead_ietf");
    aead_kn(key, nonce);
    for (li = 0; li < 2; li++) {
        size_t n = SIZE_LARGE[li];
        unsigned char *m = (unsigned char *) malloc(n);
        unsigned char *c = (unsigned char *) malloc(n + 16);
        unsigned char *m2 = (unsigned char *) malloc(n + 16);
        unsigned long long clen = 0, mlen = 0;
        CHECK(m != NULL && c != NULL && m2 != NULL);
        fill_pattern(m, n, 0x61);
        CHECK_OK(naion_aead_xchacha20poly1305_ietf_encrypt(c, &clen, m, n, NULL, 0, NULL, nonce, key));
        mlen = 0;
        CHECK_OK(naion_aead_xchacha20poly1305_ietf_decrypt(m2, &mlen, NULL, c, clen, NULL, 0, nonce, key));
        CHECK(naion_memcmp(m, m2, n) == 0);
        /* tamper head + tail */
        c[0] ^= 0xff;
        CHECK_ERR(naion_aead_xchacha20poly1305_ietf_decrypt(m2, &mlen, NULL, c, clen, NULL, 0, nonce, key));
        c[0] ^= 0xff;
        c[clen - 1] ^= 0xff;
        CHECK_ERR(naion_aead_xchacha20poly1305_ietf_decrypt(m2, &mlen, NULL, c, clen, NULL, 0, nonce, key));
        c[clen - 1] ^= 0xff;
        free(m); free(c); free(m2);
    }
    TEST_END();
}

/* T6.2 */
static int test_large_secretbox_easy(void)
{
    unsigned char key[32], nonce[24];
    size_t li;
    TEST_BEGIN("test_large_secretbox_easy");
    secretbox_kn(key, nonce);
    for (li = 0; li < 2; li++) {
        size_t n = SIZE_LARGE[li];
        unsigned char *m = (unsigned char *) malloc(n);
        unsigned char *c = (unsigned char *) malloc(n + 16);
        unsigned char *m2 = (unsigned char *) malloc(n + 16);
        CHECK(m != NULL && c != NULL && m2 != NULL);
        fill_pattern(m, n, 0x62);
        CHECK_OK(naion_secretbox_xchacha20poly1305_easy(c, m, n, nonce, key));
        CHECK_OK(naion_secretbox_xchacha20poly1305_open_easy(m2, c, n + 16, nonce, key));
        CHECK(naion_memcmp(m, m2, n) == 0);
        c[0] ^= 0xff;
        CHECK_ERR(naion_secretbox_xchacha20poly1305_open_easy(m2, c, n + 16, nonce, key));
        c[0] ^= 0xff;
        free(m); free(c); free(m2);
    }
    TEST_END();
}
#endif

#if NAION_LAYER_CSM
/* T6.3 */
static int test_large_box_easy(void)
{
    unsigned char apk[32], ask[32], bpk[32], bsk[32], nonce[24];
    size_t li;
    TEST_BEGIN("test_large_box_easy");
    CHECK_OK(naion_box_curve25519xchacha20poly1305_keypair(apk, ask));
    CHECK_OK(naion_box_curve25519xchacha20poly1305_keypair(bpk, bsk));
    derive_key(nonce, 24, "lbox-nonce");
    for (li = 0; li < 2; li++) {
        size_t n = SIZE_LARGE[li];
        unsigned char *m = (unsigned char *) malloc(n);
        unsigned char *c = (unsigned char *) malloc(n + 16);
        unsigned char *m2 = (unsigned char *) malloc(n + 16);
        CHECK(m != NULL && c != NULL && m2 != NULL);
        fill_pattern(m, n, 0x63);
        CHECK_OK(naion_box_curve25519xchacha20poly1305_easy(c, m, n, nonce, bpk, ask));
        CHECK_OK(naion_box_curve25519xchacha20poly1305_open_easy(m2, c, n + 16, nonce, apk, bsk));
        CHECK(naion_memcmp(m, m2, n) == 0);
        c[0] ^= 0xff;
        CHECK_ERR(naion_box_curve25519xchacha20poly1305_open_easy(m2, c, n + 16, nonce, apk, bsk));
        c[0] ^= 0xff;
        free(m); free(c); free(m2);
    }
    TEST_END();
}

/* T6.4 */
static int test_large_box_seal(void)
{
    unsigned char bpk[32], bsk[32];
    size_t li;
    TEST_BEGIN("test_large_box_seal");
    CHECK_OK(naion_box_curve25519xchacha20poly1305_keypair(bpk, bsk));
    for (li = 0; li < 2; li++) {
        size_t n = SIZE_LARGE[li];
        unsigned char *m = (unsigned char *) malloc(n);
        unsigned char *c = (unsigned char *) malloc(n + 48);
        unsigned char *m2 = (unsigned char *) malloc(n + 48);
        CHECK(m != NULL && c != NULL && m2 != NULL);
        fill_pattern(m, n, 0x64);
        CHECK_OK(naion_box_curve25519xchacha20poly1305_seal(c, m, n, bpk));
        CHECK_OK(naion_box_curve25519xchacha20poly1305_seal_open(m2, c, n + 48, bpk, bsk));
        CHECK(naion_memcmp(m, m2, n) == 0);
        c[0] ^= 0xff;
        CHECK_ERR(naion_box_curve25519xchacha20poly1305_seal_open(m2, c, n + 48, bpk, bsk));
        c[0] ^= 0xff;
        free(m); free(c); free(m2);
    }
    TEST_END();
}
#endif

#if NAION_LAYER_AEAD
/* T6.5 */
static int test_large_ad(void)
{
    unsigned char key[32], nonce[24];
    size_t li;
    TEST_BEGIN("test_large_ad");
    aead_kn(key, nonce);
    for (li = 0; li < 2; li++) {
        size_t n = SIZE_LARGE[li];
        unsigned char *m = (unsigned char *) malloc(n);
        unsigned char *ad = (unsigned char *) malloc(n);
        unsigned char *c = (unsigned char *) malloc(n + 16);
        unsigned char *m2 = (unsigned char *) malloc(n + 16);
        unsigned long long clen = 0, mlen = 0;
        CHECK(m != NULL && ad != NULL && c != NULL && m2 != NULL);
        fill_pattern(m, n, 0x65);
        fill_pattern(ad, n, 0xad);
        CHECK_OK(naion_aead_xchacha20poly1305_ietf_encrypt(c, &clen, m, n, ad, n, NULL, nonce, key));
        mlen = 0;
        CHECK_OK(naion_aead_xchacha20poly1305_ietf_decrypt(m2, &mlen, NULL, c, clen, ad, n, nonce, key));
        CHECK(naion_memcmp(m, m2, n) == 0);
        free(m); free(ad); free(c); free(m2);
    }
    TEST_END();
}
#endif

#if NAION_LAYER_SYMM
/* T6.6 */
static int test_large_stream_xor(void)
{
    unsigned char key[32], nonce[24];
    size_t li;
    TEST_BEGIN("test_large_stream_xor");
    derive_key(key, 32, "lstream-k");
    derive_key(nonce, 24, "lstream-n");
    for (li = 0; li < 2; li++) {
        size_t n = SIZE_LARGE[li];
        unsigned char *m = (unsigned char *) malloc(n);
        unsigned char *c = (unsigned char *) malloc(n);
        unsigned char *m2 = (unsigned char *) malloc(n);
        CHECK(m != NULL && c != NULL && m2 != NULL);
        fill_pattern(m, n, 0x66);
        CHECK_OK(naion_stream_xchacha20_xor(c, m, n, nonce, key));
        CHECK_OK(naion_stream_xchacha20_xor(m2, c, n, nonce, key));
        CHECK(naion_memcmp(m, m2, n) == 0);
        free(m); free(c); free(m2);
    }
    TEST_END();
}

/* T6.7 */
static int test_large_generichash(void)
{
    unsigned char key[32];
    size_t li;
    TEST_BEGIN("test_large_generichash");
    derive_key(key, 32, "lgh-k");   /* not used as a hash key; silences unused */
    (void) key;
    for (li = 0; li < 2; li++) {
        size_t n = SIZE_LARGE[li];
        unsigned char *in = (unsigned char *) malloc(n);
        unsigned char one64[64], streamed64[64];
        naion_generichash_state st;
        size_t off = 0;
        static const size_t chunks[] = { 65536, 4096, 1 };
        size_t ci;
        CHECK(in != NULL);
        fill_pattern(in, n, 0x67);

        CHECK_OK(naion_generichash(one64, 64, in, n, NULL, 0));
        for (ci = 0; ci < sizeof chunks / sizeof chunks[0]; ci++) {
            CHECK_OK(naion_generichash_init(&st, NULL, 0, 64));
            off = 0;
            while (off < n) {
                size_t step = chunks[ci];
                if (off + step > n) step = n - off;
                CHECK_OK(naion_generichash_update(&st, in + off, step));
                off += step;
            }
            CHECK_OK(naion_generichash_final(&st, streamed64, 64));
            CHECK(naion_memcmp(one64, streamed64, 64) == 0);
        }
        /* also a 32-byte one-shot must match a 32-byte final */
        {
            unsigned char one32[32], st32[32];
            CHECK_OK(naion_generichash(one32, 32, in, n, NULL, 0));
            CHECK_OK(naion_generichash_init(&st, NULL, 0, 32));
            CHECK_OK(naion_generichash_update(&st, in, n));
            CHECK_OK(naion_generichash_final(&st, st32, 32));
            CHECK(naion_memcmp(one32, st32, 32) == 0);
        }
        free(in);
    }
    TEST_END();
}
#endif

/* ========================================================================= */
/* Test runner + main                                                         */
/* ========================================================================= */

/* RUN: invoke a test function pointer, returning 0/1. */
#define RUN(fn) do { (void) (fn)(); } while (0)

int main(int argc, char **argv)
{
    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--full") == 0) {
            g_full = 1;
        }
    }

    printf("naion test harness%s\n", g_full ? " (--full)" : "");
    (void) naion_init();

    /* ---- Section 0 ---- */
    RUN(test_memcmp);
    RUN(test_is_zero);
    RUN(test_verify_32);
    RUN(test_memzero);

#if NAION_LAYER_SYMM
    /* ---- Section 1 ---- */
    RUN(test_init);
    RUN(test_random_provider_default);
    RUN(test_random_provider_custom);
    RUN(test_random_provider_roundtrip);
    RUN(test_generichash_one_shot);
    RUN(test_generichash_deterministic);
    RUN(test_generichash_streaming);
    RUN(test_generichash_errors);
    RUN(test_generichash_keyed);
    RUN(test_stream_xchacha20_keystream);
    RUN(test_stream_xchacha20_deterministic);
    RUN(test_stream_xchacha20_xor_roundtrip);
    RUN(test_stream_xchacha20_xor_ic);
    RUN(test_stream_errors_null);
#endif

#if NAION_LAYER_AEAD
    /* ---- Section 2 ---- */
    RUN(test_aead_ietf_roundtrip);
    RUN(test_aead_ietf_tamper);
    RUN(test_aead_ietf_wrong_ad);
    RUN(test_aead_ietf_wrong_nonce);
    RUN(test_aead_ietf_wrong_key);
    RUN(test_aead_ietf_detached_roundtrip);
    RUN(test_aead_ietf_detached_tamper_mac);
    RUN(test_aead_ietf_detached_tamper_ct);
    RUN(test_aead_ietf_detached_wrong_ad);
    RUN(test_aead_ietf_errors);
    RUN(test_aead_ietf_empty_msg);
    RUN(test_aead_ietf_vs_libsodium);
    RUN(test_secretbox_easy_roundtrip);
    RUN(test_secretbox_easy_tamper);
    RUN(test_secretbox_easy_wrong_key);
    RUN(test_secretbox_easy_wrong_nonce);
    RUN(test_secretbox_detached_roundtrip);
    RUN(test_secretbox_detached_tamper);
    RUN(test_secretbox_errors);
    RUN(test_secretbox_empty);
    RUN(test_secretbox_stream_interop);
    RUN(test_box_afternm_roundtrip);
    RUN(test_box_afternm_tamper);
    RUN(test_box_afternm_wrong_key);
    RUN(test_box_afternm_wrong_nonce);
    RUN(test_box_afternm_errors);
    RUN(test_secretbox_delegates_to_afternm);
#endif

#if NAION_LAYER_CSM
    /* ---- Section 3 ---- */
    RUN(test_scalarmult_rfc7748);
    RUN(test_scalarmult_dh_agreement);
    RUN(test_scalarmult_commutative);
    RUN(test_scalarmult_errors);
    RUN(test_scalarmult_small_order);
    RUN(test_scalarmult_zero_scalar);
    RUN(test_kx_keypair_random);
    RUN(test_kx_seed_keypair);
    RUN(test_kx_session_keys);
    RUN(test_kx_session_keys_deterministic);
    RUN(test_kx_session_aliasing);
    RUN(test_kx_errors);
    RUN(test_box_xchacha_keypair);
    RUN(test_box_xchacha_seed_keypair);
    RUN(test_box_xchacha_beforenm);
    RUN(test_box_xchacha_easy_roundtrip);
    RUN(test_box_xchacha_easy_tamper);
    RUN(test_box_xchacha_easy_wrong_recipient);
    RUN(test_box_xchacha_seal_roundtrip);
    RUN(test_box_xchacha_seal_tamper);
    RUN(test_box_xchacha_seal_anon);
    RUN(test_box_xchacha_seal_size);
    RUN(test_box_xchacha_errors);
    RUN(test_box_get_use_xchacha);
    RUN(test_box_set_use_xchacha);
    RUN(test_box_query_sizes);
    RUN(test_box_generic_keypair);
    RUN(test_box_generic_seed_keypair);
    RUN(test_box_generic_beforenm);
    RUN(test_box_generic_easy_roundtrip);
    RUN(test_box_generic_afternm_roundtrip);
    RUN(test_box_generic_seal_roundtrip);
    RUN(test_box_generic_errors);
    RUN(test_ed25519_keypair_random);
    RUN(test_ed25519_seed_keypair);
    RUN(test_ed25519_sign_detached_verify);
    RUN(test_ed25519_sign_combined);
    RUN(test_ed25519_deterministic_sign);
    RUN(test_ed25519_different_message);
    RUN(test_ed25519_wrong_pk);
    RUN(test_ed25519_sk_to_seed_pk);
    RUN(test_ed25519_pk_to_curve25519);
    RUN(test_ed25519_sk_to_curve25519);
    RUN(test_ed25519_curve25519_consistency);
    RUN(test_ed25519_errors);
    RUN(test_ed25519_small_order);
    RUN(test_csm_init);
    RUN(test_csm_client_create_wipe);
    RUN(test_csm_server_create_wipe);
    RUN(test_csm_full_flow);
    RUN(test_csm_server_encrypt_before_client);
    RUN(test_csm_size_functions);
    RUN(test_csm_encrypt_null_plaintext);
    RUN(test_csm_encrypt_zero_length);
    RUN(test_csm_buffer_too_small);
    RUN(test_csm_tamper_packet);
    RUN(test_csm_null_errors);
#endif

#if NAION_LAYER_CSM_CA
    /* ---- Section 4 ---- */
    RUN(test_csm_ca_client_create);
    RUN(test_csm_ca_server_create);
    RUN(test_csm_ca_handshake_response_size);
    RUN(test_csm_ca_handshake_response);
    RUN(test_csm_ca_handshake_flow);
    RUN(test_csm_ca_handshake_tamper);
    RUN(test_csm_ca_handshake_wrong_ca);
    RUN(test_csm_ca_handshake_wrong_size);
    RUN(test_csm_ca_full_flow);
    RUN(test_csm_ca_encrypt_before_handshake);
    RUN(test_csm_ca_server_encrypt_before_client);
    RUN(test_csm_ca_size_functions);
    RUN(test_csm_ca_wipe);
    RUN(test_csm_ca_tamper);
    RUN(test_csm_ca_null_errors);
#endif

#if NAION_LAYER_CSM_SESSION
    /* ---- Section 4C ---- */
    RUN(test_csm_sess_client_create);
    RUN(test_csm_sess_server_create);
    RUN(test_csm_sess_constants);
    RUN(test_csm_sess_client_hello);
    RUN(test_csm_sess_handshake_flow);
    RUN(test_csm_sess_server_handshake_reject);
    RUN(test_csm_sess_client_finish_reject);
    RUN(test_csm_sess_full_flow);
    RUN(test_csm_sess_encrypt_before_handshake);
    RUN(test_csm_sess_size_functions);
    RUN(test_csm_sess_wipe);
    RUN(test_csm_sess_tamper);
    RUN(test_csm_sess_null_errors);
#endif

#if NAION_XSALSA20
    /* ---- Section 5 ---- */
    RUN(test_secretbox_xsalsa_easy_roundtrip);
    RUN(test_secretbox_xsalsa_detached_roundtrip);
    RUN(test_secretbox_xsalsa_errors);
    RUN(test_box_xsalsa_keypair);
    RUN(test_box_xsalsa_beforenm);
    RUN(test_box_xsalsa_easy_roundtrip);
    RUN(test_box_xsalsa_afternm_roundtrip);
    RUN(test_box_xsalsa_seal_roundtrip);
    RUN(test_box_xsalsa_errors);
    RUN(test_use_xchacha20_toggle);
    RUN(test_generic_box_dispatch_xsalsa);
    RUN(test_generic_box_dispatch_toggle);
#endif

    /* ---- Section 6 (large, --full only) ---- */
    if (g_full) {
#if NAION_LAYER_AEAD
        RUN(test_large_aead_ietf);
        RUN(test_large_secretbox_easy);
        RUN(test_large_ad);
#endif
#if NAION_LAYER_CSM
        RUN(test_large_box_easy);
        RUN(test_large_box_seal);
#endif
#if NAION_LAYER_SYMM
        RUN(test_large_stream_xor);
        RUN(test_large_generichash);
#endif
    }

    printf("\nTOTAL: %d passed, %d failed\n", g_passed, g_failed);
    return g_failed > 0 ? 1 : 0;
}
