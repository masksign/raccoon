//  nist_random.c
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//  === Provides randombytes() compatible with AES-based NIST rng.

#ifndef NIST_KAT
//  (only if the original generator is not used)

#include <string.h>
#include "nist_random.h"

//  shared random generator

aes256_ctr_drbg_t aesdrbg_global_ctx = {0};

//  (not constant time )

static inline void aesdrbg_inc_ctr(uint8_t ctr[16])
{
    int i;
    uint32_t x;

    x = 1;

    for (i = 15; i >= 0; i--) {
        x += (uint32_t)ctr[i];
        ctr[i] = (uint8_t)x;
        x >>= 8;
    }
}

static void aesdrbg_update(aes256_ctr_drbg_t *ctx, const uint8_t *input48)
{
    size_t i;
    uint8_t tmp[48];

    for (i = 0; i < 48; i += 16) {
        aesdrbg_inc_ctr(ctx->ctr);
        aes256_enc_ecb(tmp + i, ctx->ctr, ctx->rk);
    }
    if (input48 != NULL) {
        for (i = 0; i < 48; i++)
            tmp[i] ^= input48[i];
    }
    memcpy(ctx->key, tmp, 32);
    memcpy(ctx->ctr, tmp + 32, 16);
    aes256_enc_key(ctx->rk, ctx->key);
}

void aes256ctr_xof_init(aes256_ctr_drbg_t *ctx, const uint8_t *input48)
{
    memset(ctx->key, 0x00, 32);
    memset(ctx->ctr, 0x00, 16);
    aes256_enc_key(ctx->rk, ctx->key);

    aesdrbg_update(ctx, input48);
}

int aes256ctr_xof(void *ctx, void *buf, size_t len)
{
    uint8_t tmp[16];
    aes256_ctr_drbg_t *drbg = ctx;
    uint8_t *x = buf;

    while (len > 0) {
        // increment ctr
        aesdrbg_inc_ctr(drbg->ctr);
        aes256_enc_ecb(tmp, drbg->ctr, drbg->rk);

        if (len > 15) {
            memcpy(x, tmp, 16);
            x += 16;
            len -= 16;
        } else {
            memcpy(x, tmp, len);
            len = 0;
        }
    }
    aesdrbg_update(drbg, NULL);

    return 0;
}

//  nist test vector initialize

void nist_randombytes_init(const uint8_t entropy_input[48],
                      const uint8_t personalization_string[48],
                      int security_strength)
{
    (void)(security_strength);  //  not used
    uint8_t seed[48];

    if (personalization_string != NULL) {
        for (size_t i = 0; i < 48; i++) {
            seed[i] = entropy_input[i] ^ personalization_string[i];
        }
        entropy_input = seed;
    }

    aes256ctr_xof_init(&aesdrbg_global_ctx, entropy_input);
}

//  nist test vector generator

int nist_randombytes(uint8_t *x, size_t xlen)
{
    return aes256ctr_xof(&aesdrbg_global_ctx, x, xlen);
}

//  NIST_KAT
#endif
