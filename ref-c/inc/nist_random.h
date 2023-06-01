//  nist_random.h
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//  === A "NIST-compatible" DRBG API

#ifndef _NIST_RANDOM_H_
#define _NIST_RANDOM_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef NIST_KAT

//  use the original version!
#include "../nist/rng.h"

#else
//  use the built-in version
#include "test_aes1kt.h"

typedef struct {
    uint8_t key[32];
    uint8_t ctr[16];
    uint32_t rk[AES256_RK_WORDS];
} aes256_ctr_drbg_t;

extern aes256_ctr_drbg_t aesdrbg_global_ctx;

//  generic random interface

void nist_randombytes_init(const uint8_t entropy_input[48],
                      const uint8_t personalization_string[48],
                      int security_strength);

int nist_randombytes(uint8_t *x, size_t xlen);

//  seed expander

void aes256ctr_xof_init(aes256_ctr_drbg_t *ctx, const uint8_t *input48);

#define randombytes(v, len) nist_randombytes(v, len)

//  NIST_KAT
#endif

#ifdef __cplusplus
}
#endif

//  _NIST_RANDOM_H_
#endif
