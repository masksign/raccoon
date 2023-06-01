//  test_aes1kt.h
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//  === AES 128/192/256 block encryption for NIST test vector generation.

#ifndef _TEST_AES1KT_H_
#define _TEST_AES1KT_H_
#ifdef __cplusplus
extern "C" {
#endif

#include "plat_local.h"

//  instantiate these if you include this header file
#define aes128_enc_key aes1kt128_enc_key
#define aes192_enc_key aes1kt192_enc_key
#define aes256_enc_key aes1kt256_enc_key
#define aes128_enc_ecb aes1kt128_enc_ecb
#define aes192_enc_ecb aes1kt192_enc_ecb
#define aes256_enc_ecb aes1kt256_enc_ecb
#define aes_enc_rounds aes1kt_enc_rounds

//  number of rounds
#define AES128_ROUNDS 10
#define AES192_ROUNDS 12
#define AES256_ROUNDS 14

//  expanded key size
#define AES128_RK_WORDS (4 * (AES128_ROUNDS + 1))
#define AES192_RK_WORDS (4 * (AES192_ROUNDS + 1))
#define AES256_RK_WORDS (4 * (AES256_ROUNDS + 1))

//  Set encryption key

void aes1kt128_enc_key(uint32_t rk[AES128_RK_WORDS], const uint8_t key[16]);

void aes1kt192_enc_key(uint32_t rk[AES192_RK_WORDS], const uint8_t key[24]);

void aes1kt256_enc_key(uint32_t rk[AES256_RK_WORDS], const uint8_t key[32]);

//  Encrypt a block

void aes1kt128_enc_ecb(uint8_t ct[16], const uint8_t pt[16],
                        const uint32_t rk[AES128_RK_WORDS]);

void aes1kt192_enc_ecb(uint8_t ct[16], const uint8_t pt[16],
                        const uint32_t rk[AES192_RK_WORDS]);

void aes1kt256_enc_ecb(uint8_t ct[16], const uint8_t pt[16],
                        const uint32_t rk[AES256_RK_WORDS]);

//  Sometimes you want to cover all versions with same code

void aes1kt_enc_rounds(uint8_t ct[16], const uint8_t pt[16],
                        const uint32_t rk[], int nr);

#ifdef __cplusplus
}
#endif

#endif  //  _TEST_AES1KT_H_
