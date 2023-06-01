//  xof_sample.h
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//  === Raccoon signature scheme -- Samplers and XOF functions

#ifndef _XOF_SAMPLE_H_
#define _XOF_SAMPLE_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "racc_param.h"

//  === Global namespace prefix
#ifdef RACC_
#define xof_sample_q    RACC_(xof_sample_q)
#define xof_sample_u    RACC_(xof_sample_u)
#define xof_chal_mu     RACC_(xof_chal_mu)
#define xof_chal_hash   RACC_(xof_chal_hash)
#define xof_chal_poly   RACC_(xof_chal_poly)
#endif

#ifdef __cplusplus
extern "C" {
#endif

//  Compute mu = H(tr, m) where tr = H(pk), "m" is message of "m_sz" bytes.
void xof_chal_mu(   uint8_t mu[RACC_MU_SZ], const uint8_t tr[RACC_TR_SZ],
                    const uint8_t *m, size_t m_sz);

//  Expand "seed" of "seed_sz" bytes to a uniform polynomial (mod q).
//  The input seed is assumed to alredy contain domain separation.
void xof_sample_q(int64_t r[RACC_N], const uint8_t *seed, size_t seed_sz);

//  Sample "bits"-wide signed coefficients from "seed[seed_sz]".
//  The input seed is assumed to alredy contain domain separation.
void xof_sample_u(int64_t r[RACC_N], int bits,
                  const uint8_t *seed, size_t seed_sz);

//  Hash "w" vector with "mu" to produce challenge hash "ch".
void xof_chal_hash( uint8_t ch[RACC_CH_SZ], const uint8_t mu[RACC_MU_SZ],
                    const int64_t w[RACC_K][RACC_N]);

//  Create a challenge polynomial "cp" from a challenge hash "ch".
void xof_chal_poly( int64_t cp[RACC_N], const uint8_t ch[RACC_CH_SZ]);


#ifdef __cplusplus
}
#endif

//  _XOF_SAMPLE_H_
#endif
