//  mask_random.h
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//  === Mask random generator interface (dummy implementations)

#ifndef _MASK_RANDOM_H_
#define _MASK_RANDOM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include "racc_param.h"

#if RACC_D > 1

//  We are "simulating" having d-1 independent generators with these PRNGs.
//  This is done to illustrate API / hardware architectural considerations.

typedef struct {
#ifdef MASK_RANDOM_ASCON
    uint64_t s[RACC_D - 1][5];  //  Ascon state
#else
    uint64_t s[RACC_D - 1][2];  //  LFSR-127 state
#endif
} mask_random_t;

//  trivial self-test; return 0 if ok
int mask_random_selftest();

//  initialize. set seed=NULL to reset. seed_sz bound to 16/36 bytes currently
void mask_random_init(mask_random_t *mrg);

//  get a 64-bit random number -- generator 0 <= ri < d-1
uint64_t mask_rand64(mask_random_t *mrg, size_t ri);

//  create a uniform random polynomial -- generator 0 <= ri < d-1
void mask_random_poly(mask_random_t *mrg, int64_t *r, size_t ri);

//  === no masking
#else

typedef int mask_random_t;
#define mask_random_selftest()  0
#define mask_random_init(mrg)
#define mask_random_poly(mrg, r, ri)
#endif

#ifdef __cplusplus
}
#endif

//  _MASK_RANDOM_H_
#endif

