//  keccakf1600.h
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//  === Raw Keccak f-1600 interface.

#ifndef _KECCAKF1600_H_
#define _KECCAKF1600_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "plat_local.h"

//  == low-level interface, keccakf1600.c or native

//  clear the state
void keccak_clear(uint64_t state[25]);

//  FIPS 202 Keccak f1600 permutation, 24 rounds
void keccak_f1600(uint64_t state[25]);

//  extract "rate" bytes from state
void keccak_extract(uint64_t* state, uint8_t* data, size_t rate);

//  absorb "rate" bytes via xor into the state
void keccak_xorbytes(uint64_t* state, const uint8_t* data, size_t rate);

#ifdef __cplusplus
}
#endif

#endif  //  _KECCAKF1600_H_
