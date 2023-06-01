//  sha3_t.c
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//  === Common wrappers for  SHA3 (FIPS 202) functionality.

#include <string.h>

#include "sha3_t.h"
#include "keccakf1600.h"

//  Initialize the Keccak context "kec" for algorithm-specific rate "r".

void sha3_init(sha3_t* kec, size_t r)
{
    keccak_clear(kec->s);
    kec->i = 0;
    kec->r = r;
}

//  Absorb "m_sz" bytes from "m" into the Keccak context "kec".

void sha3_absorb(sha3_t* kec, const uint8_t* m, size_t m_sz)
{
    size_t l;

    l = kec->r - kec->i;
    if (m_sz < l) {
        memcpy(kec->b + kec->i, m, m_sz);
        kec->i += m_sz;
        return;
    }
    if (kec->i > 0) {
        memcpy(kec->b + kec->i, m, l);
        keccak_xorbytes(kec->s, kec->b, kec->r);
        keccak_f1600(kec->s);
        m_sz -= l;
        m += l;
        kec->i = 0;
    }
    while (m_sz >= kec->r) {
        keccak_xorbytes(kec->s, m, kec->r);
        keccak_f1600(kec->s);
        m_sz -= kec->r;
        m += kec->r;
    }
    memcpy(kec->b, m, m_sz);
    kec->i = m_sz;
}

//  Move from absorb phase to squeeze phase and add a padding byte "p".

void sha3_pad(sha3_t* kec, uint8_t p)
{
    kec->b[kec->i++] = p;
    memset(kec->b + kec->i, 0, kec->r - kec->i);
    kec->b[kec->r - 1] |= 0x80;
    keccak_xorbytes(kec->s, kec->b, kec->r);
    kec->i = kec->r;
}

//  Squeeze "h_sz" bytes to address "h" from Keccak context "kec".

void sha3_squeeze(sha3_t* kec, uint8_t* h, size_t h_sz)
{
    size_t l;

    while (h_sz > 0) {
        if (kec->i >= kec->r) {
            keccak_f1600(kec->s);
            keccak_extract(kec->s, kec->b, kec->r);
            kec->i = 0;
        }
        l = kec->r - kec->i;
        if (h_sz <= l) {
            memcpy(h, kec->b + kec->i, h_sz);
            kec->i += h_sz;
            return;
        }
        memcpy(h, kec->b + kec->i, l);
        h += l;
        h_sz -= l;
        kec->i += l;
    }
}

//  Clear sensitive information from the Keccak context "kec."

void sha3_clear(sha3_t* kec)
{
    memset(kec, 0, sizeof(sha3_t));
}

//  function for single-call sha3

void sha3_hash(uint8_t* h, size_t h_sz, const uint8_t* m, size_t m_sz)
{
    sha3_t  kec;

    sha3_init(&kec, 200 - 2 * h_sz);
    sha3_absorb(&kec, m, m_sz);
    sha3_pad(&kec, SHA3_PAD);
    sha3_squeeze(&kec, h, h_sz);
}

//  function for single-call shake at rate r

void shake_xof( uint8_t* h, size_t h_sz,
                const uint8_t* m, size_t m_sz, size_t r)
{
    sha3_t  kec;

    sha3_init(&kec, r);
    sha3_absorb(&kec, m, m_sz);
    sha3_pad(&kec, SHAKE_PAD);
    sha3_squeeze(&kec, h, h_sz);
}
