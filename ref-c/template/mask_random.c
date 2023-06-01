//  mask_random.c
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//  === Mask random generator (dummy implementations)

#include <string.h>

#include "mask_random.h"
#include "plat_local.h"
#include "racc_param.h"

#if RACC_D > 1
#ifdef MASK_RANDOM_ASCON

//  === MASK_RANDOM_ASCON is set

/*
    ASCON v1.2 masking noise source simulation.

    This pseudorandom generator simulates a masking noise source based
    on Ascon-80pq from the specification of Ascon v1.2 (May 31, 2021).
    Note that this particular variant of Ascon is not an XOF; The output
    sequence is ciphertext from the AEAD mode with plaintext set as zero.

    The statistical properties of this generator are more than sufficient
    as a masking noise source. A similar Ascon-based construction has
    been used in hardware implementations for this purpose, continuously
    re-seeding from an on-chip entropy source.

    In this instance, the reference code is used mainly to demonstrate
    the performance impact of having a "good" random number generator.
*/

//  ASCON v1.2 Permutation

static inline void ascon_p(uint64_t s[5], int n)
{
    uint64_t c = ((3 + (n)) << 4 | (12 - (n)));
    uint64_t t;

    for (int i = 0; i < n; i++) {

        s[2] ^= c;  //  round constant
        c -= 0xF;

        //  s-box layer
        s[0] ^= s[4];
        s[4] ^= s[3];
        s[2] ^= s[1];
        t = andn64(s[0], s[4]);
        s[0] ^= andn64(s[2], s[1]);
        s[2] ^= andn64(s[4], s[3]);
        s[4] ^= andn64(s[1], s[0]);
        s[1] ^= andn64(s[3], s[2]);
        s[3] ^= t;
        s[1] ^= s[0];
        s[3] ^= s[2];
        s[0] ^= s[4];

        // linear layer
        s[0] ^= ror64(s[0], 19) ^ ror64(s[0], 28);
        s[1] ^= ror64(s[1], 39) ^ ror64(s[1], 61);
        s[2] ^= ror64(s[2],  1) ^ ror64(s[2],  6);
        s[3] ^= ror64(s[3], 10) ^ ror64(s[3], 17);
        s[4] ^= ror64(s[4],  7) ^ ror64(s[4], 41);
        s[2] = ~(s[2]);
    }
}

//  From six-round AEAD mode; takes input ("pt"), returns ciphertext.

static inline uint64_t asconp6_enc(uint64_t s[5], uint64_t pt)
{
    pt ^= s[0];
    s[0] = pt;
    ascon_p(s, 6);

    return pt;
}

//  initialize. you can set seed=NULL in case just zeroizes

void mask_random_init(mask_random_t *mrg)
{
    //  trivial test vector; see mask_random_selftest()
    const uint8_t key[20] = {
        0,  1,  2,  3,  4,  5,  6,  7,  8,  9,      //  KAT Key: 160-bit
        10, 11, 12, 13, 14, 15, 16, 17, 18, 19  };
    const uint8_t iv[16] = {
        0,  1,  2,  3,  4,  5,  6,  7,              //  KAT nonce: 128-bit
        8,  9,  10, 11, 12, 13, 14, 15
    };

    size_t i;
    uint64_t *s;

    /*
    **  +---------------------------------------------------------------+
    **  |   Each individual RNG should be independently initialized     |
    **  |   and continuously reseeded using real (physical) entropy.    |
    **  +---------------------------------------------------------------+
    */

    for (i = 0; i < RACC_D - 1; i++) {

        s = mrg->s[i];

        //  the "test vector IV" is for Ascon80-PQ
        s[0] = 0xA0400C0600000000 | get32u_be(key);
        s[1] = get64u_be(key + 4);
        s[2] = get64u_be(key + 12);
        s[3] = get64u_be(iv);
        s[4] = get64u_be(iv + 8);

        //  modify nonce with the share # in this dummy implementation
        s[3] += i;

        ascon_p(s, 12);
        s[2] ^= get32u_be(key);
        s[3] ^= get64u_be(key + 4);
        s[4] ^= get64u_be(key + 12);
        s[4] ^= 1;          //  Domain separation.
    }
}

//  get a 64-bit random number

uint64_t mask_rand64(mask_random_t *mrg, size_t ri)
{
    return asconp6_enc(mrg->s[ri], 0);
}

//  sample a uniform random polynomial

void mask_random_poly(mask_random_t *mrg, int64_t *r, size_t ri)
{
    size_t i;
    int64_t z;
    uint64_t s[5];

    //  local copy of state allows some additional optimizations
    memcpy(s, mrg->s[ri], sizeof(s));

    for (i = 0; i < RACC_N; i++) {
        do {
            z = s[0] & RACC_QMSK;
            ascon_p(s, 6);
        } while (z >= RACC_Q);
        r[i] = z;
    }

    //  copy it back
    memcpy(mrg->s[ri], s, sizeof(s));
}

//  ASCON: simple deterministic self-test, return nonzero on failure

int mask_random_selftest()
{
    //  From: Count = 1057, ascon80pqv12/LWC_AEAD_KAT_160_128.txt
    //  NOTE: The plaintext words are actually big-endian in Ascon.
    const uint64_t pt[4] = {
        0x0001020304050607, 0x08090A0B0C0D0E0F,
        0x1011121314151617, 0x18191A1B1C1D1E1F
    };
    const uint64_t ct[4] = {
        0x2846418067CE9386, 0xB47F0584BF9EEE3F,
        0x51A62969F011D86D, 0xE54D5B258AF88C21
    };

    int fail = 0;
    int i;
    uint64_t x;
    mask_random_t mrg;

    mask_random_init(&mrg);

    for (i = 0; i < 4; i++) {
        x = asconp6_enc(mrg.s[0], pt[i]) ^ ct[i];
        if (x != 0) {
            fail++;
        }
    }

    return fail;
}

#else

//  === MASK_RANDOM_ASCON *not* set

/*
    LFSR-127: A simple LFSR that outputs 64 bits at a time.

    While not theoretically/cryptographically secure, the output has
    reasonable statistical qualities -- sufficient for side-channel
    masking noise in many applications.

    Degree 127 is a "classic" -- the multiplicative field size 2^127-1
    is a (Mersenne) prime, so a large cycle is guaranteed. The trinomial
    x^127+x^64+1 is suitable for stepping 64 times at once while keeping
    the circuit depth low (not too many stacked XORs.)

    The state is in two words s[1],s[0], where s[1] is bits 126..64,
    and s[0] has bits 63..0.
*/

//  period 2^127-1, primitive polynomial x^127+x^64+1, 64 steps

static inline uint64_t lfsr127(uint64_t s[2])
{
    uint64_t x;

    x = ((s[1] << 1) | (s[0] >> 63)) ^ (s[1] >> 62);
    s[1] = (x ^ s[0]) & 0x7FFFFFFFFFFFFFFF;     //  high word
    s[0] = x;                                   //  low word

    return x;      //  return 64 bits is the low value
}

//  get a 64-bit random number

uint64_t mask_rand64(mask_random_t *mrg, size_t ri)
{
    return lfsr127(mrg->s[ri]);
}

//  sample a uniform random polynomial

void mask_random_poly(mask_random_t *mrg, int64_t *r, size_t ri)
{
    size_t i;
    int64_t z;
    uint64_t s[2];

    //  local state allows some additional optimizations
    memcpy(s, mrg->s[ri], sizeof(s));
    for (i = 0; i < RACC_N; i++) {
        do {
            z = lfsr127(s) & RACC_QMSK;
        } while (z >= RACC_Q);
        r[i] = z;
    }
    memcpy(mrg->s[ri], s, sizeof(s));
}

//  Initialize the mask random number generator from physical sources.

void mask_random_init(mask_random_t *mrg)
{
    //  test vector key is default
    const uint8_t key[16] = {
        0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87,
        0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F
    };

    size_t i;

    /*
    **  +---------------------------------------------------------------+
    **  |   Each individual RNG should be independently initialized     |
    **  |   and continuously reseeded using real (physical) entropy.    |
    **  +---------------------------------------------------------------+
    */

    //  set the state
    for (i = 0; i < RACC_D - 1; i++) {
        mrg->s[i][0] = get64u_le(key);
        mrg->s[i][1] = get64u_le(key + 8) + (0x0123456789ABCDEF * i);
    }
}

//  LFSR127: simple deterministic self-test, return nonzero on failure

int mask_random_selftest()
{
    const uint64_t lfsr127_kat[8] = {
        0x1E3C5A7896B4D2F1, 0x3355FF98AACC6602, 0x5AD34BC078F169E6,
        0xD30D68B1A47A1FC9, 0x13BC46E3B916EC5F, 0x81625CA43AD9E72D,
        0x25BC348F079E16E5, 0x49BCD0567A8FE390 };

    int i;
    mask_random_t mrg;
    int fail = 0;

    //  the
    mask_random_init(&mrg);

    for (i = 0; i < 8; i++) {
        if (lfsr127(mrg.s[0]) != lfsr127_kat[i]) {
            fail++;
        }
    }

    return fail;
}

#endif
//  RACC_D
#endif
