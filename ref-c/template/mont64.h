//  mont64.h
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//  === Portable 64-bit Montgomery arithmetic

#ifndef _MONT64_H_
#define _MONT64_H_

#include "plat_local.h"
#include "racc_param.h"

#if (RACC_N != 512 || RACC_Q != 549824583172097l)
#error "Unrecognized polynomial parameters N, Q"
#endif

/*
    n   = 512
    q1  = 2^24-2^18+1
    q2  = 2^25-2^18+1
    q   = q1*q2
    r   = 2^64 % q
    rr  = r^2 % q
    ni  = lift(rr * Mod(n,q)^-1)
    qi  = lift(Mod(-q,2^64)^-1)
*/

//  Montgomery constants. These depend on Q and N
#define MONT_R 129308285697266L
#define MONT_RR 506614974174448L
#define MONT_NI 293083792181611L
#define MONT_QI 2231854466648768511L

//  Addition and subtraction

static inline int64_t mont64_add(int64_t x, int64_t y)
{
    return x + y;
}

static inline int64_t mont64_sub(int64_t x, int64_t y)
{
    return x - y;
}
//  Conditionally add m if x is negative

static inline int64_t mont64_cadd(int64_t x, int64_t m)
{
    int64_t t, r;

    XASSUME(x >= -m && x < m);

    t = x >> 63;
    r = x + (t & m);

    XASSERT(r >= 0 && r < m);
    XASSERT(r == x || r == x + m);

    return r;
}

//  Conditionally subtract m if x >= m

static inline int64_t mont64_csub(int64_t x, int64_t m)
{
    int64_t t, r;

    XASSUME(x >= 0 && x < 2 * m);
    XASSUME(m > 0);

    t = x - m;
    r = t + ((t >> 63) & m);

    XASSERT(r >= 0 && r < m);
    XASSERT(r == x || r == x - m);

    return r;
}

//  Montgomery reduction. Returns r in [-q,q-1] so that r == (x/2^64) mod q.

static inline int64_t mont64_redc(__int128 x)
{
    int64_t r;

    //  prove these input bounds
    XASSUME(x >= -(((__int128)1) << 111));
    XASSUME(x < (((__int128)1) << 111));

    r = x * MONT_QI;
    r = (x + ((__int128)r) * ((__int128)RACC_Q)) >> 64;

    //  prove that only one coditional addition is required
    XASSERT(r >= -RACC_Q && r < RACC_Q);

#ifdef XDEBUG
    //  this modular reduction correctness proof is too slow for SAT
    XASSERT(((((__int128)x) - (((__int128)r) << 64)) %
            ((__int128_t)RACC_Q)) == 0);
#endif
    return r;
}

//  Montgomery multiplication. r in [-q,q-1] so that r == (a*b)/2^64) mod q.

static inline int64_t mont64_mulq(int64_t x, int64_t y)
{
    int64_t r;

    r = mont64_redc(((__int128)x) * ((__int128)y));

    return r;
}

//  same with addition

static inline int64_t mont64_mulqa(int64_t x, int64_t y, int64_t z)
{
    int64_t r;

    r = mont64_redc(((__int128)x) * ((__int128)y) + ((__int128)z));

    return r;
}

//  _MONT64_H_
#endif
