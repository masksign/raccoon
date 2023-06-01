//  mont32.h
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//  === Portable 32-bit Montgomery arithmetic

#ifndef _MONT32_H_
#define _MONT32_H_

#include "plat_local.h"
#include "racc_param.h"

/*
    n   = 512
    q1  = 2^24-2^18+1
    q2  = 2^25-2^18+1
    q   = q1*q2
*/

#define RACC_Q1 16515073
#define RACC_Q2 33292289

#if (RACC_N != 512 || RACC_Q != (RACC_Q1 * RACC_Q2))
#error "Unrecognized polynomial parameters N, Q"
#endif

/*
    r1  = 2^32 % q1
    rr1 = r1^2 % q1
    rrr1 = r1^3 % q1
    ri1 = lift(Mod(2^32,q1)^-1)
    ni1 = lift(rr1 * Mod(n,q1)^-1)
    qi1 = lift(Mod(-q1,2^32)^-1)
*/

#define MONT_R1 1048316
#define MONT_RR1 3933217
#define MONT_RRR1 2096954
#define MONT_RI1 63504
#define MONT_NI1 15458307
#define MONT_QI1 16515071

/*
    r2  = 2^32 % q2
    rr2 = r2^2 % q2
    rrr2 = r2^3 % q2
    ri2 = lift(Mod(2^32,q2)^-1)
    ni2 = lift(rr1 * Mod(n,q2)^-1)
    qi2 = lift(Mod(-q2, 2^32)^-1)
*/

#define MONT_R2 262015
#define MONT_RR2 3160307
#define MONT_RRR2 2026597
#define MONT_RI2 258064
#define MONT_NI2 31154179
#define MONT_QI2 33292287

/*
    (c4q1, c4q2) accounts for FFT^-1 (n) and 4 REDC's (2^-32).
    c4q1 = lift(Mod(q2*n,q1)^-1 * (2^32)^4)
    c4q2 = lift(Mod(q1*n,q2)^-1 * (2^32)^4)
*/

#define MONT_C4Q1 1048477
#define MONT_C4Q2 15632846

/*
    (d2q1, d2q2) accounts for 2 REDC's (2^-32) -- no FFT^-1
    d2q1 = lift(Mod(q2,q1)^-1 * (2^32)^2)
    d2q2 = lift(Mod(q1,q2)^-1 * (2^32)^2)
*/

#define MONT_D2Q1 4127728
#define MONT_D2Q2 32801027

//  Addition and subtraction

static inline int32_t mont32_add(int32_t x, int32_t y)
{
    return x + y;
}

static inline int32_t mont32_sub(int32_t x, int32_t y)
{
    return x - y;
}
//  Conditionally add m if x is negative

static inline int32_t mont32_cadd(int32_t x, int32_t m)
{
    int32_t t, r;

    XASSUME(x >= -m && x < m);

    t = x >> 31;
    r = x + (t & m);

    XASSERT(r >= 0 && r < m);
    XASSERT(r == x || r == x + m);

    return r;
}

//  Conditionally subtract m if x >= m

static inline int32_t mont32_csub(int32_t x, int32_t m)
{
    int32_t t, r;

    XASSUME(x >= 0 && x < 2 * m);
    XASSUME(m > 0);

    t = x - m;
    r = t + ((t >> 31) & m);

    XASSERT(r >= 0 && r < m);
    XASSERT(r == x || r == x - m);

    return r;
}

//  Montgomery reduction. Returns r in [-q,q-1] so that r == (x/2^32) mod q.

static inline int32_t mont32_redc1(int64_t x)
{
    int32_t r;

    //  prove these input bounds (55-bit for q1)
    XASSUME(x >= -(((int64_t)1) << 54));
    XASSUME(x < (((int64_t)1) << 54));

    r = x * MONT_QI1;
    r = (x + ((int64_t)r) * ((int64_t)RACC_Q1)) >> 32;

    //  prove that only one coditional addition is required
    XASSERT(r >= -RACC_Q1 && r < RACC_Q1);

#ifdef XDEBUG
    //  this modular reduction correctness proof is too slow for SAT
    XASSERT(((((int64_t)x) - (((int64_t)r) << 32)) % ((int64_t)RACC_Q1)) == 0);
#endif
    return r;
}

static inline int32_t mont32_redc2(int64_t x)
{
    int32_t r;

    //  prove these input bounds (56-bit for q2)
    XASSUME(x >= -(((int64_t)1) << 55));
    XASSUME(x < (((int64_t)1) << 55));

    r = x * MONT_QI2;
    r = (x + ((int64_t)r) * ((int64_t)RACC_Q2)) >> 32;

    //  prove that only one coditional addition is required
    XASSERT(r >= -RACC_Q2 && r < RACC_Q2);

    //  this modular reduction correctness proof is too slow for SAT
#ifdef XDEBUG
    XASSERT(((((int64_t)x) - (((int64_t)r) << 32)) % ((int64_t)RACC_Q2)) == 0);
#endif
    return r;
}

//  Montgomery multiplication. r in [-q,q-1] so that r == (a*b)/2^32) mod q.

static inline int32_t mont32_mulq1(int32_t x, int32_t y)
{
    int32_t r;

    r = mont32_redc1(((int64_t)x) * ((int64_t)y));

    return r;
}

static inline int32_t mont32_mulq2(int32_t x, int32_t y)
{
    int32_t r;

    r = mont32_redc2(((int64_t)x) * ((int64_t)y));

    return r;
}

//  same with addition

static inline int32_t mont32_mulqa1(int32_t x, int32_t y, int32_t z)
{
    int32_t r;

    r = mont32_redc1(((int64_t)x) * ((int64_t)y) + ((int64_t)z));

    return r;
}

static inline int32_t mont32_mulqa2(int32_t x, int32_t y, int32_t z)
{
    int32_t r;

    r = mont32_redc2(((int64_t)x) * ((int64_t)y) + ((int64_t)z));

    return r;
}

//  _MONT32_H_
#endif
