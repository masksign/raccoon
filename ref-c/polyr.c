//  polyr.c
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//  === Polynomial arithmetic related to the ring Zq[x]/(x^n+1).

#include <stddef.h>
#include <stdbool.h>

#include "polyr.h"
#include "mont64.h"

//  === Polynomial API

//  Zeroize a polynomial:   r = 0.

void polyr_zero(int64_t *r)
{
    size_t i;

    for (i = 0; i < RACC_N; i++) {
        r[i] = 0;
    }
}

//  Copy a polynomial:  r = a.

void polyr_copy(int64_t *r, const int64_t *a)
{
    size_t i;

    for (i = 0; i < RACC_N; i++) {
        r[i] = a[i];
    }
}

//  Add polynomials:  r = a + b.

void polyr_add(int64_t *r, const int64_t *a, const int64_t *b)
{
    size_t i;

    for (i = 0; i < RACC_N; i++) {
        r[i] = mont64_add(a[i], b[i]);
    }
}

//  Subtract polynomials:  r = a - b.

void polyr_sub(int64_t *r, const int64_t *a, const int64_t *b)
{
    size_t i;

    for (i = 0; i < RACC_N; i++) {
        r[i] = mont64_sub(a[i], b[i]);
    }
}

//  Add polynomials mod q:  r = a + b  (mod q).

void polyr_addq(int64_t *r, const int64_t *a, const int64_t *b)
{
    size_t i;

    for (i = 0; i < RACC_N; i++) {
        r[i] = mont64_csub(a[i] + b[i], RACC_Q);
    }
}
#ifndef POLYR_Q32
void polyr_ntt_addq(int64_t *r, const int64_t *a, const int64_t *b)
{
    polyr_addq(r, a, b);
}
#endif

//  Subtract polynomials mod q:  r = a - b  (mod q).

void polyr_subq(int64_t *r, const int64_t *a, const int64_t *b)
{
    size_t i;

    for (i = 0; i < RACC_N; i++) {
        r[i] = mont64_cadd(a[i] - b[i], RACC_Q);
    }
}

#ifndef POLYR_Q32
void polyr_ntt_subq(int64_t *r, const int64_t *a, const int64_t *b)
{
    polyr_subq(r, a, b);
}
#endif

//  Add polynomials:  r = a + b, conditionally subtract m on overflow

void polyr_addm(int64_t *r, const int64_t *a, const int64_t *b, int64_t m)
{
    size_t i;

    for (i = 0; i < RACC_N; i++) {
        r[i] = mont64_csub(a[i] + b[i], m);
    }
}

//  Subtract polynomials:  r = a - b, conditionally add m on underflow.

void polyr_subm(int64_t *r, const int64_t *a, const int64_t *b, int64_t m)
{
    size_t i;

    for (i = 0; i < RACC_N; i++) {
        r[i] = mont64_cadd(a[i] - b[i], m);
    }
}

//  Negate a polynomial mod m:  r = -a, add m on underflow.

void polyr_negm(int64_t *r, int64_t *a, int64_t m)
{
    size_t i;

    for (i = 0; i < RACC_N; i++) {
        r[i] = mont64_cadd(-a[i], m);
    }
}

//  Left shift:  r = a << sh, conditionally subtract m on overflow.

void polyr_shlm(int64_t *r, const int64_t *a, size_t sh, int64_t m)
{
    size_t i;

    for (i = 0; i < RACC_N; i++) {
        r[i] = mont64_csub(a[i] << sh, m);
    }
}

//  Right shift:  r = a >> sh, conditionally subtract m on overflow.

void polyr_shrm(int64_t *r, const int64_t *a, size_t sh, int64_t m)
{
    size_t i;

    for (i = 0; i < RACC_N; i++) {
        r[i] = mont64_csub(a[i] >> sh, m);
    }
}

//  Rounding:  r = (a + h) >> sh, conditionally subtract m on overflow.

void polyr_round(int64_t *r, const int64_t *a, size_t sh, int64_t h, int64_t m)
{
    size_t i;

    for (i = 0; i < RACC_N; i++) {
        r[i] = mont64_csub((a[i] + h) >> sh, m);
    }
}

//  Move from range 0 <= x < m to centered range -m/2 <= x <  m/2.

void polyr_center(int64_t *r, const int64_t *a, int64_t m)
{
    size_t i;
    int64_t x, c;

    c = m >> 1;
    for (i = 0; i < RACC_N; i++) {
        x = mont64_add(a[i], c);
        x = mont64_csub(x, m);
        r[i] = mont64_sub(x, c);
    }
}

//  Move from range -m <= x < m to non-negative range 0 <= x < m.

void polyr_nonneg(int64_t *r, const int64_t *a, int64_t m)
{
    size_t i;

    for (i = 0; i < RACC_N; i++) {
        r[i] = mont64_cadd(a[i], m);
    }
}
