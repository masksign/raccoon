//  polyr.h
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//  === Polynomial arithmetic related to the ring Zq[x]/(x^n+1).

#ifndef _POLYR_H_
#define _POLYR_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

//  Zeroize a polynomial:   r = 0.
void polyr_zero(int64_t *r);

//  Copy a polynomial:  r = a.
void polyr_copy(int64_t *r, const int64_t *a);

//  Add polynomials:  r = a + b.
void polyr_add(int64_t *r, const int64_t *a, const int64_t *b);

//  Subtract polynomials:  r = a - b.
void polyr_sub(int64_t *r, const int64_t *a, const int64_t *b);

//  Add polynomials mod q:  r = a + b  (mod q).
void polyr_addq(int64_t *r, const int64_t *a, const int64_t *b);
void polyr_ntt_addq(int64_t *r, const int64_t *a, const int64_t *b);

//  Subtract polynomials mod q:  r = a - b  (mod q).
void polyr_subq(int64_t *r, const int64_t *a, const int64_t *b);
void polyr_ntt_subq(int64_t *r, const int64_t *a, const int64_t *b);

//  Add polynomials:  r = a + b, conditionally subtract m on overflow
void polyr_addm(int64_t *r, const int64_t *a, const int64_t *b, int64_t m);

//  Subtract polynomials, conditionally add m on underflow.
void polyr_subm(int64_t *r, const int64_t *a, const int64_t *b, int64_t m);

//  Negate a polynomial mod m:  r = -a, add m on underflow.
void polyr_negm(int64_t *r, int64_t *a, int64_t m);

//  Left shift:  r = a << sh, conditionally subtract m on overflow.
void polyr_shlm(int64_t *r, const int64_t *a, size_t sh, int64_t m);

//  Right shift:  r = a >> sh, conditionally subtract m on overflow.
void polyr_shrm(int64_t *r, const int64_t *a, size_t sh, int64_t m);

//  Rounding:  r = (a + h) >> sh, conditionally subtract m on overflow.
void polyr_round(int64_t *r, const int64_t *a, size_t sh, int64_t h, int64_t m);

//  Move from range 0 <= x < m to centered range -m/2 <= x <  m/2.
void polyr_center(int64_t *r, const int64_t *a, int64_t m);

//  Move from range -m <= x < m to non-negative range 0 <= x < m.
void polyr_nonneg(int64_t *r, const int64_t *a, int64_t m);

//  Scalar multiplication:  r = a * c,  Montgomery reduction.
#ifdef POLYR_Q32
void polyr_ntt_smul(int64_t *r, const int64_t *a, int32_t c1, int32_t c2);
#else
void polyr_ntt_smul(int64_t *r, const int64_t *a, int64_t c);
#endif

//  Coefficient multiply:  r = a * b,  Montgomery reduction.
void polyr_ntt_cmul(int64_t *r, const int64_t *a, const int64_t *b);

//  Coefficient multiply and add:  r = a * b + c, Montgomery reduction.
void polyr_ntt_mula(int64_t *r, const int64_t *a, const int64_t *b,
                    const int64_t *c);

//  Forward NTT (negacyclic -- evaluate polynomial at factors of x^n+1).
void polyr_fntt(int64_t *v);

//  Reverse NTT (negacyclic -- x^n+1), normalize by 1/(n*r).
void polyr_intt(int64_t *v);

#ifdef POLYR_Q32
//  2x32 CRT: Split into two-prime representation (in-place).
void polyr2_split(int64_t *v);

//  2x32 CRT: Join two-prime into 64-bit integer representation (in-place).
//  Use scale factors (s1, s2). Normalizes to 0 <= x < q.
void polyr2_join(int64_t *v, int32_t s1, int32_t s2);

//  2x32 CRT: Add polynomials:  r = a + b.
void polyr2_add(int64_t *r, const int64_t *a, const int64_t *b);

//  2x32 CRT: Subtract polynomials:  r = a - b.
void polyr2_sub(int64_t *r, const int64_t *a, const int64_t *b);

//  POLYR_Q32
#endif

#ifdef __cplusplus
}
#endif

//  _POLYR_H_
#endif
