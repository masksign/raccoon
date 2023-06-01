"""
test_ntt.py
Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

=== Code for re-creating the NTT magic constants. Unit tests for NTT.
"""

from random import randrange
from polyr import *

if (__name__ == "__main__"):

    def _modexp(x, e, n):
        """(TESTING) Modular exponentiation: Compute x**e (mod n)."""
        y = 1
        while e > 0:
            if e & 1 == 1:
                y = (y * x) % n
            x = (x * x) % n
            e >>= 1
        return y

    def _bitrev(x, l):
        """(TESTING) Return x with bits 0,1,..(l-1) in reverse order."""
        y = 0
        for i in range(l):
            y |= ((x >> i) & 1) << (l - i - 1)
        return y

    #   g=15 is the smallest generator of both prime fields of composite q.
    #   Reduce to subgroup of order 2*n to obtain "h" in gp-pari;
    #   g   = Mod(15, q)
    #   h   = g^(znorder(g)/(2*n))

    def _calc_w():
        """(TESTING) Re-generate the NTT "tweak" table."""
        q   = RACC_Q
        lgn = 9                         #   log2(n)
        n   = 2**lgn                    #   length of the transform
        h   = 358453792785495           #   Generates a subgroup of order 2*n
        w   = []
        for i in range(n):
            j = _bitrev(i, lgn)
            x = (_modexp(h, j, q)) % q
            w.append(x)
        return w

    #   prettyprint the table
    def _print_w():
        w = _calc_w()
        for i in range(0, RACC_N, 4):
            print(f'\t{w[i]:15}, {w[i+1]:15}, {w[i+2]:15}, {w[i+3]:15},')

    def _rand_poly(n=RACC_N, q=RACC_Q):
        """(TESTING) Random polynomial."""
        return [ randrange(q) for _ in range(n) ]

    def _conv_slow(f, g, n=RACC_N,q=RACC_Q):
        """(TESTING) Slow negacyclic convolution h = f*g (mod x^n+1)."""
        h = [0] * n
        for i in range(n):
            for j in range(n):
                x = (f[i] * g[j]) % q
                k = i + j
                if k >= n:
                    k -= n
                    x = -x                  # x^n == -1 (mod x^n + 1)
                h[k] = (h[k] + x) % q

        return h

    def _conv_fast(f, g, n=RACC_N, q=RACC_Q):
        """(TESTING) Fast NTT negacyclic convolution h = f*g (mod x^n+1)."""
        ft = ntt(f.copy())
        gt = ntt(g.copy())
        ht = [ ( ft[i] * gt[i] ) % q for i in range(n) ]
        return intt(ht)

    """
    q=549824583172097
    h=Mod(358453792785495,q)
    rev(x)=sum(i=0,8,2^(8-i)*(floor(2^-i * x) % 2))
    """

    def _slow_ntt(f, n=RACC_N, q=RACC_Q, h=358453792785495):
        """(TESTING) Compute NTT via very slow polynomial evaluation."""
        ft = []
        fails = 0
        for i in range(n):
            #   yes, not a modexp!
            x = h**(2*_bitrev(i,9)+1) % q
            #   horner's: y = f(x)
            y = 0
            for j in reversed(range(n)):
                y = (y * x + f[j]) % q
            ft += [y]
        return ft

    #   ---------------

    #   check the zeta table
    print("_calc_w():", _calc_w() == RACC_W)

    #   test convolutions
    for _ in range(5):
        f = _rand_poly()
        g = _rand_poly()
        print("_conv_fast():", _conv_slow(f, g) == _conv_fast(f, g))
        ft1 = ntt(f.copy())
        ft2 = _slow_ntt(f.copy())
        print("_slow_ntt():", ft1 == ft2)

