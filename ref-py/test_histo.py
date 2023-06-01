#!/usr/bin/env python3

"""
test_histo.py
Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

=== Create "histograms" and average / std. deviation pairs for signature size.
"""

import sys,math
from nist_kat_drbg import NIST_KAT_DRBG
from racc_api import *
from polyr import RACC_Q, RACC_N

#   actual length

def sig_len(iut, sig):
    """Count bits in an actual signature."""
    (c_hash, h, z) = sig
    b = []                          #   bit string
    for hi in h:                    #   h bit strings
        b += iut._bits_enc_h(hi)
    for zi in z:                    #   z bit strings
        b += iut._bits_enc_z(zi)
    return len(c_hash) + (len(b) / 8)

def stats(iut):
    """Print quick version-control checksums."""

    def _chkdata(label, data):
        print(f'{label}: ' +
                SHAKE256.new(bytes(data)).read(16).hex() +
                f' ({len(data)})')

    #iut.set_random(NIST_KAT_DRBG(bytes([i for i in range(48)])).random_bytes)

    #   statistics
    h_c = [0] * 100
    h_n = 0
    z_c = [0] * 100
    z_n = 0


    len_s = 0
    len_r = 0
    len_n = 0

    for j in range(100):

        if j % 5 == 0:
            pk, sk = iut.byte_keygen()

        sm = iut.byte_sign(bytes([j]), sk)
        sig = iut.decode_sig(sm)
        (ch, h, z) = sig

        #   histograms (absolute values)
        for hi in h:
            h_n += len(hi)
            for x in hi:
                x = min(abs(x), 99)
                h_c[x] += 1
        for zi in z:
            z_n += len(zi)
            for x in zi:
                x %= RACC_Q
                if x > RACC_Q // 2:
                    x = RACC_Q - x
                x >>= 40
                x = min(x, 99)
                z_c[x] += 1

        len_x = sig_len(iut, sig)
        len_s += len_x
        len_r += len_x**2
        len_n += 1
        x_avg = len_s / len_n
        x_sig = (len_r / len_n - x_avg**2)**0.5

        print(f'{iut.name}: {j} x_avg= {x_avg:9.3f}  x_sig= {x_sig:9.6f}  x= {len_x}')

        h_avg = 0.0
        h_var = 0.0
        z_avg = 0.0
        z_var = 0.0
        for i in range(99):
            if h_c[i] == 0 and z_c[i] == 0:
                continue

            if i == 0:
                h_l = 1
            else:
                h_l = i + 2
            z_l = 42 + i

            h_f = h_c[i] / h_n
            h_avg += h_f * h_l
            h_var += h_f * (h_l**2)

            z_f = z_c[i] / z_n
            z_avg += z_f * z_l
            z_var += z_f * (z_l**2)

            print(f'#{i} h: {h_f:8.6f} {h_l:2d}   z: {z_f:8.6f} {z_l:2d}')

        h_var = (h_var - h_avg**2)
        z_var = (z_var - z_avg**2)

        print(f'h_avg= {h_avg:9.6f}  h_var= {h_var:9.6f}')
        print(f'z_avg= {z_avg:9.6f}  z_var= {z_var:9.6f}')

        l_avg = iut.ch_sz + iut.n * (iut.k * h_avg + iut.ell * z_avg) / 8
        l_sig = (iut.n * (iut.k * h_var + iut.ell * z_var))**0.5 / 8
        print(f'{iut.name}: {j} l_avg= {l_avg:9.3f}  l_sig= {l_sig:9.6f}')


#   Gaussian cumulative density function [-inf,+inf] -> [0,1]
def cdf(x):
    return 1 - math.erfc(x/math.sqrt(2))/2

if __name__ == '__main__':

    for iut in raccoon_all:
        if len(sys.argv) <= 1:
            print(iut.name)
            stats(iut)              # check them all
        else:
            for x in sys.argv[1:]:
                if iut.name.lower() == x.lower():
                    print(iut.name)
                    stats(iut)
                    break

