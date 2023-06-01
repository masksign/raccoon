"""
racc_core.py
Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

=== Masked Raccoon signature scheme: Core implementation.
"""

import os

from Crypto.Hash import SHAKE256
from nist_kat_drbg import NIST_KAT_DRBG
from mask_random import MaskRandom
from polyr import *

BYTEORDER = "little"

class Raccoon:

    ### Public Interface

    #   initialize
    def __init__(self,  bitsec,
                        q, nut, nuw, rep, ut, uw, n, k, ell, w, d,
                        masking_poly=MaskRandom().random_poly,
                        random_bytes=os.urandom, kappa=512):
        """Initialize a Raccoon instance."""

        self.name   =   f'Raccoon-{bitsec}-{d}'
        self.bitsec =   bitsec
        self.d      =   d
        self.q      =   q
        self.q_bits =   q.bit_length()
        self.n      =   n
        self.k      =   k
        self.ell    =   ell
        self.nut    =   nut
        self.nuw    =   nuw
        self.rep    =   rep
        self.ut     =   ut
        self.uw     =   uw
        self.w      =   w

        self.sec    =   self.bitsec//8  # pre-image resistance, bytes
        self.crh    =   2*self.sec      # collision resistance, bytes
        self.as_sz  =   self.sec        # A seed size
        self.mu_sz  =   self.crh        # mu digest H(tr, m) size
        self.tr_sz  =   self.crh        # tr digest H(pk) size
        self.ch_sz  =   self.crh        # Challenge hash size
        self.mk_sz  =   self.sec        # serialization "key" size

        self.masking_poly = masking_poly
        self.random_bytes = random_bytes

        #   calculate derived parmeters
        self._compute_metrics()

    def keygen(self):
        """Raccoon keypair generation."""

        #   --- 1.  seed <- {0,1}^kappa
        seed = self.random_bytes(self.as_sz)

        #   --- 2.  A := ExpandA(seed)
        A_ntt = mat_ntt(self._expand_a(seed))

        #   --- 3.  [[s]] <- ell * ZeroEncoding(d)
        ms = [ self._zero_encoding() for _ in range(self.ell) ]

        #   --- 4.  [[s]] <- AddRepNoise([[s]], ut, rep)
        ms = self._vec_add_rep_noise( ms, self.ut, self.rep )

        #   --- 5.  [[t]] := A * [[s]]
        ms_ntt = mat_ntt(ms)
        mt = mat_intt(mul_mat_mvec_ntt(A_ntt, ms_ntt))

        #   --- 6.  [[t]] <- AddRepNoise([[t]], ut, rep)
        mt = self._vec_add_rep_noise( mt, self.ut, self.rep )

        #   --- 7.  t := Decode([[t]])
        t = [ self._decode(mti) for mti in mt ]

        #   --- 8.  t := round( t_m )_q->q_t
        qt  = self.q >> self.nut
        t = [ poly_rshift(ti, self.nut, qt) for ti in t ]

        #   --- 9.  return ( (vk := seed, t), sk:= (vk, [[s]]) )
        vk = (seed, t)
        msk = (seed, t, ms_ntt)
        return msk, vk

    def sign_mu(self, msk, mu):
        """Signing procedure of Raccoon (core: signs the mu hash)."""


        #   --- 1.  (vk, [[s]]) := [[sk]], (seed, t) := vk      [ caller ]
        (seed, t, ms_ntt) = msk

        #   --- 2.  mu := H( H(vk) || msg )                     [ caller ]

        #   --- 3.  A := ExpandA(seed)
        A_ntt = mat_ntt(self._expand_a(seed))

        #   (restart position.)
        rsp_norms = False
        while not rsp_norms:

            #   --- 4.  [[r]] <- ell x ZeroEncoding()
            mr = [ self._zero_encoding() for _ in range(self.ell) ]

            #   --- 5.  [[r]] <- AddRepNoise([[r]], uw, rep)
            mr = self._vec_add_rep_noise( mr, self.uw, self.rep )
            mr_ntt = mat_ntt(mr)

            #   --- 6.  [[w]] := A * [[r]]
            mw = mat_intt(mul_mat_mvec_ntt(A_ntt, mr_ntt))

            #   --- 7.  [[w]] <- AddRepNoise([[w]], uw, rep)
            mw = self._vec_add_rep_noise( mw, self.uw, self.rep )

            #   --- 8.  w := Decode([[w]])
            w = [ self._decode(mwi) for mwi in mw ]

            #   --- 9.  w := round( w )_q->q_w
            qw  = self.q >> self.nuw
            w = [ poly_rshift(wi, self.nuw, qw) for wi in w ]

            #   --- 10. c_hash := ChalHash(w, mu)
            c_hash  = self._chal_hash(mu, w)

            #   --- 11. c_poly := ChalPoly(c_hash)
            c_ntt   = ntt(self._chal_poly(c_hash))

            #   --- 12. [[s]] <- Refresh([[s]])
            for si in ms_ntt:
                self._refresh(si)

            #   --- 13. [[r]] <- Refresh([[r]])
            for ri in mr_ntt:
                self._refresh(ri)

            #   --- 14. [[z]] := c_poly * [[s]] + [[r]]
            mz_ntt = [[[ None ] for _ in range(self.d)]
                                    for _ in range(self.ell)]
            for i in range(self.ell):
                for j in range(self.d):
                    mz_ntt[i][j] = poly_add(mul_ntt(c_ntt, ms_ntt[i][j]),
                                            mr_ntt[i][j])

            #   --- 15. [[z]] <- Refresh([[z]])
            for zi in mz_ntt:
                self._refresh(zi)

            #   --- 16. z := Decode([[z]])
            z_ntt = [ self._decode(mzi) for mzi in mz_ntt ]

            #   --- 17. y := A*z - 2^{nu_t} * c_poly * t
            y = mul_mat_vec_ntt(A_ntt, z_ntt)
            for i in range(self.k):
                tp = poly_lshift(t[i], self.nut)
                ntt(tp)
                y[i] = poly_sub( y[i], mul_ntt(c_ntt, tp) )
                intt(y[i])

            #   --- 18. h := w - round( y )_q->q_w
            for i in range(self.k):
                y[i] = poly_rshift(y[i], self.nuw, qw)
                y[i] = poly_sub(w[i], y[i], qw)
                y[i] = poly_center(y[i], qw)
            h = y   #   (rename)

            #   --- 19. sig := (c_hash, h, z)                   [caller]

            #   --- 20. if CheckBounds(sig) = FAIL goto Line 4
            z = [intt(zi.copy()) for zi in z_ntt]
            rsp_norms = self._check_bounds(h, z)

        #   --- 21. return sig
        sig = (c_hash, h, z)
        return sig


    def verify_mu(self, vk, mu, sig):
        """Verification procedure of Raccoon (core: verifies mu)."""

        #   --- 1.  (c hash, h, z) := sig, (seed, t) := vk
        (c_hash, h, z) = sig
        (seed, t) = vk

        #   --- 2.  if CheckBounds(h, z) = FAIL return FAIL
        if self._check_bounds(h, z) == False:
            return False

        #   --- 3.  mu := H( H(vk) || msg )                     [caller]

        #   --- 4.  A := ExpandA(seed)
        A_ntt = mat_ntt(self._expand_a(seed))

        #   --- 5.  c_poly := ChalPoly(c_hash)
        c_poly = self._chal_poly(c_hash)
        c_ntt = ntt(c_poly.copy())

        #   --- 6.  y = A * z - 2^{nu_t} * c_poly * t
        z_ntt = [ ntt(zi.copy()) for zi in z ]
        y = mul_mat_vec_ntt(A_ntt, z_ntt)
        for i in range(self.k):
            tp = poly_lshift(t[i], self.nut)    # p_t * t
            ntt(tp)
            y[i] = poly_sub( y[i], mul_ntt(c_ntt, tp) ) # y -= p_t * c * t
            intt(y[i])

        #   --- 7.  w' = round( y )_q->q_w + h
        qw  = self.q >> self.nuw
        for i in range(self.k):
            y[i] = poly_rshift(y[i], self.nuw, qw)
            y[i] = poly_add(y[i], h[i], qw)
        w = y;  #   (rename)

        #   --- 8. c_hash' := ChalHash(w', mu)
        c_hash_new = self._chal_hash(mu, w)

        #   --- 9. if c_hash != c_hash' return FAIL
        #   --- 10. (else) return OK
        rsp_hash = (c_hash == c_hash_new)

        return rsp_hash

    def set_random(self, random_bytes):
        """Set the key material RBG."""
        self.random_bytes   =   random_bytes

    def set_masking(self, masking_poly):
        """Set masking generator."""
        self.masking_poly = masking_poly

    #   --- internal methods ---

    def _compute_metrics(self):
        """Derive rejection bounds from parameters."""
        w   = self.w
        nuw = self.nuw
        nut = self.nut
        k   = self.k
        ell = self.ell
        n   = self.n
        d   = self.d

        sigma = (self.d * self.rep / 12)**0.5
        beta2 = n * ( (k + ell) *
            (((2**self.uw * sigma)**2) + w * ((2**self.ut * sigma)**2))
                + k * ( ((2**nuw)**2 / 6) +  w * ((2**nut)**2) / 12 ) )

        self.B22 = int(1.2 * beta2 / 2**64)
        self.Boo = int(6 * ((beta2 / (n * (k + ell)))**0.5))
        #   Boo_h = round(Boo/2^nuw)
        self.Boo_h = (self.Boo + (1 << (self.nuw - 1))) >> self.nuw

    def _check_bounds(self, h, z):
        """Check signature bounds. Return True iff bounds are acceptable."""

        #   this function only checks the norms; steps 1 and 2 are external.
        #   --- 1.  if |sig| != |sig|default return FAIL        [caller]
        #   --- 2.  (c hash, h, z) := sig                       [caller]

        midq = self.q // 2

        #   Infinity and L2 norms for hint
        h22 = 0
        hoo = 0
        for hi in h:
            for x in hi:
                hoo = max(hoo, abs(x))
                h22 += (x * x)

        #   Infinity norm and scaled L2 norm for z
        z22 = 0
        zoo = 0
        for zi in z:
            for x in zi:
                x = abs((x + midq) % self.q - midq)
                zoo = max(zoo, x)
                #   --- 6.  z2 := sum_i [ abs(zi) / 2^32 ]^2
                x >>= 32
                z22 += (x * x)

        #   --- 3:  if ||h||oo > round(Boo/2^nuw) return FAIL
        if  hoo > self.Boo_h:
            return False

        #   --- 4.  if ||z||oo > Boo return FAIL
        if  zoo > self.Boo:
            return False

        #   --- 5.  h2 := 2^(2*nuw - 64) * ||h||^2
        #   --- 7.  if (h2 + z2) > 2^-64*B22 return FAIL
        if  ((h22 << (2 * self.nuw - 64)) + z22) > self.B22:
            return False

        #   --- 8.  return OK
        return True

    def _decode(self, mp):
        """Decode(): Collapse shares into a single polynomial."""
        r = mp[0].copy()
        for p in mp[1:]:
            r = poly_add(r, p)
        return r

    def _zero_encoding(self):
        """ZeroEncoding(): Create a masked encoding of zero."""

        z = [ [0] * self.n for _ in range(self.d) ]
        i = 1
        #   same ops as with recursion, but using nested loops
        while i < self.d:
            for j in range(0, self.d, 2 * i):
                for k in range(j, j + i):
                    r = self.masking_poly()
                    z[k] = poly_add(z[k], r)
                    z[k + i] = poly_sub(z[k + i], r)
            i <<= 1
        return z

    def _refresh(self, v):
        """Refresh(): Refresh shares via ZeroEncoding."""
        z = self._zero_encoding()
        for i in range(self.d):
            v[i] = poly_add(v[i], z[i])

    def _xof_sample_q(self, seed):
        """Expand a seed to n uniform values [0,q-1] using a XOF."""
        blen = (self.q_bits + 7) // 8
        mask = (1 << self.q_bits) - 1

        xof = SHAKE256.new(seed)
        v = [0] * self.n
        i = 0
        while i < self.n:
            z = xof.read(blen)
            x = int.from_bytes(z, BYTEORDER) & mask
            if (x < self.q):
                v[i] = x
                i += 1
        return v

    def _expand_a(self, seed):
        """ExpandA(): Expand "seed" into a k*ell matrix A."""
        a = [[None for _ in range(self.ell)] for _ in range(self.k)]
        #   matrix rejection sampler
        for i in range(self.k):
            for j in range(self.ell):
                #   XOF( 'A' || row || col || seed )
                xof_in  = bytes([ord('A'), i, j, 0, 0, 0, 0, 0]) + seed
                a[i][j] = self._xof_sample_q(xof_in)
        return a

    def _xof_sample_u(self, seed, u):
        """Sample a keyed uniform noise polynomial."""
        blen = (u + 7) // 8
        mask = (1 << u) - 1
        mid = (1 << u) // 2
        xof = SHAKE256.new(seed)
        r = [0] * self.n
        for i in range(self.n):
            z = xof.read(blen)
            x = int.from_bytes(z, BYTEORDER) & mask
            x ^= mid        # two's complement sign (1=neg)
            r[i] = (x - mid) % self.q
        return r


    def _vec_add_rep_noise(self, v, u, rep):
        """Repeatedly add uniform noise."""

        #   --- 1.  for i in [ |v| ] do
        for i in range(len(v)):

            #   --- 2.  for i_rep in [rep] do
            for i_rep in range(rep):

                #   --- 3. for j in [d] do
                for j in range(self.d):

                    #   --- 4.  rho <- {0,1}^lambda
                    sigma = self.random_bytes(self.sec)

                    #   --- 5.  hdr_u = ( 'u', rep, i, j, 0, 0, 0, 0 )
                    hdr_u   = bytes([ord('u'), i_rep, i, j,
                                            0, 0, 0, 0]) + sigma

                    #   --- 6.  v_i,j <- v_i,j + SampleU( hdr_u, sigma, u )
                    r       = self._xof_sample_u(hdr_u, u)
                    v[i][j] = poly_add(v[i][j], r)

                #   --- 7. Refresh([[v_i]])
                self._refresh(v[i])

        #   --- 8. Return [[v]]
        return v

    def _chal_hash(self, mu, w):
        """Compute the challenge for the signature (a single hash)."""

        lqw = (self.q >> self.nuw).bit_length()
        blen = (lqw + 7) // 8       #   usually: 1 byte
        xof = SHAKE256.new()

        #   Hash w: XOF( 'h' || k || (0 pad) || mu || coeffs.. )
        xof.update(bytes([ord('h'), self.k, 0, 0, 0, 0, 0, 0]))
        xof.update(mu)  #   add mu

        if blen == 1:
            #   this is the typical case; just 1 byte per coefficient
            for i in range(self.k):
                xof.update(bytes(w[i]))
        else:
            #   general version where little-endian encoding may be needed
            for i in range(self.k):
                for j in range(self.n):
                    xof.update(w[i][j].to_bytes(blen, byteorder=BYTEORDER))

        c_hash = xof.read(self.ch_sz)

        return c_hash

    def _chal_poly(self, c_hash):
        """ChalPoly(c_hash): Derive the challenge polynomial from c_hash."""
        mask_n  = (self.n - 1)

        #   For each sample, we need logn bits for the position and
        #   1 bit for the sign
        blen = (mask_n.bit_length() + 1 + 7) // 8

        xof = SHAKE256.new()
        xof.update(bytes([ord('c'), self.w, 0, 0, 0, 0, 0, 0]))
        xof.update(c_hash)

        #   Create a "w"-weight ternary polynomial
        c_poly = [0] * self.n
        wt = 0
        while wt < self.w:
            z = xof.read(blen)
            x = int.from_bytes(z, BYTEORDER)
            sign = x & 1
            idx = (x >> 1) & mask_n
            if (c_poly[idx] == 0):
                c_poly[idx] = (2 * sign - 1)
                wt += 1
        return c_poly

#   --- some testing code ----------------------------------------------

if (__name__ == "__main__"):

    def chksum(v, q=549824583172097,g=15,s=31337):
        """Simple recursive poly/vector/matrix checksum routine."""
        if isinstance(v, int):
            return ((g * s + v) % q)
        elif isinstance(v, list):
            for x in v:
                s = chksum(x,q=q,g=g,s=s)
        return s

    def chkdim(v, s=''):
        t = v
        while isinstance(t, list):
            s += '[' + str(len(t)) + ']'
            t = t[0]
        s += ' = ' + str(chksum(v))
        return s

    #   one instance here for testing
    iut = Raccoon(  bitsec=128, q=RACC_Q, nut=42, nuw=44, rep=4, ut=5,
                    uw=40, n=512, k=5, ell=4, w=19, d=8)

    #   initialize nist pseudo random
    entropy_input = bytes(range(48))
    drbg = NIST_KAT_DRBG(entropy_input)

    iut.set_random(drbg.random_bytes)
    iut.set_masking(MaskRandom().random_poly)

    print(f'name = {iut.name}')

    print("=== Keygen ===")
    msk, vk = iut.keygen()
    print(f"key: seed = {msk[0].hex().upper()}")
    print(chkdim(msk[1], 'key: t'))
    print(chkdim(msk[2], 'key: s'))

    print("=== Sign ===")
    mu = bytes(range(iut.mu_sz))

    sig = iut.sign_mu(msk, mu)
    print(f"sig: c_hash = {sig[0].hex().upper()}")
    print(chkdim(sig[1], 'sig: z'))
    print(chkdim(sig[2], 'sig: h'))

    print("=== Verify ===")
    rsp = iut.verify_mu(vk, mu, sig)
    print(rsp)
    assert(rsp is True)

