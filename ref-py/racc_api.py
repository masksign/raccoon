"""
racc_api.py
Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

=== Masked Raccoon signature scheme: Serialization, parameters, BUFF interface.
"""

from Crypto.Hash import SHAKE256
from nist_kat_drbg import NIST_KAT_DRBG
from mask_random import MaskRandom
from racc_core import Raccoon
from polyr import *

#   Encoding and decoding methods for NIST Test Vectors

class NIST_Raccoon(Raccoon):

    def __init__(self, *args, **kwargs):
        """This is a subclass that provides serialization and BUFF."""
        super().__init__(*args, **kwargs)

        #   nist serialization sizes
        self.pk_sz  =   (self.as_sz +
                            self.k * self.n * (self.q_bits - self.nut) // 8)
        self.sk_sz  =   (self.pk_sz + (self.d - 1) * self.mk_sz +
                            (self.ell * self.n * self.q_bits) // 8)

        #   set fixed signature sizes and the number of signature queries
        if self.sec == 16:
            self.sig_sz = 11524
            self.nsigqs = 53
        elif self.sec == 24:
            self.sig_sz = 14544
            self.nsigqs = 51
        elif self.sec == 32:
            self.sig_sz = 20330
            self.nsigqs = 55

    @staticmethod
    def _encode_bits(v, bits):
        """Encode vector v of integers into bytes, 'bits' per element."""
        x = 0                           # bit buffer
        l = 0                           # number of bits in x
        i = 0                           # index in vector v[i]
        b = b''                         # zero-length array of bytes
        m = (1 << bits) - 1             # bit mask

        while i < len(v):
            while l < 8 and i < len(v):
                x |= (v[i] & m) << l    # load an integer into x
                i += 1
                l += bits
            while l >= 8:
                b += bytes([x & 0xFF])  # store a bytes from x
                x >>= 8
                l -= 8
        if l > 0:
            b += bytes([x])             # a byte with leftover bits

        return b

    """
    #   this is functionally equivalent but slower -- O(n^2)!
    @staticmethod
    def _encode_bits(v, bits):
        x = 0                   # bit buffer
        m = (1 << bits) - 1     # bit mask; "bits" ones
        for i in range(len(v)):
            x |= (v[i] & m) << (bits * i)
        return x.to_bytes( (bits * len(v) + 7) // 8, byteorder='little' )
    """

    @staticmethod
    def _decode_bits(b, bits, n, is_signed=False):
        """
        Decode bytes from 'b' into a vector of 'n' integers, 'bits' each.
        """
        x = 0                           # bit buffer
        i = 0                           # source byte index b[i]
        v = []                          # zero-length result vector
        l = 0                           # number of bits in x

        if is_signed:
            s = 1 << (bits - 1)         # sign bit is negative
            m = s - 1                   # mask bits-1 bits
        else:
            s = 0                       # unsigned: no sign bit
            m = (1 << bits) - 1         # mask given number of bits

        while len(v) < n:
            while l < bits:             # read bytes until full integer
                x |= int(b[i]) << l
                i += 1
                l += 8
            while l >= bits and len(v) < n: # write integer(s)
                v += [ (x & m) - (x & s) ]
                x >>= bits
                l -= bits

        return v, i     #   return the vector and number of bytes read

    def encode_pk(self, vk):
        """Serialize the signature verification (public) key."""
        (seed, t) = vk
        b = seed
        for ti in t:
            b += self._encode_bits(ti, self.q_bits - self.nut)
        return b

    def encode_sk(self, msk):
        """Serialize the masked signing key."""
        (seed, t, s) = msk

        #   encode public key
        b = self.encode_pk((seed, t))

        #   copy share 0
        s0 = [ s[i][0].copy() for i in range(self.ell) ]

        #   encode keys for shares 1, 2, ..., d-1
        for j in range(1, self.d):

            #   key_j for share j
            key =   self.random_bytes(self.mk_sz)
            b   +=  key

            #   update share 0
            for i in range(self.ell):
                #   XOF( 'K' || index i || index j || (0 pad) || key_j )
                xof_in  = bytes([ord('K'), i, j, 0, 0, 0, 0, 0]) + key

                r       = self._xof_sample_q(xof_in)
                s0[i]   = poly_sub(s0[i], r)
                s0[i]   = poly_add(s0[i], s[i][j])

        #   encode share 0
        for s0i in s0:
            b += self._encode_bits(s0i, self.q_bits)

        return b

    def decode_pk(self, b):
        """Decode the verification key from bytes."""
        seed = b[0:self.as_sz]
        l = len(seed)
        t = []
        for i in range(self.k):
            p,pl = self._decode_bits(b[l:], self.q_bits - self.nut, self.n);
            t += [p]
            l += pl
        vk = (seed, t)

        #   compute the "tr" hash from serialized public key
        tr = SHAKE256.new(b[0:l]).read(self.tr_sz)

        return vk, tr, l

    def decode_sk(self, b):
        """Decode a signing key from bytes."""

        #   decode public key
        vk, tr, l = self.decode_pk(b)
        seed, t = vk

        #   expand shares 1, 2, .. d-1
        ms = [[None for _ in range(self.d)] for _ in range(self.ell)]

        for j in range(1, self.d):
            key =   b[l:l+self.mk_sz]
            l   +=  self.mk_sz
            for i in range(self.ell):
                #   XOF( 'K' || index i || index j || (0 pad)  || key_j )
                xof_in  = bytes([ord('K'), i, j, 0, 0, 0, 0, 0]) + key
                ms[i][j]    = self._xof_sample_q(xof_in)

        #   decode share zero
        for i in range(self.ell):
            ms[i][0],sl =   self._decode_bits(b[l:], self.q_bits, self.n)
            l           +=  sl

        msk = (seed, t, ms)
        return msk, tr, l

    def _bits_enc_h(self, h):
        """Signature h component encoding into bits"""
        b = []
        for x in h:
            if x == 0:
                b += [ 0 ]              #   zero is encoded to a bit
            else:
                b += [ 1 ] * abs(x)     #   run of ones
                if x >= 0:              #   stop bit and sign
                    b += [0, 0]
                else:
                    b += [0, 1]
        return b

    def _bits_dec_h(self, b):
        """Signature h component decoding into integers"""
        i = 0
        h = []
        for _ in range(self.n):
            x = 0
            while b[i] == 1:            #   count ones
                x += 1
                i += 1
            i += 1                      #   stop bit (0)
            if x != 0:                  #   have a sign bit if x non-zero
                if b[i] == 1:
                    x = -x
                i += 1
            h += [ x ]
        return h, i                     #   also return read length i

    def _bits_enc_z(self, z, low_bits=40):
        """Signature z component encoding into bits"""
        b = []
        for x in z:
            x %= self.q
            if x == 0:                  #   no sign bit for x == 0
                sgn = None
            elif x > self.q // 2:       #   negative half
                sgn = 1                 #   set sign
                x = self.q - x          #   absolute value
            else:                       #   positive half
                sgn = 0
            for _ in range(low_bits):   #   low bits verbatim
                b += [ x & 1 ]
                x >>= 1
            b += [ 1 ] * x              #   high bits as a run
            b += [ 0 ]                  #   stop bit
            if sgn != None:             #   sign bit
                b += [ sgn ]
        return b

    def _bits_dec_z(self, b, low_bits=40):
        """Signature z component decoding into integers"""
        z = []
        i = 0
        for _ in range(self.n):
            x = 0
            for j in range(low_bits):   #   get low bits
                x += b[i + j] << j
            i += low_bits
            hi = 0
            while b[i] == 1:            #   decode hi bit run
                hi += 1
                i += 1
            i += 1                      #   stop bit (0)
            x += hi << low_bits
            if x > self.Boo:            #   check inf norm here due to mod q
                x = self.Boo + 1
            if x != 0:                  #   use sign if x != 0
                if b[i] == 1:           #   neaative
                    x = -x
                i += 1
            z += [ x % self.q ]
        return z,  i                    #   also return read length i

    def encode_sig(self, sig):
        """Serialize a signature as bytes. No zero padding / length check."""
        (c_hash, h, z) = sig
        s = c_hash                      #   challenge hash
        b = []                          #   bit string
        for hi in h:                    #   h bit strings
            b += self._bits_enc_h(hi)
        for zi in z:                    #   z bit strings
            b += self._bits_enc_z(zi)
        i = 0                           #   convert to bytes
        x = 0
        for bit in b:
            x += bit << i
            i += 1
            if i == 8:
                s += bytes([x])
                i = 0
                x = 0
        if i > 0:
            s += bytes([x])
        return s

    def decode_sig(self, s):
        """Deserialize a signature."""
        c_hash = s[0:self.ch_sz]        #   challenge hash
        b = []                          #   convert rest to a bit string
        for x in s[self.ch_sz:]:
            b += [ (x >> i) & 1 for i in range(8) ]
        h = [ None for _ in range(self.k) ]
        i = 0
        for j in range(self.k):
            h[j], l = self._bits_dec_h(b[i:])
            i   +=  l
        z = [ None for _ in range(self.ell) ]
        for j in range(self.ell):
            z[j], l = self._bits_dec_z(b[i:])
            i   +=  l
        sig = (c_hash, h, z)
        return sig

    def _buff_mu(self, tr, msg):
        """BUFF helper: mu = H( tr | msg ), where tr = H(pk)."""
        xof = SHAKE256.new(tr)
        xof.update(msg)
        return xof.read(self.mu_sz)

    #   interface that directly uses byte sequences

    def byte_keygen(self):
        """(API) Key pair generation directly into bytes."""
        msk, vk = self.keygen()
        return self.encode_pk(vk), self.encode_sk(msk)

    def byte_signature(self, msg, sk):
        """Detached signature generation directly from/to bytes."""
        msk, tr, _ = self.decode_sk(sk)
        mu = self._buff_mu(tr, msg)
        sig_b = []
        while len(sig_b) != self.sig_sz:
            sig = self.sign_mu(msk, mu)
            sig_b = self.encode_sig(sig)
            if len(sig_b) < self.sig_sz:
                sig_b += bytes([0] * (self.sig_sz - len(sig_b)))
        return sig_b

    def byte_verify(self, msg, sm, pk):
        """Detached Signature verification directly from bytes."""
        if len(sm) < self.sig_sz:
            return False
        vk, tr, _ = self.decode_pk(pk)
        sig = self.decode_sig(sm[0:self.sig_sz])
        mu = self._buff_mu(tr, msg)
        return self.verify_mu(vk, mu, sig)

    def byte_sign(self, msg, sk):
        """(API) Signature "envelope" generation directly from/to bytes."""
        sig = self.byte_signature(msg, sk)
        return sig + msg

    def byte_open(self, sm, pk):
        """(API) Signature verification directly from bytes."""
        msg = sm[self.sig_sz:]
        return self.byte_verify(msg, sm, pk), msg

### Instantiate Parameter sets

############################
### 128 bits of security ###
############################
raccoon_128_1  = NIST_Raccoon(bitsec=128, q=RACC_Q, nut=42, nuw=44, rep=8,
                                ut=6, uw=41, n=512, k=5, ell=4, w=19, d=1)
raccoon_128_2  = NIST_Raccoon(bitsec=128, q=RACC_Q, nut=42, nuw=44, rep=4,
                                ut=6, uw=41, n=512, k=5, ell=4, w=19, d=2)
raccoon_128_4  = NIST_Raccoon(bitsec=128, q=RACC_Q, nut=42, nuw=44, rep=2,
                                ut=6, uw=41, n=512, k=5, ell=4, w=19, d=4)
raccoon_128_8  = NIST_Raccoon(bitsec=128, q=RACC_Q, nut=42, nuw=44, rep=4,
                                ut=5, uw=40, n=512, k=5, ell=4, w=19, d=8)
raccoon_128_16 = NIST_Raccoon(bitsec=128, q=RACC_Q, nut=42, nuw=44, rep=2,
                                ut=5, uw=40, n=512, k=5, ell=4, w=19, d=16)
raccoon_128_32 = NIST_Raccoon(bitsec=128, q=RACC_Q, nut=42, nuw=44, rep=4,
                                ut=4, uw=39, n=512, k=5, ell=4, w=19, d=32)

############################
### 192 bits of security ###
############################
raccoon_192_1  = NIST_Raccoon(bitsec=192, q=RACC_Q, nut=42, nuw=44, rep=8,
                                ut=7, uw=41, n=512, k=7, ell=5, w=31, d=1)
raccoon_192_2  = NIST_Raccoon(bitsec=192, q=RACC_Q, nut=42, nuw=44, rep=4,
                                ut=7, uw=41, n=512, k=7, ell=5, w=31, d=2)
raccoon_192_4  = NIST_Raccoon(bitsec=192, q=RACC_Q, nut=42, nuw=44, rep=2,
                                ut=7, uw=41, n=512, k=7, ell=5, w=31, d=4)
raccoon_192_8  = NIST_Raccoon(bitsec=192, q=RACC_Q, nut=42, nuw=44, rep=4,
                                ut=6, uw=40, n=512, k=7, ell=5, w=31, d=8)
raccoon_192_16 = NIST_Raccoon(bitsec=192, q=RACC_Q, nut=42, nuw=44, rep=2,
                                ut=6, uw=40, n=512, k=7, ell=5, w=31, d=16)
raccoon_192_32 = NIST_Raccoon(bitsec=192, q=RACC_Q, nut=42, nuw=44, rep=4,
                                ut=5, uw=39, n=512, k=7, ell=5, w=31, d=32)

############################
### 256 bits of security ###
############################
raccoon_256_1  = NIST_Raccoon(bitsec=256, q=RACC_Q, nut=42, nuw=44, rep=8,
                                ut=6, uw=41, n=512, k=9, ell=7, w=44, d=1)
raccoon_256_2  = NIST_Raccoon(bitsec=256, q=RACC_Q, nut=42, nuw=44, rep=4,
                                ut=6, uw=41, n=512, k=9, ell=7, w=44, d=2)
raccoon_256_4  = NIST_Raccoon(bitsec=256, q=RACC_Q, nut=42, nuw=44, rep=2,
                                ut=6, uw=41, n=512, k=9, ell=7, w=44, d=4)
raccoon_256_8  = NIST_Raccoon(bitsec=256, q=RACC_Q, nut=42, nuw=44, rep=4,
                                ut=5, uw=40, n=512, k=9, ell=7, w=44, d=8)
raccoon_256_16 = NIST_Raccoon(bitsec=256, q=RACC_Q, nut=42, nuw=44, rep=2,
                                ut=5, uw=40, n=512, k=9, ell=7, w=44, d=16)
raccoon_256_32 = NIST_Raccoon(bitsec=256, q=RACC_Q, nut=42, nuw=44, rep=4,
                                ut=4, uw=39, n=512, k=9, ell=7, w=44, d=32)

##################################
### List of all parameter sets ###
##################################

raccoon_all = [ raccoon_128_1,  raccoon_128_2,  raccoon_128_4,
                raccoon_128_8,  raccoon_128_16, raccoon_128_32,
                raccoon_192_1,  raccoon_192_2,  raccoon_192_4,
                raccoon_192_8,  raccoon_192_16, raccoon_192_32,
                raccoon_256_1,  raccoon_256_2,  raccoon_256_4,
                raccoon_256_8,  raccoon_256_16, raccoon_256_32 ]

