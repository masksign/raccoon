#!/usr/bin/env python3

"""
test_genkat.py
Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

=== Generate NIST KAT files compatible with the C reference implementaiton.
"""

import sys,fnmatch
from nist_kat_drbg import NIST_KAT_DRBG
from racc_api import *

#   This is intended to match the .rsp output from NIST PQCgenKAT_sign.c

def nist_kat_rsp(iut, katnum=100):
    """Create a test vector string matching official NIST KATs."""

    def _fmt_int(fh, label, n):
        fh.write(f"{label} = {n}\n")

    def _fmt_hex(fh, label, data):
        fh.write(f"{label} = {data.hex().upper()}\n")

    #   kat files are named based on secret key length in the nist suite
    fn = f"PQCsignKAT_{iut.sk_sz}.rsp"
    with open(fn, "w") as fh:

        #   KAT response file (no need for the request file here)
        fh.write(f"# {iut.name}\n\n")

        entropy_input = bytes([i for i in range(48)])
        drbg = NIST_KAT_DRBG(entropy_input)

        for count in range(katnum):

            print(f"{iut.name}: {fn} writing {count+1}/{katnum}.")

            _fmt_int(fh, "count", count)
            seed = drbg.random_bytes(48)
            _fmt_hex(fh, "seed", seed)
            mlen = 33 * (count + 1)
            _fmt_int(fh, "mlen", mlen)
            msg = drbg.random_bytes(mlen)
            _fmt_hex(fh, "msg", msg)

            #   force deterministic
            iut.set_random(NIST_KAT_DRBG(seed).random_bytes)

            pk, sk = iut.byte_keygen()
            _fmt_hex(fh, "pk", pk)
            _fmt_hex(fh, "sk", sk)

            sm = iut.byte_sign(msg, sk)
            _fmt_int(fh, "smlen", len(sm))
            _fmt_hex(fh, "sm", sm)
            fh.write('\n')
            assert iut.byte_open(sm, sk) == (True, msg)

def checksums(iut):
    """Print quick version-control checksums."""

    def _chkdata(label, data):
        print(f'{label}: ' +
                SHAKE256.new(bytes(data)).read(16).hex() +
                f' ({len(data)})')

    def _hexdump(data):
        s = ''
        for i in range(len(data)):
            if i % 16 == 0:
                print(s)
                s = f'{i:08x}'
            if i % 8 == 0:
                s += ' '
            s += f' {data[i]:02x}'
        print(s)

    iut.set_random(NIST_KAT_DRBG(bytes([i for i in range(48)])).random_bytes)

    pk, sk = iut.byte_keygen()
    _chkdata(iut.name + ".pk", pk)
    _chkdata(iut.name + ".sk", sk)

    msg = b'abc'
    sm = iut.byte_sign(msg, sk)
    _chkdata(iut.name + ".sm", sm)
    assert iut.byte_open(sm, sk) == (True,msg)

if __name__ == '__main__':
    if len(sys.argv) <= 1:

        #   no arguments -- just generate all NIST KAT files
        for iut in raccoon_all:
            nist_kat_rsp(iut)

    else:
        #   quick checksums
        for name in sys.argv[1:]:
            match = False
            for iut in raccoon_all:
                if fnmatch.fnmatch(iut.name, name):
                    match = True
                    checksums(iut)
            if not match:
                print('Not found:', name)
                print('Here are the IUT options:')
                for iut in raccoon_all:
                    print(iut.name)
                exit(0)
