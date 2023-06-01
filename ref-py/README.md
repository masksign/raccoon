#   raccoon/ref-py

Copyright (c) 2023 Raccoon Signature Team. See LICENSE.
*(Original Code was written by Thomas Prest and Markku-Juhani O. Saarinen.)*

Python implementation of Masked Raccoon, aimed at readability.

Test: `python3 test_genkat.py`: Generate .rsp KAT files for all variants.

```
Makefile            Only target: make clean
mask_random.py      Dummy Mask Random Generator (LFSR127 MRG)
nist_kat_drbg.py    NIST KAT Generator DRBG
polyr.py            Polynomial ring arithmetic + NTT code
racc_api.py         Serializaton/deserialization, NIST style functions
racc_core.py        Raccoon signature scheme -- Core Algorithm.
README.md           This file
requirements.txt    Python requirements: pycryptodome
test_genkat.py      Generate NIST KAT files (.rsp files)
test_genlist.py     Prettyprint parameter lists for C for TeX
test_histo.py       Used for signature encoding design
test_ntt.py         Basic tests for NTT, also generate tweak tables
```

