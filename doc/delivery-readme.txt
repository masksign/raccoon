RACCOON File Inventory
======================
2023-05-31

Algorithm Specification (and Supporting Documentation):

    Supporting_Documentation/raccoon.pdf

The Cover Sheet and Intellectual Property Statements/Agreements/Disclosures
are provided in directory Supporting_Documentation/Statements/

    CoverSheet.pdf                 IP-MouhartemFabrice.pdf
    Implementation-SaarinenMJ.pdf  IP-PrestThomas.pdf
    IP-delPinoRafael.pdf           IP-RossiMelissa.pdf
    IP-EspitauThomas.pdf           IP-SaarinenMJ.pdf
    IP-MallerMary.pdf              PatentOwner-ElKaafaraniAli.pdf


Implementations
---------------

The Raccoon implementation comes in 18 variants for three cryptanalytic
security levels and six side-channel security levels.

    Raccoon-128-1   Raccoon-128-2   Raccoon-128-4
    Raccoon-128-8   Raccoon-128-16  Raccoon-128-32
    Raccoon-192-1   Raccoon-192-2   Raccoon-192-4
    Raccoon-192-8   Raccoon-192-16  Raccoon-192-32
    Raccoon-256-1   Raccoon-256-2   Raccoon-256-4
    Raccoon-256-8   Raccoon-256-16  Raccoon-256-32

The code subdirectories are organized as:

    Reference_Implementation/Raccoon-*-*    ANSI C Reference Implementation
    Optimized_Implementation/Raccoon-*-*    Exactly same code

The contents of all of these directories are equivalent apart from
`param_select.h`, which defines the variant used.

Inventory:

    api.h               NIST API Definitions
    build-kat.sh        Build a KAT generator executable
    clean-kat.sh        Cleanup KAT generator
    ct_util.c           Generic constant time utilities
    ct_util.h           "
    keccakf1600.c       Keccak permutation for a "generic 64-bit" target
    keccakf1600.h       "
    LICENSE             MIT License
    mask_random.c       Mask random generator (dummy implementations)
    mask_random.h       "
    mont32.h            Portable 32-bit Montgomery arithmetic
    mont64.h            Portable 64-bit Montgomery arithmetic
    nist_random.h       Wrapper to rng.h
    ntt32.c             32-bit Number Theoretic Transform
    ntt64.c             64-bit Number Theoretic Transform
    param_list.h        All parameter sets
    param_select.h      Single-line file that selects the parameter set
    plat_local.h        Local platform helper macros
    polyr.c             Polynomial arithmetic and ring Zq[x]/(x^n+1)
    polyr.h             "
    PQCgenKAT_sign.c    NIST KAT Generator main()
    racc_api.c          Raccoon signature scheme -- NIST KAT Generator API
    racc_core.c         Raccoon signature scheme -- Core scheme
    racc_core.h         Raccoon signature scheme -- Core internal API
    racc_param.h        Raccoon signature scheme -- Derived parameters
    racc_serial.c       Raccoon signature scheme -- Serialize/deserialize
    racc_serial.h       "
    README.txt          This file
    rng.c               NIST KAT Generator DRBG
    rng.h               "
    sha3_t.c            Common wrappers for  SHA3 (FIPS 202) functionality
    sha3_t.h            "
    xof_sample.c        Raccoon signature scheme -- Samplers and XOF functions
    xof_sample.h        "


An additional reference python implementation is provided in

    Additional_Implementations/Python

Inventory:

    Makefile            Only target: make clean
    mask_random.py      Dummy Mask Random Generator (LFSR127 MRG)
    nist_kat_drbg.py    NIST KAT Generator DRBG
    polyr.py            Polynomial ring arithmetic + NTT code
    racc_api.py         Serializaton/deserialization, NIST style functions
    racc_core.py        Raccoon signature scheme -- Core Algorithm.
    README.md           Brief instructions
    requirements.txt    Python requirements: pycryptodome
    test_genkat.py      Generate NIST KAT files (.rsp files)
    test_genlist.py     Prettyprint parameter lists for C for TeX
    test_histo.py       Used for signature encoding design
    test_ntt.py         Basic tests for NTT, also generate tweak tables


Known Answer Test values
------------------------

The NIST KAT files (.req and .rsp files) are contained under KAT/Raccoon-*-*
Here are the SHA-256 hashes of the response files:

    KAT/Raccoon-128-1/PQCsignKAT_14800.rsp:
        039383b9d9b29c5a9cda63cb93666771c7c09791afaadc941341e0df670229e0

    KAT/Raccoon-128-2/PQCsignKAT_14816.rsp:
        71586c2fd1ae47f17cb5c44c2b5351ab48531344041a76357ffc695098d2506c

    KAT/Raccoon-128-4/PQCsignKAT_14848.rsp:
        ae6e775feaf9d26eac5d10bec3c742fb7ab8f6716ee96a2ce3cf2c3aa23b8ef0

    KAT/Raccoon-128-8/PQCsignKAT_14912.rsp:
        ffbd4df642d15da96624e2b8489b5303a97a7f6a5d60416c72108880746394ea

    KAT/Raccoon-128-16/PQCsignKAT_15040.rsp:
        579fbaafde26049c4f4993b28568abfb657da76e5cd0c7a83239e37d4cc43325

    KAT/Raccoon-128-32/PQCsignKAT_15296.rsp:
        dff454bf03e9c027d70d4443bb394cae3c5af23ed81179889a62bf98a8a916d8

    KAT/Raccoon-192-1/PQCsignKAT_18840.rsp:
        bb577467a15ff20d6ac88c3eb7ba3fd6b3a3e7bf8e5bc627890bb027bba8bda5

    KAT/Raccoon-192-2/PQCsignKAT_18864.rsp:
        1543992c77e4a3ee08cd93daf1044e2d7816efbb6c572f167e500ee5b6e68d02

    KAT/Raccoon-192-4/PQCsignKAT_18912.rsp:
        82f2b834889bacdbcbb48d51f99c15639a235a764714ba858b415fdf546c9dbc

    KAT/Raccoon-192-8/PQCsignKAT_19008.rsp:
        b21ecba12cafa88a8337a813e9dac131a50f043f860241f7cd36f8b502233971

    KAT/Raccoon-192-16/PQCsignKAT_19200.rsp:
        57e3c6d014c7283806f4cd3d9c83737c6d381202a1649042c499c5c354f7606b

    KAT/Raccoon-192-32/PQCsignKAT_19584.rsp:
        49a552559d6a68175996de373232e0863496834c16b4d2772781f0e01469b621

    KAT/Raccoon-256-1/PQCsignKAT_26016.rsp:
        031d4976f4c09b90ecec5c535b5ab3bcb020b9cb4f95e17dfdcedb10de1425fc

    KAT/Raccoon-256-2/PQCsignKAT_26048.rsp:
        8936afaf3fd6cf5b43716e006977e1c14a2624913bfd23adb850aa141ef2ae91

    KAT/Raccoon-256-4/PQCsignKAT_26112.rsp:
        2e3ae8a29435ce8621a98390874fa2193756c87741f02934018650163c57e369

    KAT/Raccoon-256-8/PQCsignKAT_26240.rsp:
        893bf614327740610c29781db7973bbfa7069010039bfa9b2ba02a9a675a78ab

    KAT/Raccoon-256-16/PQCsignKAT_26496.rsp:
        663ce05beb35184b0012e638ed8c918f945b379a9bd35a97e37141798c320acf

    KAT/Raccoon-256-32/PQCsignKAT_27008.rsp:
        594169ee1ddc6238fbbfae0178d0ed8fab9eb0205066fe382f6ff788c775bd58

