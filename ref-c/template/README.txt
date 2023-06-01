RACCOON -- ANSI C REFERENCE IMPLEMENTATION

The directories Reference_Implementation/* and Optimized_Implementation/* are
equivalent apart from `param_select.h`, which defines the variant used.

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

