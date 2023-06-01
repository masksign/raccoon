//  test_main.c
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//  === private tests and benchmarks

#ifndef NIST_KAT

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "plat_local.h"
#include "racc_core.h"
#include "nist_random.h"
#include "mask_random.h"
#include "racc_serial.h"
#include "mont64.h"
#include "polyr.h"
#include "sha3_t.h"

#include "api.h"

//  [debug] (shake) checksums of data

void dbg_chk(const char  *label, uint8_t *data, size_t data_sz)
{
    size_t i;
    uint8_t md[16] = {0};

    shake256(md, sizeof(md), data, data_sz);
    printf("%s: ", label);
    for (i = 0; i < sizeof(md); i++) {
        printf("%02x", md[i]);
    }
    printf(" (%zu)\n", data_sz);
}

//  [debug] dump a hex string

void dbg_hex(const char *label, const uint8_t *data, size_t data_sz)
{
    size_t i;
    printf("%s= ", label);
    for (i = 0; i < data_sz; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

//  standard library process time

static inline double cpu_clock_secs()
{
    return ((double)clock()) / ((double)CLOCKS_PER_SEC);
}

//  maximum message size
#define MAX_MSG 256

int main()
{
    size_t i;

    //  message to be signed (used in checksums)
    uint8_t msg[MAX_MSG] = "abc";
    size_t mlen = 3;

    //  timing
    size_t iter = 100;
    double ts, to;
    uint64_t cc;

    int fail = 0;

    //  buffers for serialized
    uint8_t pk[CRYPTO_PUBLICKEYBYTES] = {0};
    uint8_t sk[CRYPTO_SECRETKEYBYTES] = {0};
    uint8_t sm[CRYPTO_BYTES + MAX_MSG] = {0};
    uint8_t m2[MAX_MSG] = {0};
    unsigned long long smlen = 0;
    unsigned long long mlen2 = 0;

    //  masking random
    fail += mask_random_selftest();
    if (fail > 0) {
        printf("mask_random_selftest() fail= %d\n", fail);
    }

    //  initialize nist pseudo random
    uint8_t seed[48];
    for (i = 0; i < 48; i++) {
        seed[i] = i;
    }
    nist_randombytes_init(seed, NULL, 256);

    //  (start)
    printf("CRYPTO_ALGNAME\t= %s\n", CRYPTO_ALGNAME);
    printf("CRYPTO_PUBLICKEYBYTES\t= %d\n", CRYPTO_PUBLICKEYBYTES);
    printf("CRYPTO_SECRETKEYBYTES\t= %d\n", CRYPTO_SECRETKEYBYTES);
    printf("CRYPTO_BYTES\t\t= %d\n", CRYPTO_BYTES);

    //  === keygen ===
    crypto_sign_keypair(pk, sk);
    dbg_chk(CRYPTO_ALGNAME ".pk", pk, CRYPTO_PUBLICKEYBYTES);
    dbg_chk(CRYPTO_ALGNAME ".sk", sk, CRYPTO_SECRETKEYBYTES);

    //  === sign ===
    smlen = 0;
    crypto_sign(sm, &smlen, msg, mlen, sk);
    dbg_chk(CRYPTO_ALGNAME ".sm", sm, (size_t) smlen);

    //  === verify ===
    mlen2 = 0;
    memset(m2, 0, sizeof(m2));
    fail += crypto_sign_open(m2, &mlen2, sm, smlen, pk) == 0 ? 0 : 1;
    fail += (mlen == mlen2 && memcmp(msg, m2, mlen) == 0) ? 0 : 1;

    sm[123]++;  //  corrupt it -- expect fail
    fail += crypto_sign_open(m2, &mlen2, sm, smlen, pk) != 0 ? 0 : 1;

    printf("verify fail= %d\n", fail);

#ifdef BENCH_TIMEOUT
    to = BENCH_TIMEOUT;
#else
    to = 1.0;  //   timeout threshold (seconds)
#endif

    printf("=== Bench ===\n");

    iter = 16;
    do {
        iter *= 2;
        ts = cpu_clock_secs();
        cc = plat_get_cycle();

        for (i = 0; i < iter; i++) {
            crypto_sign_keypair(pk, sk);
        }
        cc = plat_get_cycle() - cc;
        ts = cpu_clock_secs() - ts;
    } while (ts < to);
    printf("%s\tKeyGen() %5zu:\t%8.3f ms\t%8.3f Mcyc\n", CRYPTO_ALGNAME, iter,
           1000.0 * ts / ((double)iter), 1E-6 * ((double) (cc / iter)));

    iter = 16;
    do {
        iter *= 2;
        crypto_sign_keypair(pk, sk);
        ts = cpu_clock_secs();
        cc = plat_get_cycle();

        for (i = 0; i < iter; i++) {
            crypto_sign(sm, &smlen, msg, mlen, sk);
        }
        cc = plat_get_cycle() - cc;
        ts = cpu_clock_secs() - ts;
    } while (ts < to);
    printf("%s\t  Sign() %5zu:\t%8.3f ms\t%8.3f Mcyc\n", CRYPTO_ALGNAME, iter,
           1000.0 * ts / ((double)iter), 1E-6 * ((double) (cc / iter)));

    iter = 16;
    do {
        iter *= 2;
        crypto_sign_keypair(pk, sk);
        crypto_sign(sm, &smlen, msg, mlen, sk);
        crypto_sign(sm, &smlen, msg, mlen, sk);
        ts = cpu_clock_secs();
        cc = plat_get_cycle();

        //  repeats the same verify..
        for (i = 0; i < iter; i++) {
            fail += crypto_sign_open(m2, &mlen2, sm, smlen, pk) == 0 ? 0 : 1;
        }
        cc = plat_get_cycle() - cc;
        ts = cpu_clock_secs() - ts;
    } while (ts < to);
    printf("%s\tVerify() %5zu:\t%8.3f ms\t%8.3f Mcyc\n", CRYPTO_ALGNAME, iter,
           1000.0 * ts / ((double)iter), 1E-6 * ((double) (cc / iter)));

    return 0;
}

// NIST_KAT
#endif
