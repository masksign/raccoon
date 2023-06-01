//  racc_serial.h
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//  === Raccoon signature scheme -- Serialize/deserialize.

#ifndef _RACC_SERIAL_H_
#define _RACC_SERIAL_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "racc_param.h"

//  === Global namespace prefix

#ifdef RACC_
#define racc_encode_pk RACC_(encode_pk)
#define racc_decode_pk RACC_(decode_pk)
#define racc_encode_sk RACC_(encode_sk)
#define racc_decode_sk RACC_(decode_sk)
#define racc_encode_sig RACC_(encode_sig)
#define racc_decode_sig RACC_(decode_sig)
#endif

#ifdef __cplusplus
extern "C" {
#endif

//  Encode public key "pk" to bytes "b". Return length in bytes.
size_t racc_encode_pk(uint8_t *b, const racc_pk_t *pk);

//  Decode a public key from "b" to "pk". Return length in bytes.
size_t racc_decode_pk(racc_pk_t *pk, const uint8_t *b);

//  Encode secret key "sk" to bytes "b". Return length in bytes.
size_t racc_encode_sk(uint8_t *b, const racc_sk_t *sk);

//  Decode a secret key from "b" to "sk". Return length in bytes.
size_t racc_decode_sk(racc_sk_t *sk, const uint8_t *b);

//  Encode signature "sig" to "*b" of max "b_sz" bytes. Return length in
//  bytes or zero in case of overflow.
size_t racc_encode_sig(uint8_t *b, size_t b_sz, const racc_sig_t *sig);

//  decode bytes "b" into signature "sig". Return length in bytes.
size_t racc_decode_sig(racc_sig_t *sig, const uint8_t *b);

#ifdef __cplusplus
}
#endif

//  _RACC_SERIAL_H_
#endif
