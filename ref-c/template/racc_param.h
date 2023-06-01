//  racc_param.h
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//  === Raccoon signature scheme -- Derived parameters.

#ifndef _RACC_PARAM_H_
#define _RACC_PARAM_H_

//  select a default parameter if somehow not defied
#if !defined(NIST_KAT) && !defined(BENCH_TIMEOUT)
#include "param_select.h"
#endif

//  include the parameter list
#include "param_list.h"

//  Byte size of symmetric keys / pre-image security
#define RACC_SEC    (RACC_KAPPA / 8)

//  Byte size for collision resistant hashes
#define RACC_CRH    ((2 * RACC_KAPPA) / 8)

//  Size of A_seed
#define RACC_AS_SZ  RACC_SEC

//  Size of public key hash used in BUFFing -- needs CRH
#define RACC_TR_SZ  RACC_CRH

//  size of pk-bound message mu = H(H(pk), msg)
#define RACC_MU_SZ  RACC_CRH

//  Size of challenge hash
#define RACC_CH_SZ  RACC_CRH

//  Size of "mask keys" in serialized secret key
#define RACC_MK_SZ  RACC_SEC

//  shared / derived parameters
#if (RACC_Q == 549824583172097) && (RACC_N == 512)
#define RACC_Q_BITS 49
#define RACC_LGN    9
#else
#error  "No known parameter defined."
#endif

#define RACC_QMSK   ((1LL << RACC_Q_BITS) - 1)
#define RACC_LGW    (RACC_Q_BITS - RACC_NUW)
#define RACC_QT     (RACC_Q >> RACC_NUT)
#define RACC_QW     (RACC_Q >> RACC_NUW)

//  "low bits" in Z encoding
#define RACC_ZLBITS 40

//  scaled inifinity norm for hint
#define RACC_BOO_H  ((RACC_BOO + (1l << (RACC_NUW - 1))) >> RACC_NUW)

//  _RACC_PARAM_H_
#endif
