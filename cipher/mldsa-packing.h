#ifndef _GCRY_MLDSA_PACKING_H
#define _GCRY_MLDSA_PACKING_H

#include <stdint.h>
#include "mldsa-params.h"
#include "mldsa-polyvec.h"

void _gcry_mldsa_pack_pk(gcry_mldsa_param_t *params, uint8_t *pk, const uint8_t rho[GCRY_MLDSA_SEEDBYTES], const gcry_mldsa_polyvec *t1);

void _gcry_mldsa_pack_sk(gcry_mldsa_param_t *params,
             uint8_t *sk,
             const uint8_t rho[GCRY_MLDSA_SEEDBYTES],
             const uint8_t tr[GCRY_MLDSA_SEEDBYTES],
             const uint8_t key[GCRY_MLDSA_SEEDBYTES],
             const gcry_mldsa_polyvec *t0,
             const gcry_mldsa_polyvec *s1,
             const gcry_mldsa_polyvec *s2);

void _gcry_mldsa_pack_sig(gcry_mldsa_param_t *params, uint8_t *sig, const uint8_t c[GCRY_MLDSA_SEEDBYTES], const gcry_mldsa_polyvec *z, const gcry_mldsa_polyvec *h);

void _gcry_mldsa_unpack_pk(gcry_mldsa_param_t *params, uint8_t rho[GCRY_MLDSA_SEEDBYTES], gcry_mldsa_polyvec *t1, const uint8_t *pk);

void _gcry_mldsa_unpack_sk(gcry_mldsa_param_t *params,
               uint8_t rho[GCRY_MLDSA_SEEDBYTES],
               uint8_t tr[GCRY_MLDSA_SEEDBYTES],
               uint8_t key[GCRY_MLDSA_SEEDBYTES],
               gcry_mldsa_polyvec *t0,
               gcry_mldsa_polyvec *s1,
               gcry_mldsa_polyvec *s2,
               const uint8_t *sk);

int _gcry_mldsa_unpack_sig(gcry_mldsa_param_t *params, uint8_t c[GCRY_MLDSA_SEEDBYTES], gcry_mldsa_polyvec *z, gcry_mldsa_polyvec *h, const uint8_t *sig);

#endif
