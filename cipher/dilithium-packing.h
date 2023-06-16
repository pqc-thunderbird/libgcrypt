#ifndef _GCRY_DILITHIUM_PACKING_H
#define _GCRY_DILITHIUM_PACKING_H

#include <stdint.h>
#include "dilithium-params.h"
#include "dilithium-polyvec.h"

void _gcry_dilithium_pack_pk(gcry_dilithium_param_t *params, uint8_t *pk, const uint8_t rho[GCRY_DILITHIUM_SEEDBYTES], const gcry_dilithium_polyvec *t1);

void _gcry_dilithium_pack_sk(gcry_dilithium_param_t *params,
             uint8_t *sk,
             const uint8_t rho[GCRY_DILITHIUM_SEEDBYTES],
             const uint8_t tr[GCRY_DILITHIUM_SEEDBYTES],
             const uint8_t key[GCRY_DILITHIUM_SEEDBYTES],
             const gcry_dilithium_polyvec *t0,
             const gcry_dilithium_polyvec *s1,
             const gcry_dilithium_polyvec *s2);

void _gcry_dilithium_pack_sig(gcry_dilithium_param_t *params, uint8_t *sig, const uint8_t c[GCRY_DILITHIUM_SEEDBYTES], const gcry_dilithium_polyvec *z, const gcry_dilithium_polyvec *h);

void _gcry_dilithium_unpack_pk(gcry_dilithium_param_t *params, uint8_t rho[GCRY_DILITHIUM_SEEDBYTES], gcry_dilithium_polyvec *t1, const uint8_t *pk);

void _gcry_dilithium_unpack_sk(gcry_dilithium_param_t *params,
               uint8_t rho[GCRY_DILITHIUM_SEEDBYTES],
               uint8_t tr[GCRY_DILITHIUM_SEEDBYTES],
               uint8_t key[GCRY_DILITHIUM_SEEDBYTES],
               gcry_dilithium_polyvec *t0,
               gcry_dilithium_polyvec *s1,
               gcry_dilithium_polyvec *s2,
               const uint8_t *sk);

int _gcry_dilithium_unpack_sig(gcry_dilithium_param_t *params, uint8_t c[GCRY_DILITHIUM_SEEDBYTES], gcry_dilithium_polyvec *z, gcry_dilithium_polyvec *h, const uint8_t *sig);

#endif
