#ifndef PACKING_H
#define PACKING_H

#include <stdint.h>
#include "mldsa-params-avx2.h"
#include "mldsa-polyvec-avx2.h"

void pack_pk(uint8_t pk[CRYPTO_PUBLICKEYBYTES], const uint8_t rho[GCRY_MLDSA_SEEDBYTES], const polyveck *t1);

void pack_sk(uint8_t sk[CRYPTO_SECRETKEYBYTES],
             const uint8_t rho[GCRY_MLDSA_SEEDBYTES],
             const uint8_t tr[GCRY_MLDSA_TRBYTES],
             const uint8_t key[GCRY_MLDSA_SEEDBYTES],
             const polyveck *t0,
             const polyvecl *s1,
             const polyveck *s2);

void pack_sig(uint8_t sig[CRYPTO_BYTES], const uint8_t c[GCRY_MLDSA_SEEDBYTES], const polyvecl *z, const polyveck *h);

void unpack_pk(uint8_t rho[GCRY_MLDSA_SEEDBYTES], polyveck *t1, const uint8_t pk[CRYPTO_PUBLICKEYBYTES]);

void unpack_sk(uint8_t rho[GCRY_MLDSA_SEEDBYTES],
               uint8_t tr[GCRY_MLDSA_TRBYTES],
               uint8_t key[GCRY_MLDSA_SEEDBYTES],
               polyveck *t0,
               polyvecl *s1,
               polyveck *s2,
               const uint8_t sk[CRYPTO_SECRETKEYBYTES]);

int unpack_sig(uint8_t c[GCRY_MLDSA_SEEDBYTES], polyvecl *z, polyveck *h, const uint8_t sig[CRYPTO_BYTES]);

#endif
