#ifndef _GCRY_MLDSA_PACKING_H
#define _GCRY_MLDSA_PACKING_H

#include "types.h"
#include "mldsa-params.h"
#include "mldsa-polyvec.h"

void _gcry_mldsa_pack_pk (gcry_mldsa_param_t *params,
                          byte *pk,
                          const byte rho[GCRY_MLDSA_SEEDBYTES],
                          const gcry_mldsa_polyvec *t1);

void _gcry_mldsa_pack_sk (gcry_mldsa_param_t *params,
                          byte *sk,
                          const byte rho[GCRY_MLDSA_SEEDBYTES],
                          const byte tr[GCRY_MLDSA_TRBYTES],
                          const byte key[GCRY_MLDSA_SEEDBYTES],
                          const gcry_mldsa_polyvec *t0,
                          const gcry_mldsa_polyvec *s1,
                          const gcry_mldsa_polyvec *s2);

void _gcry_mldsa_pack_sig (
    gcry_mldsa_param_t *params, byte *sig, const byte *c, const gcry_mldsa_polyvec *z, const gcry_mldsa_polyvec *h);

void _gcry_mldsa_unpack_pk (gcry_mldsa_param_t *params,
                            byte rho[GCRY_MLDSA_SEEDBYTES],
                            gcry_mldsa_polyvec *t1,
                            const byte *pk);

void _gcry_mldsa_unpack_sk (gcry_mldsa_param_t *params,
                            byte rho[GCRY_MLDSA_SEEDBYTES],
                            byte tr[GCRY_MLDSA_TRBYTES],
                            byte key[GCRY_MLDSA_SEEDBYTES],
                            gcry_mldsa_polyvec *t0,
                            gcry_mldsa_polyvec *s1,
                            gcry_mldsa_polyvec *s2,
                            const byte *sk);

int _gcry_mldsa_unpack_sig (
    gcry_mldsa_param_t *params, byte *c, gcry_mldsa_polyvec *z, gcry_mldsa_polyvec *h, const byte *sig);

#endif
