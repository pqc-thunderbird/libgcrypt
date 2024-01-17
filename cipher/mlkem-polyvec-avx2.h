#ifndef POLYVEC_H
#define POLYVEC_H

#include <stdint.h>
#include "mlkem-params-avx2.h"
#include "mlkem-params.h"
#include "mlkem-poly-avx2.h"
#include "mlkem-polyvec.h"

typedef struct
{
  byte *vec;
  byte *alloc_addr;
} gcry_mlkem_polyvec_al;

gcry_err_code_t _gcry_mlkem_polyvec_al_create (gcry_mlkem_polyvec_al *vec,
                                               size_t num_elems,
                                               size_t size_elems,
                                               int secure);
void _gcry_mlkem_polyvec_al_destroy (gcry_mlkem_polyvec_al *vec);

void polyvec_compress(uint8_t *r, const byte *a, const gcry_mlkem_param_t *param);
void polyvec_decompress(byte *r, const uint8_t *a, const gcry_mlkem_param_t *param);

void polyvec_tobytes(uint8_t *r, const byte *a, const gcry_mlkem_param_t *param);
void polyvec_frombytes(byte *r, const uint8_t *a, const gcry_mlkem_param_t *param);

void polyvec_ntt(byte *r, const gcry_mlkem_param_t *param);
void polyvec_invntt_tomont(byte *r, const gcry_mlkem_param_t *param);

void polyvec_basemul_acc_montgomery(poly *r, const byte *a, const byte *b, const gcry_mlkem_param_t *param);

void polyvec_reduce(byte *r, const gcry_mlkem_param_t *param);

void polyvec_add(byte *r, const byte *a, const byte *b, const gcry_mlkem_param_t *param);

#endif
