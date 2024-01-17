#ifndef POLYVEC_H
#define POLYVEC_H

#include <stdint.h>
#include "mlkem-params-avx2.h"
#include "mlkem-params.h"
#include "mlkem-poly-avx2.h"
#include "mlkem-polyvec.h"


#define MAX_K 4 // TODO: remove
typedef struct{
  poly vec[MAX_K];
} polyvec;

typedef struct
{
  polyvec *vec;
  byte *alloc_addr;
} gcry_mlkem_polyvec_al;

gcry_err_code_t _gcry_mlkem_polyvec_al_create (gcry_mlkem_polyvec_al *polyvec,
                                               size_t num_elems,
                                               size_t size_elems,
                                               int secure);
void _gcry_mlkem_polyvec_al_destroy (gcry_mlkem_polyvec_al *polyvec);

void polyvec_compress(uint8_t *r, const polyvec *a, const gcry_mlkem_param_t *param);
void polyvec_decompress(polyvec *r, const uint8_t *a, const gcry_mlkem_param_t *param);

void polyvec_tobytes(uint8_t *r, const polyvec *a, const gcry_mlkem_param_t *param);
void polyvec_frombytes(polyvec *r, const uint8_t *a, const gcry_mlkem_param_t *param);

void polyvec_ntt(polyvec *r, const gcry_mlkem_param_t *param);
void polyvec_invntt_tomont(polyvec *r, const gcry_mlkem_param_t *param);

void polyvec_basemul_acc_montgomery(poly *r, const polyvec *a, const polyvec *b, const gcry_mlkem_param_t *param);

void polyvec_reduce(polyvec *r, const gcry_mlkem_param_t *param);

void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b, const gcry_mlkem_param_t *param);

#endif
