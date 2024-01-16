#ifndef POLYVEC_H
#define POLYVEC_H

#include <stdint.h>
#include "mlkem-params-avx2.h"
#include "mlkem-params.h"
#include "mlkem-poly-avx2.h"

#define MAX_K 4 // TODO: remove
typedef struct{
  poly vec[MAX_K];
} polyvec;

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
