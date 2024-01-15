#ifndef POLYVEC_H
#define POLYVEC_H

#include <stdint.h>
#include "mlkem-params-avx2.h"
#include "mlkem-params.h"
#include "mlkem-poly-avx2.h"

typedef struct{
  poly vec[KYBER_K];
} polyvec;

void polyvec_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES+2], const polyvec *a, const gcry_mlkem_param_t *param);
void polyvec_decompress(polyvec *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES+12], const gcry_mlkem_param_t *param);

void polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], const polyvec *a, const gcry_mlkem_param_t *param);
void polyvec_frombytes(polyvec *r, const uint8_t a[KYBER_POLYVECBYTES], const gcry_mlkem_param_t *param);

void polyvec_ntt(polyvec *r, const gcry_mlkem_param_t *param);
void polyvec_invntt_tomont(polyvec *r, const gcry_mlkem_param_t *param);

void polyvec_basemul_acc_montgomery(poly *r, const polyvec *a, const polyvec *b, const gcry_mlkem_param_t *param);

void polyvec_reduce(polyvec *r, const gcry_mlkem_param_t *param);

void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b, const gcry_mlkem_param_t *param);

#endif
