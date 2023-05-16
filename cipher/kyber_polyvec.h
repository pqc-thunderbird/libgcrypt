#ifndef POLYVEC_H
#define POLYVEC_H

#include <config.h>
#include <stdint.h>
#include "kyber_params.h"
#include "kyber_poly.h"
#include "g10lib.h"

typedef struct{
  poly *vec;
} gcry_kyber_polyvec;


gcry_error_t gcry_kyber_polymatrix_create(gcry_kyber_polyvec **polymat, gcry_kyber_param_t const* param);
void gcry_kyber_polymatrix_destroy(gcry_kyber_polyvec **polymat, gcry_kyber_param_t const* param);

gcry_error_t gcry_kyber_polyvec_create(gcry_kyber_polyvec *polyvec, gcry_kyber_param_t const* param);
void gcry_kyber_polyvec_destroy(gcry_kyber_polyvec *polyvec);

void gcry_kyber_polyvec_compress(uint8_t* r, const gcry_kyber_polyvec *a, gcry_kyber_param_t const* param);
void gcry_kyber_polyvec_decompress(gcry_kyber_polyvec *r, const uint8_t* a, gcry_kyber_param_t const* param);


void gcry_kyber_polyvec_tobytes(uint8_t* r, const gcry_kyber_polyvec *a, gcry_kyber_param_t const* param);
void gcry_kyber_polyvec_frombytes(gcry_kyber_polyvec *r, const uint8_t* a, gcry_kyber_param_t const* param);

void gcry_kyber_polyvec_ntt(gcry_kyber_polyvec *r, gcry_kyber_param_t const* param);
void gcry_kyber_polyvec_invntt_tomont(gcry_kyber_polyvec *r, gcry_kyber_param_t const* param);

void gcry_kyber_polyvec_basemul_acc_montgomery(poly *r, const gcry_kyber_polyvec *a, const gcry_kyber_polyvec *b, gcry_kyber_param_t const* param);

void gcry_kyber_polyvec_reduce(gcry_kyber_polyvec *r, gcry_kyber_param_t const* param);

void gcry_kyber_polyvec_add(gcry_kyber_polyvec *r, const gcry_kyber_polyvec *a, const gcry_kyber_polyvec *b, gcry_kyber_param_t const* param);

#endif
