#ifndef POLYVEC_H
#define POLYVEC_H

#include <stdint.h>
#include "dilithium-params.h"
#include "dilithium-poly.h"
#include <config.h>
#include "g10lib.h"
typedef struct{
  poly *vec;
  //unsigned char vec_len;
} gcry_dilithium_polyvec;

gcry_error_t _gcry_dilithium_polymatrix_create(gcry_dilithium_polyvec **polymat, unsigned char mat_elems, unsigned char vec_elems);
void _gcry_dilithium_polymatrix_destroy(gcry_dilithium_polyvec **polymat, unsigned char elems);
gcry_error_t _gcry_dilithium_polyvec_create(gcry_dilithium_polyvec *polyvec, unsigned char elems);
gcry_error_t _gcry_dilithium_polyvec_copy(gcry_dilithium_polyvec *a, gcry_dilithium_polyvec *b, unsigned char elems);
void _gcry_dilithium_polyvec_destroy(gcry_dilithium_polyvec *polyvec);

void polyvecl_uniform_eta(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *v, const uint8_t seed[GCRY_DILITHIUM_CRHBYTES], uint16_t nonce);

void polyvecl_uniform_gamma1(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *v, const uint8_t seed[GCRY_DILITHIUM_CRHBYTES], uint16_t nonce);

void polyvecl_reduce(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *v);

void polyvecl_add(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *w, const gcry_dilithium_polyvec *u, const gcry_dilithium_polyvec *v);

void polyvecl_ntt(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *v);
void polyvecl_invntt_tomont(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *v);
void polyvecl_pointwise_poly_montgomery(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *r, const poly *a, const gcry_dilithium_polyvec *v);

void polyvecl_pointwise_acc_montgomery(gcry_dilithium_param_t *params,
                                       poly *w,
                                       const gcry_dilithium_polyvec *u,
                                       const gcry_dilithium_polyvec *v);


int polyvecl_chknorm(gcry_dilithium_param_t *params, const gcry_dilithium_polyvec *v, int32_t B);

void polyveck_uniform_eta(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *v, const uint8_t seed[GCRY_DILITHIUM_CRHBYTES], uint16_t nonce);

void polyveck_reduce(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *v);
void polyveck_caddq(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *v);

void polyveck_add(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *w, const gcry_dilithium_polyvec *u, const gcry_dilithium_polyvec *v);
void polyveck_sub(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *w, const gcry_dilithium_polyvec *u, const gcry_dilithium_polyvec *v);
void polyveck_shiftl(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *v);

void polyveck_ntt(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *v);
void polyveck_invntt_tomont(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *v);
void polyveck_pointwise_poly_montgomery(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *r, const poly *a, const gcry_dilithium_polyvec *v);

int polyveck_chknorm(gcry_dilithium_param_t *params, const gcry_dilithium_polyvec *v, int32_t B);

void polyveck_power2round(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *v1, gcry_dilithium_polyvec *v0, const gcry_dilithium_polyvec *v);
void polyveck_decompose(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *v1, gcry_dilithium_polyvec *v0, const gcry_dilithium_polyvec *v);
unsigned int polyveck_make_hint(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *h,
                                const gcry_dilithium_polyvec *v0,
                                const gcry_dilithium_polyvec *v1);
void polyveck_use_hint(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *w, const gcry_dilithium_polyvec *v, const gcry_dilithium_polyvec *h);

void polyveck_pack_w1(gcry_dilithium_param_t *params, uint8_t *r, const gcry_dilithium_polyvec *w1);

void polyvec_matrix_expand(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *mat, const uint8_t rho[GCRY_DILITHIUM_SEEDBYTES]);

void polyvec_matrix_pointwise_montgomery(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *t, const gcry_dilithium_polyvec *mat, const gcry_dilithium_polyvec *v);

#endif
