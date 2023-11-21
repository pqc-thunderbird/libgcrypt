#ifndef POLYVEC_H
#define POLYVEC_H

#include <stdint.h>
#include "mldsa-params-avx2.h"
#include "mldsa-poly-avx2.h"

/* Vectors of polynomials of length L */
typedef struct {
  gcry_mldsa_poly vec[L];
} polyvecl;

void polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[CRHBYTES], uint16_t nonce);

void polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[CRHBYTES], uint16_t nonce);

void polyvecl_reduce(polyvecl *v);

void polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v);

void polyvecl_ntt(polyvecl *v);
void polyvecl_invntt_tomont(polyvecl *v);
void polyvecl_pointwise_poly_montgomery(polyvecl *r, const gcry_mldsa_poly *a, const polyvecl *v);

void polyvecl_pointwise_acc_montgomery(gcry_mldsa_poly *w,
                                       const polyvecl *u,
                                       const polyvecl *v);

int polyvecl_chknorm(const polyvecl *v, int32_t B);

/* Vectors of polynomials of length K */
typedef struct {
  gcry_mldsa_poly vec[K];
} polyveck;

void polyveck_uniform_eta(polyveck *v, const uint8_t seed[CRHBYTES], uint16_t nonce);

void polyveck_reduce(polyveck *v);
void polyveck_caddq(polyveck *v);

void polyveck_add(polyveck *w, const polyveck *u, const polyveck *v);
void polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v);
void polyveck_shiftl(polyveck *v);

void polyveck_ntt(polyveck *v);
void polyveck_invntt_tomont(polyveck *v);
void polyveck_pointwise_poly_montgomery(polyveck *r, const gcry_mldsa_poly *a, const polyveck *v);

int polyveck_chknorm(const polyveck *v, int32_t B);

void polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v);
void polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v);
unsigned int polyveck_make_hint(uint8_t *hint, const polyveck *v0, const polyveck *v1);
void polyveck_use_hint(polyveck *w, const polyveck *v, const polyveck *h);

void polyveck_pack_w1(uint8_t r[K*POLYW1_PACKEDBYTES], const polyveck *w1);

void polyvec_matrix_expand(polyvecl mat[K], const uint8_t rho[SEEDBYTES]);

void polyvec_matrix_expand_row0(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
void polyvec_matrix_expand_row1(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
void polyvec_matrix_expand_row2(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
void polyvec_matrix_expand_row3(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
void polyvec_matrix_expand_row4(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
void polyvec_matrix_expand_row5(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
void polyvec_matrix_expand_row6(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
void polyvec_matrix_expand_row7(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);

void polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[K], const polyvecl *v);

#endif
