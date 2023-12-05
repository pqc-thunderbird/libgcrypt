#ifndef POLYVEC_H
#define POLYVEC_H

#include <stdint.h>
#include "mldsa-params-avx2.h"
#include "mldsa-poly-avx2.h"

/* Vectors of polynomials of length L */


void polyvecl_ntt(gcry_mldsa_param_t *params, byte *v);

void polyvecl_pointwise_acc_montgomery(gcry_mldsa_poly *w,
                                       const byte *u,
                                       const byte *v);

/* Vectors of polynomials of length K */



void polyveck_caddq(gcry_mldsa_param_t *params, byte *v);

void polyveck_ntt(gcry_mldsa_param_t *params, byte *v);
void polyveck_invntt_tomont(gcry_mldsa_param_t *params, byte *v);

void polyveck_decompose(gcry_mldsa_param_t *params, byte *v1, byte *v0, const byte *v);

void polyveck_pack_w1(gcry_mldsa_param_t *params, byte *r, const byte *w1);

gcry_err_code_t polyvec_matrix_expand(gcry_mldsa_param_t *params, byte *mat, const byte rho[GCRY_MLDSA_SEEDBYTES]);

gcry_err_code_t polyvec_matrix_expand_row0(gcry_mldsa_param_t *params, byte *rowa, byte *rowb, const byte rho[GCRY_MLDSA_SEEDBYTES]);
gcry_err_code_t polyvec_matrix_expand_row1(gcry_mldsa_param_t *params, byte *rowa, byte *rowb, const byte rho[GCRY_MLDSA_SEEDBYTES]);
gcry_err_code_t polyvec_matrix_expand_row2(gcry_mldsa_param_t *params, byte *rowa, byte *rowb, const byte rho[GCRY_MLDSA_SEEDBYTES]);
gcry_err_code_t polyvec_matrix_expand_row3(gcry_mldsa_param_t *params, byte *rowa, byte *rowb, const byte rho[GCRY_MLDSA_SEEDBYTES]);
gcry_err_code_t polyvec_matrix_expand_row4(gcry_mldsa_param_t *params, byte *rowa, byte *rowb, const byte rho[GCRY_MLDSA_SEEDBYTES]);
gcry_err_code_t polyvec_matrix_expand_row5(gcry_mldsa_param_t *params, byte *rowa, byte *rowb, const byte rho[GCRY_MLDSA_SEEDBYTES]);
gcry_err_code_t polyvec_matrix_expand_row6(gcry_mldsa_param_t *params, byte *rowa, byte *rowb, const byte rho[GCRY_MLDSA_SEEDBYTES]);
gcry_err_code_t polyvec_matrix_expand_row7(gcry_mldsa_param_t *params, byte *rowa, byte *rowb, const byte rho[GCRY_MLDSA_SEEDBYTES]);

void polyvec_matrix_pointwise_montgomery(gcry_mldsa_param_t *params, byte *t, const byte *mat, const byte *v);

#endif
