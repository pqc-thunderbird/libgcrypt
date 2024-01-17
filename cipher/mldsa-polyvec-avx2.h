/* mldsa-polyvec-avx2.h
 * Copyright (C) 2024 MTG AG
 * The code was created based on the reference implementation that is part of the ML-DSA NIST submission.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _GCRY_MLDSA_AVX2_POLYVEC_H
#define _GCRY_MLDSA_AVX2_POLYVEC_H

#include "avx2-immintrin-support.h"
#ifdef USE_AVX2

#include <stdint.h>
#include "mldsa-params.h"
#include "mldsa-poly-avx2.h"

/**
 * represents the avx2 poly / polymat / polyvec types, each is simply an aligned buffer.
 */
typedef struct
{
  byte *buf;
  byte *alloc_addr;
} gcry_mldsa_polybuf_al;

/* aligned buffer type */
typedef gcry_mldsa_polybuf_al gcry_mldsa_buf_al;

gcry_err_code_t _gcry_mldsa_polybuf_al_create (gcry_mldsa_polybuf_al *polybuf,
                                               size_t mat_elems,
                                               size_t vec_elems,
                                               int secure);
void _gcry_mldsa_polybuf_al_destroy (gcry_mldsa_polybuf_al *polybuf);

gcry_err_code_t _gcry_mldsa_buf_al_create (gcry_mldsa_buf_al *buf, size_t size, int secure);
void _gcry_mldsa_buf_al_destroy (gcry_mldsa_buf_al *buf);


/* Vectors of polynomials of length L */


void _gcry_mldsa_avx2_polyvecl_ntt (gcry_mldsa_param_t *params, byte *v);

void _gcry_mldsa_avx2_polyvecl_pointwise_acc_montgomery (gcry_mldsa_param_t *params,
                                                         gcry_mldsa_poly *w,
                                                         const byte *u,
                                                         const byte *v);

/* Vectors of polynomials of length K */


void _gcry_mldsa_avx2_polyveck_caddq (gcry_mldsa_param_t *params, byte *v);

void _gcry_mldsa_avx2_polyveck_ntt (gcry_mldsa_param_t *params, byte *v);
void _gcry_mldsa_avx2_polyveck_invntt_tomont (gcry_mldsa_param_t *params, byte *v);

void _gcry_mldsa_avx2_polyveck_decompose (gcry_mldsa_param_t *params, byte *v1, byte *v0, const byte *v);

void _gcry_mldsa_avx2_polyveck_pack_w1 (gcry_mldsa_param_t *params, byte *r, const byte *w1);

gcry_err_code_t _gcry_mldsa_avx2_polyvec_matrix_expand (gcry_mldsa_param_t *params,
                                                        byte *mat,
                                                        const byte rho[GCRY_MLDSA_SEEDBYTES]);

gcry_err_code_t _gcry_mldsa_avx2_polyvec_matrix_expand_row0 (gcry_mldsa_param_t *params,
                                                             byte *rowa,
                                                             byte *rowb,
                                                             const byte rho[GCRY_MLDSA_SEEDBYTES]);
gcry_err_code_t _gcry_mldsa_avx2_polyvec_matrix_expand_row1 (gcry_mldsa_param_t *params,
                                                             byte *rowa,
                                                             byte *rowb,
                                                             const byte rho[GCRY_MLDSA_SEEDBYTES]);
gcry_err_code_t _gcry_mldsa_avx2_polyvec_matrix_expand_row2 (gcry_mldsa_param_t *params,
                                                             byte *rowa,
                                                             byte *rowb,
                                                             const byte rho[GCRY_MLDSA_SEEDBYTES]);
gcry_err_code_t _gcry_mldsa_avx2_polyvec_matrix_expand_row3 (gcry_mldsa_param_t *params,
                                                             byte *rowa,
                                                             const byte rho[GCRY_MLDSA_SEEDBYTES]);
gcry_err_code_t _gcry_mldsa_avx2_polyvec_matrix_expand_row4 (gcry_mldsa_param_t *params,
                                                             byte *rowa,
                                                             byte *rowb,
                                                             const byte rho[GCRY_MLDSA_SEEDBYTES]);
gcry_err_code_t _gcry_mldsa_avx2_polyvec_matrix_expand_row5 (gcry_mldsa_param_t *params,
                                                             byte *rowa,
                                                             byte *rowb,
                                                             const byte rho[GCRY_MLDSA_SEEDBYTES]);
gcry_err_code_t _gcry_mldsa_avx2_polyvec_matrix_expand_row6 (gcry_mldsa_param_t *params,
                                                             byte *rowa,
                                                             byte *rowb,
                                                             const byte rho[GCRY_MLDSA_SEEDBYTES]);
gcry_err_code_t _gcry_mldsa_avx2_polyvec_matrix_expand_row7 (gcry_mldsa_param_t *params,
                                                             byte *rowa,
                                                             const byte rho[GCRY_MLDSA_SEEDBYTES]);

void _gcry_mldsa_avx2_polyvec_matrix_pointwise_montgomery (gcry_mldsa_param_t *params,
                                                           byte *t,
                                                           const byte *mat,
                                                           const byte *v);

#endif
#endif