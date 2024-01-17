/* mldsa-polyvec.h
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

#ifndef _GCRY_MLDSA_POLYVEC_H
#define _GCRY_MLDSA_POLYVEC_H
#include <config.h>

#include "types.h"
#include "mldsa-params.h"
#include "mldsa-poly.h"
#include "g10lib.h"

typedef struct
{
  gcry_mldsa_poly *vec;
} gcry_mldsa_polyvec;

gcry_err_code_t _gcry_mldsa_polymatrix_create (gcry_mldsa_polyvec **polymat,
                                               unsigned char mat_elems,
                                               unsigned char vec_elems);
void _gcry_mldsa_polymatrix_destroy (gcry_mldsa_polyvec **polymat, unsigned char elems);
gcry_err_code_t _gcry_mldsa_polyvec_create (gcry_mldsa_polyvec *polyvec, unsigned char elems);
gcry_err_code_t _gcry_mldsa_polyvec_copy (gcry_mldsa_polyvec *a, gcry_mldsa_polyvec *b, unsigned char elems);
void _gcry_mldsa_polyvec_destroy (gcry_mldsa_polyvec *polyvec);

gcry_err_code_t _gcry_mldsa_polyvecl_uniform_eta (gcry_mldsa_param_t *params,
                                                  gcry_mldsa_polyvec *v,
                                                  const byte seed[GCRY_MLDSA_CRHBYTES],
                                                  u16 nonce);

gcry_err_code_t _gcry_mldsa_polyvecl_uniform_gamma1 (gcry_mldsa_param_t *params,
                                                     gcry_mldsa_polyvec *v,
                                                     const byte seed[GCRY_MLDSA_CRHBYTES],
                                                     u16 nonce);

void _gcry_mldsa_polyvecl_reduce (gcry_mldsa_param_t *params, gcry_mldsa_polyvec *v);

void _gcry_mldsa_polyvecl_add (gcry_mldsa_param_t *params,
                               gcry_mldsa_polyvec *w,
                               const gcry_mldsa_polyvec *u,
                               const gcry_mldsa_polyvec *v);

void _gcry_mldsa_polyvecl_ntt (gcry_mldsa_param_t *params, gcry_mldsa_polyvec *v);
void _gcry_mldsa_polyvecl_invntt_tomont (gcry_mldsa_param_t *params, gcry_mldsa_polyvec *v);
void _gcry_mldsa_polyvecl_pointwise_poly_montgomery (gcry_mldsa_param_t *params,
                                                     gcry_mldsa_polyvec *r,
                                                     const gcry_mldsa_poly *a,
                                                     const gcry_mldsa_polyvec *v);

void _gcry_mldsa_polyvecl_pointwise_acc_montgomery (gcry_mldsa_param_t *params,
                                                    gcry_mldsa_poly *w,
                                                    const gcry_mldsa_polyvec *u,
                                                    const gcry_mldsa_polyvec *v);


int _gcry_mldsa_polyvecl_chknorm (gcry_mldsa_param_t *params, const gcry_mldsa_polyvec *v, s32 B);

gcry_err_code_t _gcry_mldsa_polyveck_uniform_eta (gcry_mldsa_param_t *params,
                                                  gcry_mldsa_polyvec *v,
                                                  const byte seed[GCRY_MLDSA_CRHBYTES],
                                                  u16 nonce);

void _gcry_mldsa_polyveck_reduce (gcry_mldsa_param_t *params, gcry_mldsa_polyvec *v);
void _gcry_mldsa_polyveck_caddq (gcry_mldsa_param_t *params, gcry_mldsa_polyvec *v);

void _gcry_mldsa_polyveck_add (gcry_mldsa_param_t *params,
                               gcry_mldsa_polyvec *w,
                               const gcry_mldsa_polyvec *u,
                               const gcry_mldsa_polyvec *v);
void _gcry_mldsa_polyveck_sub (gcry_mldsa_param_t *params,
                               gcry_mldsa_polyvec *w,
                               const gcry_mldsa_polyvec *u,
                               const gcry_mldsa_polyvec *v);
void _gcry_mldsa_polyveck_shiftl (gcry_mldsa_param_t *params, gcry_mldsa_polyvec *v);

void _gcry_mldsa_polyveck_ntt (gcry_mldsa_param_t *params, gcry_mldsa_polyvec *v);
void _gcry_mldsa_polyveck_invntt_tomont (gcry_mldsa_param_t *params, gcry_mldsa_polyvec *v);
void _gcry_mldsa_polyveck_pointwise_poly_montgomery (gcry_mldsa_param_t *params,
                                                     gcry_mldsa_polyvec *r,
                                                     const gcry_mldsa_poly *a,
                                                     const gcry_mldsa_polyvec *v);

int _gcry_mldsa_polyveck_chknorm (gcry_mldsa_param_t *params, const gcry_mldsa_polyvec *v, s32 B);

void _gcry_mldsa_polyveck_power2round (gcry_mldsa_param_t *params,
                                       gcry_mldsa_polyvec *v1,
                                       gcry_mldsa_polyvec *v0,
                                       const gcry_mldsa_polyvec *v);
void _gcry_mldsa_polyveck_decompose (gcry_mldsa_param_t *params,
                                     gcry_mldsa_polyvec *v1,
                                     gcry_mldsa_polyvec *v0,
                                     const gcry_mldsa_polyvec *v);
unsigned int _gcry_mldsa_polyveck_make_hint (gcry_mldsa_param_t *params,
                                             gcry_mldsa_polyvec *h,
                                             const gcry_mldsa_polyvec *v0,
                                             const gcry_mldsa_polyvec *v1);
void _gcry_mldsa_polyveck_use_hint (gcry_mldsa_param_t *params,
                                    gcry_mldsa_polyvec *w,
                                    const gcry_mldsa_polyvec *v,
                                    const gcry_mldsa_polyvec *h);

void _gcry_mldsa_polyveck_pack_w1 (gcry_mldsa_param_t *params, byte *r, const gcry_mldsa_polyvec *w1);

gcry_err_code_t _gcry_mldsa_polyvec_matrix_expand (gcry_mldsa_param_t *params,
                                                   gcry_mldsa_polyvec *mat,
                                                   const byte rho[GCRY_MLDSA_SEEDBYTES]);

void _gcry_mldsa_polyvec_matrix_pointwise_montgomery (gcry_mldsa_param_t *params,
                                                      gcry_mldsa_polyvec *t,
                                                      const gcry_mldsa_polyvec *mat,
                                                      const gcry_mldsa_polyvec *v);

#endif
