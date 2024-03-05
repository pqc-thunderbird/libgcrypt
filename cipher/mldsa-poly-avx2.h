/* mldsa-poly-avx2.h
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

#ifndef _GCRY_MLDSA_AVX2_POLY_H
#define _GCRY_MLDSA_AVX2_POLY_H

#include "avx2-immintrin-support.h"
#ifdef USE_AVX2

#include <stdint.h>
#include "mldsa-params.h"

#include "mldsa-poly.h"

void _gcry_mldsa_avx2_poly_reduce (gcry_mldsa_poly *a);
void _gcry_mldsa_avx2_poly_caddq (gcry_mldsa_poly *a);

void _gcry_mldsa_avx2_poly_add (gcry_mldsa_poly *c,
                                const gcry_mldsa_poly *a,
                                const gcry_mldsa_poly *b);
void _gcry_mldsa_avx2_poly_sub (gcry_mldsa_poly *c,
                                const gcry_mldsa_poly *a,
                                const gcry_mldsa_poly *b);
void poly_shiftl (gcry_mldsa_poly *a);

void _gcry_mldsa_avx2_poly_ntt (gcry_mldsa_poly *a);
void _gcry_mldsa_avx2_poly_invntt_tomont (gcry_mldsa_poly *a);
void _gcry_mldsa_avx2_poly_nttunpack (byte *a);
void _gcry_mldsa_avx2_poly_pointwise_montgomery (gcry_mldsa_poly *c,
                                                 const gcry_mldsa_poly *a,
                                                 const gcry_mldsa_poly *b);

void _gcry_mldsa_avx2_poly_power2round (gcry_mldsa_poly *a1,
                                        gcry_mldsa_poly *a0,
                                        const gcry_mldsa_poly *a);
void _gcry_mldsa_avx2_poly_decompose (gcry_mldsa_param_t *params,
                                      gcry_mldsa_poly *a1,
                                      gcry_mldsa_poly *a0,
                                      const gcry_mldsa_poly *a);
unsigned int _gcry_mldsa_avx2_poly_make_hint (gcry_mldsa_param_t *params,
                                              byte hint[GCRY_MLDSA_N],
                                              const gcry_mldsa_poly *a0,
                                              const gcry_mldsa_poly *a1);
void _gcry_mldsa_avx2_poly_use_hint (gcry_mldsa_param_t *params,
                                     gcry_mldsa_poly *b,
                                     const gcry_mldsa_poly *a,
                                     const gcry_mldsa_poly *h);

int _gcry_mldsa_avx2_poly_chknorm (const gcry_mldsa_poly *a, s32 B);
gcry_err_code_t _gcry_mldsa_avx2_poly_uniform_gamma1 (
    gcry_mldsa_param_t *params,
    gcry_mldsa_poly *a,
    const byte seed[GCRY_MLDSA_CRHBYTES],
    u16 nonce);

gcry_err_code_t _gcry_mldsa_avx2_poly_uniform_4x (
    byte *a0,
    byte *a1,
    byte *a2,
    byte *a3,
    const byte seed[GCRY_MLDSA_SEEDBYTES],
    u16 nonce0,
    u16 nonce1,
    u16 nonce2,
    u16 nonce3);
gcry_err_code_t _gcry_mldsa_avx2_poly_uniform_eta_4x (
    gcry_mldsa_param_t *params,
    gcry_mldsa_poly *a0,
    gcry_mldsa_poly *a1,
    gcry_mldsa_poly *a2,
    gcry_mldsa_poly *a3,
    const byte seed[GCRY_MLDSA_CRHBYTES],
    u16 nonce0,
    u16 nonce1,
    u16 nonce2,
    u16 nonce3);
gcry_err_code_t _gcry_mldsa_avx2_poly_uniform_gamma1_4x (
    gcry_mldsa_param_t *params,
    byte *a0,
    byte *a1,
    byte *a2,
    byte *a3,
    const byte seed[GCRY_MLDSA_CRHBYTES],
    u16 nonce0,
    u16 nonce1,
    u16 nonce2,
    u16 nonce3);

void _gcry_mldsa_avx2_polyeta_pack (gcry_mldsa_param_t *params,
                                    byte *r,
                                    const gcry_mldsa_poly *a);
void _gcry_mldsa_avx2_polyeta_unpack (gcry_mldsa_param_t *params,
                                      gcry_mldsa_poly *r,
                                      const byte *a);

void _gcry_mldsa_avx2_polyt1_pack (byte r[GCRY_MLDSA_POLYT1_PACKEDBYTES],
                                   const gcry_mldsa_poly *a);
void _gcry_mldsa_avx2_polyt1_unpack (
    gcry_mldsa_poly *r, const byte a[GCRY_MLDSA_POLYT1_PACKEDBYTES]);

void _gcry_mldsa_avx2_polyt0_pack (byte r[GCRY_MLDSA_POLYT0_PACKEDBYTES],
                                   const gcry_mldsa_poly *a);
void _gcry_mldsa_avx2_polyt0_unpack (
    gcry_mldsa_poly *r, const byte a[GCRY_MLDSA_POLYT0_PACKEDBYTES]);

void _gcry_mldsa_avx2_polyz_pack (gcry_mldsa_param_t *params,
                                  byte *r,
                                  const gcry_mldsa_poly *a);
void _gcry_mldsa_avx2_polyz_unpack (gcry_mldsa_param_t *params,
                                    gcry_mldsa_poly *r,
                                    const byte *a);

void _gcry_mldsa_avx2_polyw1_pack (gcry_mldsa_param_t *params,
                                   byte *r,
                                   const gcry_mldsa_poly *a);


void _gcry_mldsa_avx2_unpack_sk (gcry_mldsa_param_t *params,
                                 byte rho[GCRY_MLDSA_SEEDBYTES],
                                 byte tr[GCRY_MLDSA_TRBYTES],
                                 byte key[GCRY_MLDSA_SEEDBYTES],
                                 byte *t0,
                                 byte *s1,
                                 byte *s2,
                                 const byte *sk);

#endif
#endif