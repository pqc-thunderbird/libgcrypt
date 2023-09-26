/* kyber-polyvec.h - functions related to vectors of polynomials for Kyber
 * Copyright (C) 2023 MTG AG
 * The code was created based on the reference implementation that is part of the Kyber NIST submission.
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

#ifndef GCRYPT_KYBER_POLYVEC_H
#define GCRYPT_KYBER_POLYVEC_H

#include <config.h>
#include <stdint.h>
#include "kyber-params.h"
#include "kyber-poly.h"
#include "g10lib.h"

typedef struct
{
  gcry_kyber_poly *vec;
} gcry_kyber_polyvec;


gcry_error_t _gcry_kyber_polymatrix_create (gcry_kyber_polyvec **polymat,
                                            gcry_kyber_param_t const *param);
void _gcry_kyber_polymatrix_destroy (gcry_kyber_polyvec **polymat,
                                     gcry_kyber_param_t const *param);

gcry_error_t _gcry_kyber_polyvec_create (gcry_kyber_polyvec *polyvec,
                                         gcry_kyber_param_t const *param);
void _gcry_kyber_polyvec_destroy (gcry_kyber_polyvec *polyvec);

void _gcry_kyber_polyvec_compress (uint8_t *r,
                                   const gcry_kyber_polyvec *a,
                                   gcry_kyber_param_t const *param);
void _gcry_kyber_polyvec_decompress (gcry_kyber_polyvec *r,
                                     const uint8_t *a,
                                     gcry_kyber_param_t const *param);


void _gcry_kyber_polyvec_tobytes (uint8_t *r,
                                  const gcry_kyber_polyvec *a,
                                  gcry_kyber_param_t const *param);
void _gcry_kyber_polyvec_frombytes (gcry_kyber_polyvec *r,
                                    const uint8_t *a,
                                    gcry_kyber_param_t const *param);

void _gcry_kyber_polyvec_ntt (gcry_kyber_polyvec *r,
                              gcry_kyber_param_t const *param);
void _gcry_kyber_polyvec_invntt_tomont (gcry_kyber_polyvec *r,
                                        gcry_kyber_param_t const *param);

gcry_err_code_t _gcry_kyber_polyvec_basemul_acc_montgomery (
    gcry_kyber_poly *r,
    const gcry_kyber_polyvec *a,
    const gcry_kyber_polyvec *b,
    gcry_kyber_param_t const *param);

void _gcry_kyber_polyvec_reduce (gcry_kyber_polyvec *r,
                                 gcry_kyber_param_t const *param);

void _gcry_kyber_polyvec_add (gcry_kyber_polyvec *r,
                              const gcry_kyber_polyvec *a,
                              const gcry_kyber_polyvec *b,
                              gcry_kyber_param_t const *param);

#endif /* GCRYPT_KYBER_POLYVEC_H */
