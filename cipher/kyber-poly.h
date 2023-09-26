/* kyber-poly.h - functions related to polynomials for Kyber
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

#ifndef GCRYPT_KYBER_POLY_H
#define GCRYPT_KYBER_POLY_H

#include <stdint.h>
#include "kyber-params.h"

/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*coeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
typedef struct
{
  int16_t coeffs[GCRY_KYBER_N];
} gcry_kyber_poly;


void _gcry_kyber_poly_compress (unsigned char *r,
                                const gcry_kyber_poly *a,
                                gcry_kyber_param_t const *param);

void _gcry_kyber_poly_decompress (gcry_kyber_poly *r,
                                  const unsigned char *a,
                                  gcry_kyber_param_t const *param);


void _gcry_kyber_poly_tobytes (unsigned char r[GCRY_KYBER_POLYBYTES],
                               const gcry_kyber_poly *a);

void _gcry_kyber_poly_frombytes (gcry_kyber_poly *r,
                                 const unsigned char a[GCRY_KYBER_POLYBYTES]);


void _gcry_kyber_poly_frommsg (
    gcry_kyber_poly *r, const unsigned char msg[GCRY_KYBER_INDCPA_MSGBYTES]);

void _gcry_kyber_poly_tomsg (unsigned char msg[GCRY_KYBER_INDCPA_MSGBYTES],
                             const gcry_kyber_poly *r);


void _gcry_kyber_poly_getnoise_eta1 (
    gcry_kyber_poly *r,
    const unsigned char seed[GCRY_KYBER_SYMBYTES],
    unsigned char nonce,
    gcry_kyber_param_t const *param);


void _gcry_kyber_poly_getnoise_eta2 (
    gcry_kyber_poly *r,
    const unsigned char seed[GCRY_KYBER_SYMBYTES],
    unsigned char nonce);


void _gcry_kyber_poly_ntt (gcry_kyber_poly *r);

void _gcry_kyber_poly_invntt_tomont (gcry_kyber_poly *r);

void _gcry_kyber_poly_basemul_montgomery (gcry_kyber_poly *r,
                                          const gcry_kyber_poly *a,
                                          const gcry_kyber_poly *b);

void _gcry_kyber_poly_tomont (gcry_kyber_poly *r);


void _gcry_kyber_poly_reduce (gcry_kyber_poly *r);


void _gcry_kyber_poly_add (gcry_kyber_poly *r,
                           const gcry_kyber_poly *a,
                           const gcry_kyber_poly *b);

void _gcry_kyber_poly_sub (gcry_kyber_poly *r,
                           const gcry_kyber_poly *a,
                           const gcry_kyber_poly *b);

#endif /* GCRYPT_KYBER_POLY_H */
