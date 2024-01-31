/* mldsa-sign.h
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

#ifndef _GCRY_MLDSA_SIGN_H
#define _GCRY_MLDSA_SIGN_H

#include <stddef.h>
#include "types.h"
#include "mldsa-params.h"
#include "mldsa-polyvec.h"
#include "mldsa-poly.h"
#include "avx2-immintrin-support.h"

gcry_err_code_t _gcry_mldsa_keypair (gcry_mldsa_param_t *params, byte *pk, byte *sk);

gcry_err_code_t _gcry_mldsa_sign (
    gcry_mldsa_param_t *params, byte *sig, size_t *siglen, const byte *m, size_t mlen, const byte *sk);

gcry_err_code_t _gcry_mldsa_verify (
    gcry_mldsa_param_t *params, const byte *sig, size_t siglen, const byte *m, size_t mlen, const byte *pk);

#ifdef USE_AVX2
gcry_err_code_t _gcry_mldsa_avx2_keypair (gcry_mldsa_param_t *params, byte *pk, byte *sk);

gcry_err_code_t _gcry_mldsa_avx2_sign (
    gcry_mldsa_param_t *params, byte *sig, size_t *siglen, const byte *m, size_t mlen, const byte *sk);

gcry_err_code_t _gcry_mldsa_avx2_verify (
    gcry_mldsa_param_t *params, const byte *sig, size_t siglen, const byte *m, size_t mlen, const byte *pk);
#endif

#endif
