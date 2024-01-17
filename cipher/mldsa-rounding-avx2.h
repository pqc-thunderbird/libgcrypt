/* mldsa-rounding-avx2.h
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

#ifndef _GCRY_MLDSA_AVX2_ROUNDING_H
#define _GCRY_MLDSA_AVX2_ROUNDING_H

#include <stdint.h>
#include <immintrin.h>
#include "config.h"
#include "mldsa-params.h"
#include "types.h"
#include "avx2-immintrin-support.h"

#ifdef USE_AVX2

void _gcry_mldsa_avx2_power2round_avx (__m256i *a1, __m256i *a0, const __m256i *a);
void _gcry_mldsa_avx2_decompose_avx (gcry_mldsa_param_t *params, __m256i *a1, __m256i *a0, const __m256i *a);
unsigned int _gcry_mldsa_avx2_make_hint_avx (gcry_mldsa_param_t *params,
                                             byte hint[GCRY_MLDSA_N],
                                             const __m256i *a0,
                                             const __m256i *a1);
void _gcry_mldsa_avx2_use_hint_avx (gcry_mldsa_param_t *params, __m256i *b, const __m256i *a, const __m256i *hint);

#endif
#endif
