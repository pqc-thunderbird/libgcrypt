/* mlkem-reduce-avx2.h
 * Copyright (C) 2024 MTG AG
 * The code was created based on the reference implementation that is part of the ML-KEM NIST submission.
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

#ifndef GCRYPT_MLKEM_REDUCE_AVX2_H
#define GCRYPT_MLKEM_REDUCE_AVX2_H

#include <immintrin.h>

void _gcry_mlkem_avx2_reduce_avx (__m256i *r, const __m256i *gcry_mlkem_avx2_qdata);
void _gcry_mlkem_avx2_tomont_avx (__m256i *r, const __m256i *gcry_mlkem_avx2_qdata);

#endif