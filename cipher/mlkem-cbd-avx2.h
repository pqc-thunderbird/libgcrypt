/* mlkem-cbd-avx2.h
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

#ifndef GCRY_MLKEM_CBD_AVX2_H
#define GCRY_MLKEM_CBD_AVX2_H

#include <stdint.h>
#include <immintrin.h>
#include "mlkem-poly-avx2.h"

void _gcry_mlkem_avx2_poly_cbd_eta1 (gcry_mlkem_poly *r,
                                     const __m256i *buf,
                                     gcry_mlkem_param_t const *param);
void _gcry_mlkem_avx2_poly_cbd_eta2 (
    gcry_mlkem_poly *r,
    const __m256i buf[GCRY_MLKEM_ETA2 * GCRY_MLKEM_N / 128]);

#endif
