/* mlkem-rejsample-avx2.h
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

#ifndef GCRYPT_MLKEM_REJSAMPLE_AVX2_H
#define GCRYPT_MLKEM_REJSAMPLE_AVX2_H

#include <stdint.h>
#include "mlkem-params.h"
#include "mlkem-fips202x4-avx2.h"

#define XOF_BLOCKBYTES GCRY_SHAKE128_RATE

#define GCRY_MLKEM_REJ_UNIFORM_AVX_NBLOCKS                                    \
  ((12 * GCRY_MLKEM_N / 8 * (1 << 12) / GCRY_MLKEM_Q + XOF_BLOCKBYTES)        \
   / XOF_BLOCKBYTES)
#define GCRY_MLKEM_REJ_UNIFORM_AVX_BUFLEN                                     \
  (GCRY_MLKEM_REJ_UNIFORM_AVX_NBLOCKS * XOF_BLOCKBYTES)

unsigned int _gcry_mlkem_avx2_rej_uniform_avx (int16_t *r, const uint8_t *buf);

#endif
