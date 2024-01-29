/* slhdsa-fips202x4.h
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

#ifndef SLHDSA_FIPS204X4_H
#define SLHDSA_FIPS204X4_H

#include "avx2-immintrin-support.h"
#include <config.h>
#include "types.h"
#include "g10lib.h"

#ifdef USE_AVX2
#include <immintrin.h>

gcry_err_code_t _gcry_slhdsa_shake256x4 (byte *out0,
                                         byte *out1,
                                         byte *out2,
                                         byte *out3,
                                         unsigned long long outlen,
                                         byte *in0,
                                         byte *in1,
                                         byte *in2,
                                         byte *in3,
                                         unsigned long long inlen);

void _gcry_slhdsa_KeccakP1600times4_PermuteAll_24rounds (__m256i *states);
#endif
#endif
