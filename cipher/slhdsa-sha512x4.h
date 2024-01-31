/* slhdsa-sha512x4.h
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

#ifndef GCRY_SLHDSA_SHA512X4_H
#define GCRY_SLHDSA_SHA512X4_H

#include "avx2-immintrin-support.h"
#include "slhdsa-hash.h"
#include <stdint.h>

#ifdef USE_AVX2
#include "immintrin.h"

void _gcry_slhdsa_sha512_inc_init (byte *state);

void _gcry_slhdsa_sha512_inc_blocks (byte *state, const byte *in, size_t inblocks);

gcry_err_code_t _gcry_slhdsa_sha512x4_seeded (byte *out0,
                                              byte *out1,
                                              byte *out2,
                                              byte *out3,
                                              const byte *seed,
                                              unsigned long long seedlen,
                                              const byte *in0,
                                              const byte *in1,
                                              const byte *in2,
                                              const byte *in3,
                                              unsigned long long inlen);

#endif
#endif