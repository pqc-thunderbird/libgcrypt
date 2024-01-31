/* ml-common-fips202x4-avx2.h
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

#ifndef _GCRY_ML_COMMON_NFIPS202X4_AVX_H
#define _GCRY_ML_COMMON_NFIPS202X4_AVX_H

#ifdef __ASSEMBLER__
/* The C ABI on MacOS exports all symbols with a leading
 * underscore. This means that any symbols we refer to from
 * C files (functions) can't be found, and all symbols we
 * refer to from ASM also can't be found.
 *
 * This define helps us get around this
 */
#if defined(__WIN32__) || defined(__APPLE__)
#define decorate(s) _##s
#define _cdecl(s) decorate (s)
#define cdecl(s) _cdecl(s)
#else
#define cdecl(s) s
#endif

#else
#include <stddef.h>
#include <stdint.h>
#include <immintrin.h>

typedef struct
{
  __m256i s[25];
} gcry_ml_common_keccakx4_state;

void _gcry_ml_common_avx2_f1600x4 (__m256i *s, const u64 *rc);

void _gcry_ml_common_avx2_shake128x4_absorb_once (
    gcry_ml_common_keccakx4_state *state, const byte *in0, const byte *in1, const byte *in2, const byte *in3, size_t inlen);

void _gcry_ml_common_avx2_shake128x4_squeezeblocks (
    byte *out0, byte *out1, byte *out2, byte *out3, size_t nblocks, gcry_ml_common_keccakx4_state *state);

void _gcry_ml_common_avx2_shake256x4_absorb_once (
    gcry_ml_common_keccakx4_state *state, const byte *in0, const byte *in1, const byte *in2, const byte *in3, size_t inlen);

void _gcry_ml_common_avx2_shake256x4_squeezeblocks (
    byte *out0, byte *out1, byte *out2, byte *out3, size_t nblocks, gcry_ml_common_keccakx4_state *state);

#endif
#endif
