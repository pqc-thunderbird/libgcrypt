/* slhdsa-thash.h
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

#ifndef SLHDSA_THASH_H
#define SLHDSA_THASH_H

#include "config.h"
#include "slhdsa-context.h"
#include "types.h"
#include "g10lib.h"
#include "avx2-immintrin-support.h"

gcry_err_code_t _gcry_slhdsa_thash (
    byte *out, const byte *in, unsigned int inblocks, const _gcry_slhdsa_param_t *ctx, u32 addr[8]);


#ifdef USE_AVX2
gcry_err_code_t _gcry_slhdsa_thash_avx2_sha2 (byte *out0,
                                              byte *out1,
                                              byte *out2,
                                              byte *out3,
                                              byte *out4,
                                              byte *out5,
                                              byte *out6,
                                              byte *out7,
                                              const byte *in0,
                                              const byte *in1,
                                              const byte *in2,
                                              const byte *in3,
                                              const byte *in4,
                                              const byte *in5,
                                              const byte *in6,
                                              const byte *in7,
                                              unsigned int inblocks,
                                              const _gcry_slhdsa_param_t *ctx,
                                              u32 addrx8[8 * 8]);

gcry_err_code_t _gcry_slhdsa_thash_avx2_shake (byte *out0,
                                               byte *out1,
                                               byte *out2,
                                               byte *out3,
                                               const byte *in0,
                                               const byte *in1,
                                               const byte *in2,
                                               const byte *in3,
                                               unsigned int inblocks,
                                               const _gcry_slhdsa_param_t *ctx,
                                               u32 addrx4[4 * 8]);
#endif

#endif
