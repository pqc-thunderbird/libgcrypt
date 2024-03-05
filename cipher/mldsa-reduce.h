/* mldsa-reduce.h
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

#ifndef _GCRY_MLDSA_REDUCE_H
#define _GCRY_MLDSA_REDUCE_H

#include "types.h"
#include "mldsa-params.h"

#define GCRY_MLDSA_MONT -4186625 /* 2^32 % GCRY_MLDSA_Q */
#define GCRY_MLDSA_QINV 58728449 /* q^(-1) mod 2^32 */

s32 _gcry_mldsa_montgomery_reduce (int64_t a);

s32 _gcry_mldsa_reduce32 (s32 a);

s32 _gcry_mldsa_caddq (s32 a);

s32 _gcry_mldsa_freeze (s32 a);

#endif