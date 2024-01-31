/* mldsa-rounding.h
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

#ifndef _GCRY_MLDSA_ROUNDING_H
#define _GCRY_MLDSA_ROUNDING_H

#include "types.h"
#include "mldsa-params.h"

s32 _gcry_mldsa_power2round (s32 *a0, s32 a);

s32 _gcry_mldsa_decompose (gcry_mldsa_param_t *params, s32 *a0, s32 a);

unsigned int _gcry_mldsa_make_hint (gcry_mldsa_param_t *params, s32 a0, s32 a1);

s32 _gcry_mldsa_use_hint (gcry_mldsa_param_t *params, s32 a, unsigned int hint);

#endif
