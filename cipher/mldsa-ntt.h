/* mldsa-ntt.h
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

#ifndef _GCRY_MLDSA_NTT_H
#define _GCRY_MLDSA_NTT_H

#include "types.h"
#include "mldsa-params.h"

void _gcry_mldsa_ntt (s32 a[GCRY_MLDSA_N]);

void _gcry_mldsa_invntt_tomont (s32 a[GCRY_MLDSA_N]);

#endif
