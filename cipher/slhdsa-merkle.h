/* slhdsa-merkle.h
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

#ifndef SLHDSA_MERKLE_H
#define SLHDSA_MERKLE_H

#include "config.h"

#include "types.h"
#include "avx2-immintrin-support.h"

#include "g10lib.h"


/* Generate a Merkle signature (WOTS signature followed by the Merkle */
/* authentication path) */
gcry_err_code_t _gcry_slhdsa_merkle_sign (
    byte *sig, byte *root, const _gcry_slhdsa_param_t *ctx, u32 wots_addr[8], u32 tree_addr[8], u32 idx_leaf);

#ifdef USE_AVX2
gcry_err_code_t _gcry_slhdsa_merkle_sign_avx_sha2 (
    byte *sig, byte *root, const _gcry_slhdsa_param_t *ctx, u32 wots_addr[8], u32 tree_addr[8], u32 idx_leaf);
gcry_err_code_t _gcry_slhdsa_merkle_sign_avx_shake (
    byte *sig, byte *root, const _gcry_slhdsa_param_t *ctx, u32 wots_addr[8], u32 tree_addr[8], u32 idx_leaf);
#endif

/* Compute the root node of the top-most subtree. */
gcry_err_code_t _gcry_slhdsa_merkle_gen_root (byte *root, const _gcry_slhdsa_param_t *ctx);

#endif /* MERKLE_H_ */
