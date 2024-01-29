/* slhdsa-utils.h
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

#ifndef SLHDSA_UTILS_H
#define SLHDSA_UTILS_H

#include "config.h"

#include "types.h"
#include "slhdsa-context.h"

#include "g10lib.h"

typedef struct
{
  byte *buf;
  byte *alloc_addr;
} gcry_slhdsa_buf_al;

gcry_err_code_t _gcry_mldsa_buf_al_create (gcry_slhdsa_buf_al *buf, size_t size);
void _gcry_mldsa_buf_al_destroy (gcry_slhdsa_buf_al *buf);

/**
 * Converts the value of 'in' to 'outlen' bytes in big-endian byte order.
 */
void _gcry_slhdsa_ull_to_bytes (byte *out, unsigned int outlen, unsigned long long in);
void _gcry_slhdsa_u32_to_bytes (byte *out, u32 in);

/**
 * Converts the inlen bytes in 'in' from big-endian byte order to an integer.
 */
unsigned long long _gcry_slhdsa_bytes_to_ull (const byte *in, unsigned int inlen);

/**
 * Computes a root node given a leaf and an auth path.
 * Expects address to be complete other than the tree_height and tree_index.
 */
gcry_err_code_t _gcry_slhdsa_compute_root (byte *root,
                                           const byte *leaf,
                                           u32 leaf_idx,
                                           u32 idx_offset,
                                           const byte *auth_path,
                                           u32 tree_height,
                                           const _gcry_slhdsa_param_t *ctx,
                                           u32 addr[8]);

#endif