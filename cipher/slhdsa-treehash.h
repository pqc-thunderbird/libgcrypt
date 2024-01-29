/* slhdsa-treehash.h
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

#ifndef SLHDSA_UTILSX4_H
#define SLHDSA_UTILSX4_H

#include "config.h"
#include "avx2-immintrin-support.h"

#include "types.h"
#include "slhdsa-context.h"

#include "g10lib.h"

/**
 * For a given leaf index, computes the authentication path and the resulting
 * root node using Merkle's TreeHash algorithm.
 * Expects the layer and tree parts of the tree_addr to be set, as well as the
 * tree type (i.e. SLHDSA_ADDR_TYPE_HASHTREE or SLHDSA_ADDR_TYPE_FORSTREE).
 * Applies the offset idx_offset to indices before building addresses, so that
 * it is possible to continue counting indices across trees.
 */
gcry_err_code_t _gcry_slhdsa_treehashx1 (byte *root,
                                         byte *auth_path,
                                         const _gcry_slhdsa_param_t *ctx,
                                         u32 leaf_idx,
                                         u32 idx_offset,
                                         u32 tree_height,
                                         gcry_err_code_t (*gen_leaf) (byte * /* Where to write the leaf */,
                                                                      const _gcry_slhdsa_param_t * /* ctx */,
                                                                      u32 addr_idx,
                                                                      void *info),
                                         u32 tree_addrx4[8],
                                         void *info);

#ifdef USE_AVX2
gcry_err_code_t _gcry_slhdsa_treehashx8 (byte *root,
                                         byte *auth_path,
                                         const _gcry_slhdsa_param_t *ctx,
                                         u32 leaf_idx,
                                         u32 idx_offset,
                                         u32 tree_height,
                                         gcry_err_code_t (*gen_leafx8) (byte * /* Where to write the leaves */,
                                                                        const _gcry_slhdsa_param_t *,
                                                                        u32 idx,
                                                                        void *info),
                                         u32 tree_addrx8[8 * 8],
                                         void *info);

gcry_err_code_t _gcry_slhdsa_treehashx4 (byte *root,
                                         byte *auth_path,
                                         const _gcry_slhdsa_param_t *ctx,
                                         u32 leaf_idx,
                                         u32 idx_offset,
                                         u32 tree_height,
                                         gcry_err_code_t (*gen_leafx4) (byte * /* Where to write the leaves */,
                                                                        const _gcry_slhdsa_param_t *,
                                                                        u32 idx,
                                                                        void *info),
                                         u32 tree_addrx4[4 * 8],
                                         void *info);
#endif

#endif
