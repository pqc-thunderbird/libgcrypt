/* slhdsa-address.h
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

#ifndef SLHDSA_ADDRESS_H
#define SLHDSA_ADDRESS_H

#include "types.h"
#include "slhdsa-context.h"

/* The hash types that are passed to _gcry_slhdsa_set_type */
#define SLHDSA_ADDR_TYPE_WOTS 0
#define SLHDSA_ADDR_TYPE_WOTSPK 1
#define SLHDSA_ADDR_TYPE_HASHTREE 2
#define SLHDSA_ADDR_TYPE_FORSTREE 3
#define SLHDSA_ADDR_TYPE_FORSPK 4
#define SLHDSA_ADDR_TYPE_WOTSPRF 5
#define SLHDSA_ADDR_TYPE_FORSPRF 6

void _gcry_slhdsa_set_layer_addr (const _gcry_slhdsa_param_t *ctx, u32 addr[8], u32 layer);

void _gcry_slhdsa_set_tree_addr (const _gcry_slhdsa_param_t *ctx, u32 addr[8], u64 tree);

void _gcry_slhdsa_set_type (const _gcry_slhdsa_param_t *ctx, u32 addr[8], u32 type);

/* Copies the layer and tree part of one address into the other */
void _gcry_slhdsa_copy_subtree_addr (const _gcry_slhdsa_param_t *ctx, u32 out[8], const u32 in[8]);

/* These functions are used for WOTS and FORS addresses. */

void _gcry_slhdsa_set_keypair_addr (const _gcry_slhdsa_param_t *ctx, u32 addr[8], u32 keypair);

void _gcry_slhdsa_set_chain_addr (const _gcry_slhdsa_param_t *ctx, u32 addr[8], u32 chain);

void _gcry_slhdsa_set_hash_addr (const _gcry_slhdsa_param_t *ctx, u32 addr[8], u32 hash);

void _gcry_slhdsa_copy_keypair_addr (const _gcry_slhdsa_param_t *ctx, u32 out[8], const u32 in[8]);

/* These functions are used for all hash tree addresses (including FORS). */

void _gcry_slhdsa_set_tree_height (const _gcry_slhdsa_param_t *ctx, u32 addr[8], u32 tree_height);

void _gcry_slhdsa_set_tree_index (const _gcry_slhdsa_param_t *ctx, u32 addr[8], u32 tree_index);

#endif
