/* slhdsa-wots.h
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

#ifndef SLHDSA_WOTS_H
#define SLHDSA_WOTS_H

#include <config.h>

#include "types.h"

#include "slhdsa-context.h"

#include "g10lib.h"

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
gcry_err_code_t _gcry_slhdsa_wots_pk_from_sig (
    byte *pk, const byte *sig, const byte *msg, const _gcry_slhdsa_param_t *ctx, u32 addr[8]);
/*
 * Compute the chain lengths needed for a given message hash
 */
gcry_err_code_t _gcry_slhdsa_chain_lengths (const _gcry_slhdsa_param_t *ctx, unsigned int *lengths, const byte *msg);

struct _gcry_slhdsa_leaf_info_x1_t
{
  byte *wots_sig;
  u32 wots_sign_leaf; /* The index of the WOTS we're using to sign */
  u32 *wots_steps;
  u32 leaf_addr[8];
  u32 pk_addr[8];
};

gcry_err_code_t _gcry_slhdsa_wots_gen_leafx1 (byte *dest, const _gcry_slhdsa_param_t *ctx, u32 leaf_idx, void *v_info);


#ifdef USE_AVX2
struct _gcry_slhdsa_leaf_info_x8_t
{
  byte *wots_sig;
  u32 wots_sign_leaf; /* The index of the WOTS we're using to sign */
  u32 *wots_steps;
  u32 leaf_addr[8 * 8];
  u32 pk_addr[8 * 8];
};
struct _gcry_slhdsa_leaf_info_x4_t
{
  byte *wots_sig;
  u32 wots_sign_leaf; /* The index of the WOTS we're using to sign */
  u32 *wots_steps;
  u32 leaf_addr[4 * 8];
  u32 pk_addr[4 * 8];
};

gcry_err_code_t _gcry_slhdsa_wots_pk_from_sig_avx2 (
    byte *pk, const byte *sig, const byte *msg, const _gcry_slhdsa_param_t *ctx, u32 addr[8]);


gcry_err_code_t _gcry_slhdsa_wots_gen_leafx8 (byte *dest, const _gcry_slhdsa_param_t *ctx, u32 leaf_idx, void *v_info);
gcry_err_code_t _gcry_slhdsa_wots_gen_leafx4 (byte *dest, const _gcry_slhdsa_param_t *ctx, u32 leaf_idx, void *v_info);
#endif
#endif
