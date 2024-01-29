/* slhdsa-fors.h
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

#ifndef SLHDSA_FORS_H
#define SLHDSA_FORS_H

#include "config.h"
#include "types.h"

#include "slhdsa-context.h"

#include "g10lib.h"

/**
 * Signs a message m, deriving the secret key from sk_seed and the FTS address.
 * Assumes m contains at least SLHDSA_FORS_HEIGHT * SLHDSA_FORS_TREES bits.
 */
gcry_err_code_t _gcry_slhdsa_fors_sign (
    byte *sig, byte *pk, const byte *m, const _gcry_slhdsa_param_t *ctx, const u32 fors_addr[8]);

/**
 * Derives the FORS public key from a signature.
 * This can be used for verification by comparing to a known public key, or to
 * subsequently verify a signature on the derived public key. The latter is the
 * typical use-case when used as an FTS below an OTS in a hypertree.
 * Assumes m contains at least SLHDSA_FORS_HEIGHT * SLHDSA_FORS_TREES bits.
 */
gcry_err_code_t _gcry_slhdsa_fors_pk_from_sig (
    byte *pk, const byte *sig, const byte *m, const _gcry_slhdsa_param_t *ctx, const u32 fors_addr[8]);

#endif
