/* slhdsa-sign.h
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

#ifndef SLHDSA_SIGN_H
#define SLHDSA_SIGN_H

#include <config.h>

#include <stddef.h>
#include "types.h"

#include "slhdsa-context.h"

#include "g10lib.h"

/*
 * Generates a slhdsa key pair given a seed.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
gcry_err_code_t _gcry_slhdsa_seed_keypair (_gcry_slhdsa_param_t *ctx, byte *pk, byte *sk, const byte *seed);

/*
 * Generates a slhdsa key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
gcry_err_code_t _gcry_slhdsa_keypair (_gcry_slhdsa_param_t *ctx, byte *pk, byte *sk);

/**
 * Returns an array containing a detached signature.
 */
gcry_err_code_t _gcry_slhdsa_signature (
    _gcry_slhdsa_param_t *ctx, byte *sig, size_t *siglen, const byte *m, size_t mlen, const byte *sk);

/**
 * Verifies a detached signature and message under a given public key.
 */
gcry_err_code_t _gcry_slhdsa_verify (
    _gcry_slhdsa_param_t *ctx, const byte *sig, size_t siglen, const byte *m, size_t mlen, const byte *pk);

#endif