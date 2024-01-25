/* mlkem-kem-avx2.h
 * Copyright (C) 2024 MTG AG
 * The code was created based on the reference implementation that is part of the ML-KEM NIST submission.
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

#ifndef GCRYPT_MLKEM_KEM_AVX2_H
#define GCRYPT_MLKEM_KEM_AVX2_H

#include <stdint.h>
#include "mlkem-params.h"
#include "g10lib.h"

gcry_err_code_t _gcry_mlkem_avx2_kem_enc_derand (
    uint8_t *ct,
    uint8_t *ss,
    const uint8_t *pk,
    const gcry_mlkem_param_t *param,
    const uint8_t *coins);

gcry_err_code_t _gcry_mlkem_avx2_kem_keypair_derand (
    uint8_t *pk,
    uint8_t *sk,
    const gcry_mlkem_param_t *param,
    const uint8_t *coins);

#endif
