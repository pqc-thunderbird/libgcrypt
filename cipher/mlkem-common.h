/* mlkem-common.h - general functions for ML-KEM
 * Copyright (C) 2023 MTG AG
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

#ifndef GCRYPT_MLKEM_COMMON_H
#define GCRYPT_MLKEM_COMMON_H


#include <stdint.h>
#include "mlkem-params.h"

#include <config.h>
#include "g10lib.h"
#include "types.h"


gcry_err_code_t _gcry_mlkem_kem_keypair_derand (byte *pk,
                                                byte *sk,
                                                gcry_mlkem_param_t *param,
                                                byte *coins);


gcry_err_code_t _gcry_mlkem_kem_keypair (byte *pk,
                                         byte *sk,
                                         gcry_mlkem_param_t *param);


gcry_err_code_t _gcry_mlkem_kem_enc_derand (byte *ct,
                                            byte *ss,
                                            const byte *pk,
                                            gcry_mlkem_param_t *param,
                                            byte *coins);

gcry_err_code_t _gcry_mlkem_kem_enc (byte *ct,
                                     byte *ss,
                                     const byte *pk,
                                     gcry_mlkem_param_t *param);

gcry_err_code_t _gcry_mlkem_kem_dec (byte *ss,
                                     const byte *ct,
                                     const byte *sk,
                                     gcry_mlkem_param_t *param);


#endif /* GCRYPT_MLKEM_COMMON_H */
