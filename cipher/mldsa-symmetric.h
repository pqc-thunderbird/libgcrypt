/* mldsa-symmetric.h
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

#ifndef _GCRY_MLDSA_SYMMETRIC_H
#define _GCRY_MLDSA_SYMMETRIC_H

#include "gcrypt-int.h"

#include "types.h"
#include "mldsa-params.h"

gcry_err_code_t _gcry_mldsa_shake128_stream_init (gcry_md_hd_t *md, const byte seed[GCRY_MLDSA_SEEDBYTES], u16 nonce);

gcry_err_code_t _gcry_mldsa_shake256_stream_init (gcry_md_hd_t *md, const byte seed[GCRY_MLDSA_CRHBYTES], u16 nonce);

gcry_err_code_t _gcry_mldsa_shake128_squeeze_nblocks (gcry_md_hd_t md, unsigned n, unsigned char *out);

gcry_err_code_t _gcry_mldsa_shake256_squeeze_nblocks (gcry_md_hd_t md, unsigned n, unsigned char *out);


gcry_err_code_t _gcry_mldsa_shake256 (const unsigned char *in_buf1,
                                      unsigned in_buf1_len,
                                      const unsigned char *in_buf2,
                                      unsigned in_buf2_len,
                                      unsigned char *out,
                                      unsigned out_len);

#define GCRY_SHAKE128_RATE 168
#define GCRY_SHAKE256_RATE 136
#define GCRY_SHA3_256_RATE 136
#define GCRY_SHA3_512_RATE 72

#define GCRY_STREAM128_BLOCKBYTES GCRY_SHAKE128_RATE
#define GCRY_STREAM256_BLOCKBYTES GCRY_SHAKE256_RATE

#endif