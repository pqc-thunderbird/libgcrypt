/* mlkem-symmetric.c - functions wrapping symmetric primitives for ML-KEM
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

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "mlkem-params.h"
#include "mlkem-symmetric.h"

#include "gcrypt.h"
#include "config.h"
#include "types.h"


void
_gcry_mlkem_shake128_absorb (gcry_md_hd_t h,
                             const unsigned char seed[GCRY_MLKEM_SYMBYTES],
                             unsigned char x,
                             unsigned char y)
{
  _gcry_md_write (h, seed, GCRY_MLKEM_SYMBYTES);
  _gcry_md_write (h, &x, 1);
  _gcry_md_write (h, &y, 1);
}


gcry_err_code_t
_gcry_mlkem_shake128_squeezeblocks (gcry_md_hd_t h, byte *out, size_t nblocks)
{
  return _gcry_md_extract (
      h, GCRY_MD_SHAKE128, out, GCRY_SHAKE128_RATE * nblocks);
}

gcry_err_code_t
_gcry_mlkem_shake256_prf (unsigned char *out,
                          size_t outlen,
                          const unsigned char key[GCRY_MLKEM_SYMBYTES],
                          unsigned char nonce)
{
  gcry_err_code_t ec = 0;
  gcry_md_hd_t h;

  ec = _gcry_md_open (&h, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);
  if (ec)
    {
      return ec;
    }
  _gcry_md_write (h, key, GCRY_MLKEM_SYMBYTES);
  _gcry_md_write (h, &nonce, 1);
  ec = _gcry_md_extract (h, GCRY_MD_SHAKE256, out, outlen);
  _gcry_md_close (h);
  return ec;
}

gcry_err_code_t
_gcry_mlkem_prf (unsigned char *out,
                 size_t outlen,
                 const unsigned char key[GCRY_MLKEM_SYMBYTES],
                 unsigned char nonce)
{
  return _gcry_mlkem_shake256_prf (out, outlen, key, nonce);
}
