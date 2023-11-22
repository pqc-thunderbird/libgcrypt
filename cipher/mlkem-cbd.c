/* mlkem-cbd.c - centered binomial distribution functions for ML-KEM
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

#include <stdint.h>
#include "mlkem-params.h"
#include "mlkem-cbd.h"

#include <config.h>
#include "bufhelp.h"
#include "types.h"

/*************************************************
 * Name:        load24_littleendian
 *
 * Description: load 3 bytes into a 32-bit integer
 *              in little-endian order.
 *              This function is only needed for ML-KEM-512
 *
 * Arguments:   - const byte *x: pointer to input byte array
 *
 * Returns 32-bit unsigned integer loaded from x (most significant byte is zero)
 **************************************************/
static uint32_t
load24_littleendian (const byte x[3])
{
  uint32_t r;
  r = (uint32_t)x[0];
  r |= (uint32_t)x[1] << 8;
  r |= (uint32_t)x[2] << 16;
  return r;
}


/*************************************************
 * Name:        cbd2
 *
 * Description: Given an array of uniformly random bytes, compute
 *              polynomial with coefficients distributed according to
 *              a centered binomial distribution with parameter eta=2
 *
 * Arguments:   - gcry_mlkem_poly *r: pointer to output polynomial
 *              - const byte *buf: pointer to input byte array
 **************************************************/
static void
cbd2 (gcry_mlkem_poly *r, const byte buf[2 * GCRY_MLKEM_N / 4])
{
  unsigned int i, j;
  uint32_t t, d;
  s16 a, b;

  for (i = 0; i < GCRY_MLKEM_N / 8; i++)
    {
      t = buf_get_le32 (buf + 4 * i);
      d = t & 0x55555555;
      d += (t >> 1) & 0x55555555;

      for (j = 0; j < 8; j++)
        {
          a                    = (d >> (4 * j + 0)) & 0x3;
          b                    = (d >> (4 * j + 2)) & 0x3;
          r->coeffs[8 * i + j] = a - b;
        }
    }
}

/*************************************************
 * Name:        cbd3
 *
 * Description: Given an array of uniformly random bytes, compute
 *              polynomial with coefficients distributed according to
 *              a centered binomial distribution with parameter eta=3.
 *              This function is only needed for ML-KEM-512
 *
 * Arguments:   - gcry_mlkem_poly *r: pointer to output polynomial
 *              - const byte *buf: pointer to input byte array
 **************************************************/
static void
cbd3 (gcry_mlkem_poly *r, const byte buf[3 * GCRY_MLKEM_N / 4])
{
  unsigned int i, j;
  uint32_t t, d;
  s16 a, b;

  for (i = 0; i < GCRY_MLKEM_N / 4; i++)
    {
      t = load24_littleendian (buf + 3 * i);
      d = t & 0x00249249;
      d += (t >> 1) & 0x00249249;
      d += (t >> 2) & 0x00249249;

      for (j = 0; j < 4; j++)
        {
          a                    = (d >> (6 * j + 0)) & 0x7;
          b                    = (d >> (6 * j + 3)) & 0x7;
          r->coeffs[4 * i + j] = a - b;
        }
    }
}

void
_gcry_mlkem_poly_cbd_eta1 (gcry_mlkem_poly *r,
                           const byte *buf,
                           gcry_mlkem_param_t const *param)
{
  if (param->eta1 == 2)
    {
      cbd2 (r, buf);
    }
  else /* eta1 = 3 */
    {
      cbd3 (r, buf);
    }
}

void
_gcry_mlkem_poly_cbd_eta2 (gcry_mlkem_poly *r,
                           const byte buf[GCRY_MLKEM_ETA2 * GCRY_MLKEM_N / 4])
{
  cbd2 (r, buf);
}
