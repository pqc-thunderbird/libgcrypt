/* kyber-cbd.h - centered binomial distribution functions for Kyber
 * Copyright (C) 2023 MTG AG
 * The code was created based on the reference implementation that is part of the Kyber NIST submission.
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

#ifndef GCRYPT_KYBER_CBD_H
#define GCRYPT_KYBER_CBD_H

#include <stdint.h>
#include "kyber-params.h"
#include "kyber-poly.h"

/**
 * buf has length KYBER_ETA1*GCRY_KYBER_N/4
 */
void _gcry_kyber_poly_cbd_eta1 (gcry_kyber_poly *r,
                                const uint8_t *buf,
                                gcry_kyber_param_t const *param);

void _gcry_kyber_poly_cbd_eta2 (
    gcry_kyber_poly *r, const uint8_t buf[GCRY_KYBER_ETA2 * GCRY_KYBER_N / 4]);

#endif /* GCRYPT_KYBER_CBD_H */
