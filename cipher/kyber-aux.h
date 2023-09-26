/* kyber-aux.h - Auxiliary functions for Kyber
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

#ifndef GCRYPT_KYBER_AUX_H
#define GCRYPT_KYBER_AUX_H

#include <stddef.h>
#include <stdint.h>
#include "kyber-params.h"

int16_t _gcry_kyber_montgomery_reduce (int32_t a);

int16_t _gcry_kyber_barrett_reduce (int16_t a);

typedef void *(*try_alloc_func_t) (size_t);

#endif /* GCRYPT_KYBER_AUX_H */
